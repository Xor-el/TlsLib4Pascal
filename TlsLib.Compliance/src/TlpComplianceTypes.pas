{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpComplianceTypes;

{$I ..\..\TlsLib\src\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpCryptoDomainTypes,
  TlpNegotiationTypes,
  TlpTlsVersion,
  TlpPkixDomainTypes,
  TlpCertificateStrengthPolicy,
  TlpChainAlgorithmPolicy,
  TlpArrayUtilities,
  TlpEnumUtilities,
  TlpCipherSuiteCatalog,
  TlpTlsLibExceptions,
  TlpTlsCredential;

type
  /// <summary>The standard a cryptographic module is attested against.</summary>
  TModuleStandard = (Fips140_3);

  /// <summary>Strict refuses every finding. Relaxed refuses a configuration finding (the
  /// allowlists, the requirement flags) and reports a platform finding, a fact about where
  /// the cryptography runs, instead of refusing it, including a derivation, chain
  /// verification or key the rules want inside the module.</summary>
  TComplianceEnforcement = (Strict, Relaxed);

  /// <summary>PrimitivesInModule: every negotiated primitive is a service of a validated module
  /// and nothing was found, but a key-schedule derivation the configuration can run is composed
  /// outside the module. Compliant: additionally every key-schedule derivation the configuration
  /// can run is a module service; a TLS 1.2 exporter derivation (RFC 5705) is composed over the
  /// module HMAC and disclosed, or refused under a strict RequireModule rule.</summary>
  TComplianceVerdict = (NotCompliant, PrimitivesInModule, Compliant);

  /// <summary>Historical: the module's certificate has passed its sunset date.</summary>
  TModuleStatus = (Unknown, NotValidated, Validated, Historical);

  /// <summary>The OS-wide legacy FIPS switch; informational only.</summary>
  TLegacyFipsPolicy = (Unknown, Disabled, Enabled);

  /// <summary>Whether a key derivation composed outside the module is accepted.</summary>
  TKdfRule = (AllowComposed, RequireModule);

  TComplianceRequirement = (ExtendedMasterSecret, NoEarlyData, NoEch, NoExternalPsk,
    NoTls12Psk, NoKeyLog, NoDangerousTrust, InModuleChainVerification);

  TComplianceRequirements = set of TComplianceRequirement;

  // TSignatureSchemes is already taken by the wire-code catalog
  TComplianceSchemeSet = set of TSignatureScheme;

  TComplianceAeadSet = set of TAeadAlgorithm;

  TComplianceKeyAgreementSet = set of TKeyAgreementAlgorithm;

  /// <summary>The allowlists and requirements a policy enforces. Rules only ever narrow:
  /// Intersect never widens either operand.</summary>
  TComplianceRules = record
    Versions: TArray<UInt16>;
    CipherSuites: TArray<UInt16>;
    Aeads: TComplianceAeadSet;
    NamedGroups: TArray<UInt16>;
    SignatureSchemes: TComplianceSchemeSet;
    Strength: TCertificateStrengthPolicy;
    /// <summary>The exact RSA modulus sizes the policy's own credential may have, inside the
    /// Strength range; empty means the range alone. A peer chain is held to the Strength range
    /// only, so the exact sizes are not enforced on it.</summary>
    RsaModulusBits: TArray<UInt32>;
    Requirements: TComplianceRequirements;
    Kdf: TKdfRule;
    ModuleStandard: TModuleStandard;
    /// <summary>The rules both operands allow, in A's order; anchors are held to the key floors
    /// when either operand does. Raises when the result would hold
    /// no curve, no RSA size (both operands list sizes, none shared) or an empty RSA range, or
    /// when the operands target different standards.</summary>
    class function Intersect(const A, B: TComplianceRules): TComplianceRules; static;
    /// <summary>Whether every allowance of Self is also allowed by AOther and Self keeps every
    /// requirement of AOther.</summary>
    function IsSubsetOf(const AOther: TComplianceRules): Boolean;
    /// <summary>Mutual IsSubsetOf; order does not count.</summary>
    class operator Equal(const A, B: TComplianceRules): Boolean;
    /// <summary>A copy that shares no array with Self.</summary>
    function Clone: TComplianceRules;
    function Describe: string;
  end;

  TComplianceFindingCategory = (Configuration, Platform);

  TComplianceFindingKind = (
    ModuleNotValidated, NoBackendReport, AlgorithmOutsideModule, KdfOutsideModule,
    CredentialKeyOutsideModule, ChainVerifiedOutsideModule, StapleVerifiedOutsideModule,
    CryptoNotCovered, ForeignCryptoProvider, ForeignPkixProvider, VersionNotAllowed,
    CipherSuiteNotAllowed, NamedGroupNotAllowed, SignatureSchemeNotAllowed,
    ExtendedMasterSecretNotRequired, EarlyDataEnabled, EchConfigured, ExternalPskConfigured,
    Tls12PskConfigured, KeyLogConfigured, DangerousTrustConfigured, StrengthBelowRules,
    CredentialKeyUndetermined, CredentialKeyMissing, CredentialKeyMismatch,
    CredentialKeyBelowRules, CredentialSchemesNotAllowed, CredentialKeyUnusable,
    TicketAeadNotAllowed, CredentialResolverUnchecked, ForeignNamedGroup,
    CustomVerifierConfigured, ResumptionStateUnchecked, TicketKeysUnchecked,
    CipherSuiteDiffersFromCatalog);

  TComplianceFinding = record
    Kind: TComplianceFindingKind;
    Subject: string;
    Message: string;
    class function Create(AKind: TComplianceFindingKind;
      const ASubject, AMessage: string): TComplianceFinding; static;
    function Category: TComplianceFindingCategory;
    /// <summary>'Kind Subject: Message', or 'Kind: Message' without a subject.</summary>
    function Describe: string;
  end;

  /// <summary>What an attestation knows about the module in use; empty strings where a fact is
  /// not attested.</summary>
  TModuleIdentity = record
    OsName: string;
    OsBuild: UInt32;
    OsRevision: UInt32;
    OsVersion: string;
    Product: string;
    ModuleName: string;
    ModuleFileVersion: string;
    /// <summary>The certificate number; the policy clears it unless the module is Validated, and
    /// the module line of a report prints it only then.</summary>
    Certificate: string;
    /// <summary>Whether the library's own platform attestation produced this identity; False
    /// for one the host supplies.</summary>
    Attested: Boolean;
    LegacyFipsPolicy: TLegacyFipsPolicy;
    /// <summary>The process and machine architectures as the OS reports them (0 for the
    /// process when it is native); NativeMachine 0 means they were not read.</summary>
    ProcessMachine: UInt16;
    NativeMachine: UInt16;
    /// <summary>The OS product type (workstation, domain controller, server); 0 unread.</summary>
    ProductType: Byte;
    /// <summary>The OS edition as the OS names it; reported, never decided on.</summary>
    Edition: string;
    /// <summary>The firmware kind (for example UEFI); empty when it was not read.</summary>
    Firmware: string;
    /// <summary>Where the module was loaded from.</summary>
    ModulePath: string;
    /// <summary>The module version the certificate lists for this build; empty when none.</summary>
    ListedModuleVersion: string;
    /// <summary>The attested facts that are present, space separated; empty when none is.</summary>
    function Describe: string;
  end;

  /// <summary>Lookups the policy and the refusing providers share.</summary>
  TComplianceCatalog = class sealed(TObject)
  public
    /// <summary>The classical agreement a NIST or X25519 group code names; False for others,
    /// where AAlgorithm is unspecified.</summary>
    class function TryKeyAgreement(AGroup: UInt16;
      out AAlgorithm: TKeyAgreementAlgorithm): Boolean; static;
    /// <summary>The agreements the groups call for.</summary>
    class function KeyAgreements(const ARules: TComplianceRules): TComplianceKeyAgreementSet;
      static;
    /// <summary>Whether every entry of ASub is in ASuper.</summary>
    class function IsSubsetOfList(const ASub, ASuper: TArray<UInt16>): Boolean; static;
    /// <summary>Whether ASizes lists no size outside AAllowed, an empty AAllowed allowing any;
    /// a list that names no size is not within a non-empty AAllowed.</summary>
    class function RsaSizesWithin(const ASizes, AAllowed: TArray<UInt32>): Boolean; static;
    /// <summary>Whether a key's facts meet the strength floors and, for an RSA key, the exact
    /// sizes ARsaSizes (empty = the range alone).</summary>
    class function KeyMeets(const AFacts: TCertKeyFacts;
      const AStrength: TCertificateStrengthPolicy;
      const ARsaSizes: TArray<UInt32>): Boolean; static;
    /// <summary>Whether a certificate signature is one the rules allow: the rule signature scheme
    /// the core requires for its family and hash (RSA-PSS only with canonical parameters and
    /// never under a PSS-restricted issuer key, AIssuerKeyIsPss), a deprecated hash the strength
    /// policy admits, or EdDSA where the strength policy admits it and the rules list its
    /// scheme.</summary>
    class function SignatureMeets(AFamily: TCertSignatureFamily; AHash: TCertSignatureHash;
      APssCanonical, AIssuerKeyIsPss: Boolean; const ARules: TComplianceRules): Boolean; static;
    /// <summary>Whether A and B are one credential: the same private key object and the same
    /// certificate chain, byte for byte.</summary>
    class function SameCredential(const A, B: TTlsCredential): Boolean; static;
    /// <summary>The display name of a module standard.</summary>
    class function StandardName(AStandard: TModuleStandard): string; static;
    /// <summary>The members of ASet in enum order.</summary>
    class function Schemes(const ASet: TComplianceSchemeSet): TArray<TSignatureScheme>; static;
    /// <summary>ACredential with its key narrowed to ASchemes.</summary>
    class function NarrowedCredential(const ACredential: TTlsCredential;
      const ASchemes: TArray<TSignatureScheme>): TTlsCredential; static;
    /// <summary>The findings AEnforcement refuses: all of them in strict mode, the configuration
    /// ones in relaxed mode.</summary>
    class function Refusals(AEnforcement: TComplianceEnforcement;
      const AFindings: TArray<TComplianceFinding>): TArray<TComplianceFinding>; static;
  end;

implementation

resourcestring
  SNoCommonCurve = 'the two rule sets share no elliptic curve';
  SModuleStandardMismatch = 'the two rule sets target different module standards';
  SNoCommonRsaSize = 'the two rule sets share no RSA modulus size';
  SEmptyRsaRange = 'the two rule sets share no RSA modulus range';
  SFips140_3Name = 'FIPS 140-3';
  SFindingLine = '%s: %s';
  SFindingSubjectLine = '%s %s: %s';
  SNativeMachinePart = 'machine 0x%.4x';
  SProcessMachinePart = 'process 0x%.4x';
  SProductTypePart = 'product type %d';
  SEditionPart = 'edition %s';
  SFirmwarePart = 'firmware %s';
  SListedVersionPart = 'listed %s';
  SLegacyPolicyPart = 'legacy FIPS policy %s';
  SVersionPart = ' 0x%.4X';
  SVersionsLine = 'Versions:%s';
  SCipherSuitesLine = 'CipherSuites:%s';
  SAeadsLine = 'Aeads:%s';
  SNamedGroupsLine = 'NamedGroups:%s';
  SSchemesLine = 'SignatureSchemes:%s';
  SStrengthLine = 'Strength: RsaBits %d..%d, RsaSizes:%s, EdDsa=%s, AnchorFloors=%s, ' +
    'DeprecatedHashes:%s, curves:%s';
  SRequirementsLine = 'Requirements:%s';
  SKdfLine = 'Kdf: %s';
  SStandardLine = 'ModuleStandard: %s';
  SYes = 'yes';
  SNo = 'no';

{ TComplianceRules }

class function TComplianceRules.Intersect(const A, B: TComplianceRules): TComplianceRules;
var
  LI: Int32;
  LSizes: TArray<UInt32>;
begin
  if A.ModuleStandard <> B.ModuleStandard then
    raise EArgumentTlsLibException.CreateRes(@SModuleStandardMismatch);
  Result := Default(TComplianceRules);
  for LI := 0 to System.Length(A.Versions) - 1 do
    if TArrayUtilities.Contains<UInt16>(B.Versions, A.Versions[LI]) then
      TArrayUtilities.Append<UInt16>(Result.Versions, A.Versions[LI]);
  for LI := 0 to System.Length(A.CipherSuites) - 1 do
    if TArrayUtilities.Contains<UInt16>(B.CipherSuites, A.CipherSuites[LI]) then
      TArrayUtilities.Append<UInt16>(Result.CipherSuites, A.CipherSuites[LI]);
  Result.Aeads := A.Aeads * B.Aeads;
  Result.SignatureSchemes := A.SignatureSchemes * B.SignatureSchemes;
  for LI := 0 to System.Length(A.NamedGroups) - 1 do
    if TArrayUtilities.Contains<UInt16>(B.NamedGroups, A.NamedGroups[LI]) then
      TArrayUtilities.Append<UInt16>(Result.NamedGroups, A.NamedGroups[LI]);
  Result.Strength.MinRsaModulusBits := A.Strength.MinRsaModulusBits;
  if B.Strength.MinRsaModulusBits > Result.Strength.MinRsaModulusBits then
    Result.Strength.MinRsaModulusBits := B.Strength.MinRsaModulusBits;
  if A.Strength.MaxRsaModulusBits = 0 then
    Result.Strength.MaxRsaModulusBits := B.Strength.MaxRsaModulusBits
  else if B.Strength.MaxRsaModulusBits = 0 then
    Result.Strength.MaxRsaModulusBits := A.Strength.MaxRsaModulusBits
  else if A.Strength.MaxRsaModulusBits < B.Strength.MaxRsaModulusBits then
    Result.Strength.MaxRsaModulusBits := A.Strength.MaxRsaModulusBits
  else
    Result.Strength.MaxRsaModulusBits := B.Strength.MaxRsaModulusBits;
  if (Result.Strength.MaxRsaModulusBits <> 0) and
    (Result.Strength.MinRsaModulusBits > Result.Strength.MaxRsaModulusBits) then
    raise EArgumentTlsLibException.CreateRes(@SEmptyRsaRange);
  // an empty size list means the range alone, so a miss must not widen to it
  if System.Length(A.RsaModulusBits) = 0 then
    LSizes := System.Copy(B.RsaModulusBits)
  else if System.Length(B.RsaModulusBits) = 0 then
    LSizes := System.Copy(A.RsaModulusBits)
  else
  begin
    LSizes := nil;
    for LI := 0 to System.Length(A.RsaModulusBits) - 1 do
      if TArrayUtilities.Contains<UInt32>(B.RsaModulusBits, A.RsaModulusBits[LI]) then
        TArrayUtilities.Append<UInt32>(LSizes, A.RsaModulusBits[LI]);
  end;
  for LI := 0 to System.Length(LSizes) - 1 do
    if (LSizes[LI] >= UInt32(Result.Strength.MinRsaModulusBits)) and
      ((Result.Strength.MaxRsaModulusBits = 0) or
      (LSizes[LI] <= UInt32(Result.Strength.MaxRsaModulusBits))) then
      TArrayUtilities.Append<UInt32>(Result.RsaModulusBits, LSizes[LI]);
  if ((System.Length(A.RsaModulusBits) > 0) or (System.Length(B.RsaModulusBits) > 0)) and
    (System.Length(Result.RsaModulusBits) = 0) then
    raise EArgumentTlsLibException.CreateRes(@SNoCommonRsaSize);
  // an empty curve list means any curve to the core, so a shared-curve miss must not reach it
  if System.Length(A.Strength.AllowedEcCurves) = 0 then
    Result.Strength.AllowedEcCurves := System.Copy(B.Strength.AllowedEcCurves)
  else if System.Length(B.Strength.AllowedEcCurves) = 0 then
    Result.Strength.AllowedEcCurves := System.Copy(A.Strength.AllowedEcCurves)
  else
    for LI := 0 to System.Length(A.Strength.AllowedEcCurves) - 1 do
      if TArrayUtilities.Contains<UInt16>(B.Strength.AllowedEcCurves,
        A.Strength.AllowedEcCurves[LI]) then
        TArrayUtilities.Append<UInt16>(Result.Strength.AllowedEcCurves,
          A.Strength.AllowedEcCurves[LI]);
  if System.Length(Result.Strength.AllowedEcCurves) = 0 then
    raise EArgumentTlsLibException.CreateRes(@SNoCommonCurve);
  Result.Strength.AllowEdDsa := A.Strength.AllowEdDsa and B.Strength.AllowEdDsa;
  Result.Strength.AnchorKeyFloors := A.Strength.AnchorKeyFloors or B.Strength.AnchorKeyFloors;
  Result.Strength.AllowedDeprecatedHashes := A.Strength.AllowedDeprecatedHashes *
    B.Strength.AllowedDeprecatedHashes;
  Result.Requirements := A.Requirements + B.Requirements;
  if (A.Kdf = TKdfRule.RequireModule) or (B.Kdf = TKdfRule.RequireModule) then
    Result.Kdf := TKdfRule.RequireModule
  else
    Result.Kdf := TKdfRule.AllowComposed;
  Result.ModuleStandard := A.ModuleStandard;
end;

function TComplianceRules.IsSubsetOf(const AOther: TComplianceRules): Boolean;
begin
  Result := TComplianceCatalog.IsSubsetOfList(Versions, AOther.Versions) and
    TComplianceCatalog.IsSubsetOfList(CipherSuites, AOther.CipherSuites) and
    TComplianceCatalog.IsSubsetOfList(NamedGroups, AOther.NamedGroups) and
    (Aeads <= AOther.Aeads) and (SignatureSchemes <= AOther.SignatureSchemes) and
    Strength.IsAtLeastAsStrictAs(AOther.Strength) and
    TComplianceCatalog.RsaSizesWithin(RsaModulusBits, AOther.RsaModulusBits) and
    (AOther.Requirements <= Requirements) and
    ((AOther.Kdf = TKdfRule.AllowComposed) or (Kdf = TKdfRule.RequireModule)) and
    (ModuleStandard = AOther.ModuleStandard);
end;

class operator TComplianceRules.Equal(const A, B: TComplianceRules): Boolean;
begin
  Result := A.IsSubsetOf(B) and B.IsSubsetOf(A);
end;

function TComplianceRules.Clone: TComplianceRules;
begin
  Result := Self;
  Result.Versions := System.Copy(Versions);
  Result.CipherSuites := System.Copy(CipherSuites);
  Result.NamedGroups := System.Copy(NamedGroups);
  Result.Strength.AllowedEcCurves := System.Copy(Strength.AllowedEcCurves);
  Result.RsaModulusBits := System.Copy(RsaModulusBits);
end;

function TComplianceRules.Describe: string;
var
  LI: Int32;
  LList, LFlag, LAnchor, LName, LSizes, LHashes: string;
  LHash: TCertSignatureHash;
  LAead: TAeadAlgorithm;
  LScheme: TSignatureScheme;
  LRequirement: TComplianceRequirement;
begin
  Result := '';
  LList := '';
  for LI := 0 to System.Length(Versions) - 1 do
    LList := LList + Format(SVersionPart, [Versions[LI]]);
  Result := Result + Format(SVersionsLine, [LList]) + sLineBreak;
  LList := '';
  for LI := 0 to System.Length(CipherSuites) - 1 do
    LList := LList + ' ' + TCipherSuiteCatalog.Name(CipherSuites[LI]);
  Result := Result + Format(SCipherSuitesLine, [LList]) + sLineBreak;
  LList := '';
  for LAead := Low(TAeadAlgorithm) to High(TAeadAlgorithm) do
    if LAead in Aeads then
    begin
      LName := TEnumUtilities.GetName<TAeadAlgorithm>(LAead);
      LList := LList + ' ' + LName;
    end;
  Result := Result + Format(SAeadsLine, [LList]) + sLineBreak;
  LList := '';
  for LI := 0 to System.Length(NamedGroups) - 1 do
    LList := LList + ' ' + TNamedGroupCatalog.Name(NamedGroups[LI]);
  Result := Result + Format(SNamedGroupsLine, [LList]) + sLineBreak;
  LList := '';
  for LScheme := Low(TSignatureScheme) to High(TSignatureScheme) do
    if LScheme in SignatureSchemes then
    begin
      LName := TEnumUtilities.GetName<TSignatureScheme>(LScheme);
      LList := LList + ' ' + LName;
    end;
  Result := Result + Format(SSchemesLine, [LList]) + sLineBreak;
  LList := '';
  for LI := 0 to System.Length(Strength.AllowedEcCurves) - 1 do
    LList := LList + ' ' + TNamedGroupCatalog.Name(Strength.AllowedEcCurves[LI]);
  if Strength.AllowEdDsa then
    LFlag := SYes
  else
    LFlag := SNo;
  if Strength.AnchorKeyFloors then
    LAnchor := SYes
  else
    LAnchor := SNo;
  LSizes := '';
  for LI := 0 to System.Length(RsaModulusBits) - 1 do
    LSizes := LSizes + ' ' + IntToStr(RsaModulusBits[LI]);
  LHashes := '';
  for LHash := Low(TCertSignatureHash) to High(TCertSignatureHash) do
    if LHash in Strength.AllowedDeprecatedHashes then
      LHashes := LHashes + ' ' + TEnumUtilities.GetName(TypeInfo(TCertSignatureHash),
        Ord(LHash));
  Result := Result + Format(SStrengthLine, [Strength.MinRsaModulusBits,
    Strength.MaxRsaModulusBits, LSizes, LFlag, LAnchor, LHashes, LList]) + sLineBreak;
  LList := '';
  for LRequirement := Low(TComplianceRequirement) to High(TComplianceRequirement) do
    if LRequirement in Requirements then
    begin
      LName := TEnumUtilities.GetName<TComplianceRequirement>(LRequirement);
      LList := LList + ' ' + LName;
    end;
  Result := Result + Format(SRequirementsLine, [LList]) + sLineBreak;
  LName := TEnumUtilities.GetName<TKdfRule>(Kdf);
  Result := Result + Format(SKdfLine, [LName]) + sLineBreak;
  LName := TEnumUtilities.GetName<TModuleStandard>(ModuleStandard);
  Result := Result + Format(SStandardLine, [LName]);
end;

{ TComplianceFinding }

class function TComplianceFinding.Create(AKind: TComplianceFindingKind;
  const ASubject, AMessage: string): TComplianceFinding;
begin
  Result.Kind := AKind;
  Result.Subject := ASubject;
  Result.Message := AMessage;
end;

function TComplianceFinding.Category: TComplianceFindingCategory;
begin
  case Kind of
    TComplianceFindingKind.ModuleNotValidated, TComplianceFindingKind.NoBackendReport,
      TComplianceFindingKind.AlgorithmOutsideModule, TComplianceFindingKind.KdfOutsideModule,
      TComplianceFindingKind.CredentialKeyOutsideModule,
      TComplianceFindingKind.ChainVerifiedOutsideModule,
      TComplianceFindingKind.StapleVerifiedOutsideModule,
      TComplianceFindingKind.CryptoNotCovered:
      Result := TComplianceFindingCategory.Platform;
  else
    Result := TComplianceFindingCategory.Configuration;
  end;
end;

function TComplianceFinding.Describe: string;
begin
  if Subject = '' then
    Result := Format(SFindingLine, [TEnumUtilities.GetName<TComplianceFindingKind>(Kind),
      Message])
  else
    Result := Format(SFindingSubjectLine, [TEnumUtilities.GetName<TComplianceFindingKind>(Kind),
      Subject, Message]);
end;

{ TModuleIdentity }

function TModuleIdentity.Describe: string;
var
  LParts: TArray<string>;
  LI: Int32;
  LNative, LProcess, LProductType, LEdition, LFirmware, LListed, LLegacy: string;
begin
  LNative := '';
  if NativeMachine <> 0 then
    LNative := Format(SNativeMachinePart, [NativeMachine]);
  LProcess := '';
  if ProcessMachine <> 0 then
    LProcess := Format(SProcessMachinePart, [ProcessMachine]);
  LProductType := '';
  if ProductType <> 0 then
    LProductType := Format(SProductTypePart, [ProductType]);
  LEdition := '';
  if Edition <> '' then
    LEdition := Format(SEditionPart, [Edition]);
  LFirmware := '';
  if Firmware <> '' then
    LFirmware := Format(SFirmwarePart, [Firmware]);
  LListed := '';
  if ListedModuleVersion <> '' then
    LListed := Format(SListedVersionPart, [ListedModuleVersion]);
  LLegacy := '';
  if LegacyFipsPolicy <> TLegacyFipsPolicy.Unknown then
    LLegacy := Format(SLegacyPolicyPart, [TEnumUtilities.GetName<TLegacyFipsPolicy>(
      LegacyFipsPolicy)]);
  LParts := TArray<string>.Create(OsName, OsVersion, Product, LEdition, LProductType, LFirmware,
    ModuleName, ModuleFileVersion, LListed, ModulePath, LNative, LProcess, LLegacy);
  Result := '';
  for LI := 0 to System.Length(LParts) - 1 do
    if LParts[LI] <> '' then
    begin
      if Result <> '' then
        Result := Result + ' ';
      Result := Result + LParts[LI];
    end;
end;

{ TComplianceCatalog }

class function TComplianceCatalog.TryKeyAgreement(AGroup: UInt16;
  out AAlgorithm: TKeyAgreementAlgorithm): Boolean;
var
  LComposition: TNamedGroupComposition;
begin
  // a hybrid or a KEM-only group is not a classical agreement
  AAlgorithm := Default(TKeyAgreementAlgorithm);
  Result := TNamedGroupCatalog.TryComposition(AGroup, LComposition) and
    (LComposition.Kind = TNamedGroupKind.Ecdhe);
  if Result then
    AAlgorithm := LComposition.KeyAgreement;
end;

class function TComplianceCatalog.KeyAgreements(
  const ARules: TComplianceRules): TComplianceKeyAgreementSet;
var
  LI: Int32;
  LAlgorithm: TKeyAgreementAlgorithm;
begin
  Result := [];
  for LI := 0 to System.Length(ARules.NamedGroups) - 1 do
    if TryKeyAgreement(ARules.NamedGroups[LI], LAlgorithm) then
      Include(Result, LAlgorithm);
end;

class function TComplianceCatalog.IsSubsetOfList(const ASub, ASuper: TArray<UInt16>): Boolean;
var
  LI: Int32;
begin
  Result := True;
  for LI := 0 to System.Length(ASub) - 1 do
  begin
    Result := TArrayUtilities.Contains<UInt16>(ASuper, ASub[LI]);
    if not Result then
      Exit;
  end;
end;

class function TComplianceCatalog.RsaSizesWithin(const ASizes,
  AAllowed: TArray<UInt32>): Boolean;
var
  LI: Int32;
  LListed: Boolean;
begin
  if System.Length(AAllowed) = 0 then
    Exit(True);
  Result := System.Length(ASizes) > 0;
  for LI := 0 to System.Length(ASizes) - 1 do
  begin
    LListed := TArrayUtilities.Contains<UInt32>(AAllowed, ASizes[LI]);
    if not LListed then
      Exit(False);
  end;
end;

class function TComplianceCatalog.SignatureMeets(AFamily: TCertSignatureFamily;
  AHash: TCertSignatureHash; APssCanonical, AIssuerKeyIsPss: Boolean;
  const ARules: TComplianceRules): Boolean;
var
  LRequired: UInt16;
  LScheme: TSignatureScheme;
  LKnown: Boolean;
begin
  LRequired := TChainAlgorithmPolicy.RequiredScheme(AFamily, AHash, APssCanonical,
    AIssuerKeyIsPss);
  LKnown := TSignatureScheme.TryFromCode(LRequired, LScheme);
  // PSS must be canonical whatever the hash, and no rule scheme covers a PSS-restricted issuer
  if (AFamily = TCertSignatureFamily.RsaPss) and
    (not APssCanonical or (AIssuerKeyIsPss and not LKnown)) then
    Exit(False);
  // the strength policy admits only a hash the core regards as deprecated
  if (AHash.Standing = TCertSignatureHashStanding.Deprecated) and
    (AHash in ARules.Strength.AllowedDeprecatedHashes) then
    Exit(True);
  if not LKnown then
    Exit(False);
  // EdDSA needs its scheme in the rules as well as the strength policy's admission
  Result := (LScheme in ARules.SignatureSchemes) and
    (ARules.Strength.AllowEdDsa or ((LScheme <> TSignatureScheme.ED25519) and
    (LScheme <> TSignatureScheme.ED448)));
end;

class function TComplianceCatalog.SameCredential(const A, B: TTlsCredential): Boolean;
var
  LI: Int32;
begin
  Result := (A.PrivateKey = B.PrivateKey) and
    (System.Length(A.CertificateChain) = System.Length(B.CertificateChain));
  for LI := 0 to System.Length(A.CertificateChain) - 1 do
    if Result then
      Result := TArrayUtilities.AreEqual(A.CertificateChain[LI], B.CertificateChain[LI]);
end;

class function TComplianceCatalog.StandardName(AStandard: TModuleStandard): string;
begin
  case AStandard of
    TModuleStandard.Fips140_3:
      Result := SFips140_3Name;
  else
    Result := '';
  end;
end;

class function TComplianceCatalog.KeyMeets(const AFacts: TCertKeyFacts;
  const AStrength: TCertificateStrengthPolicy; const ARsaSizes: TArray<UInt32>): Boolean;
begin
  Result := AStrength.AdmitsKey(AFacts);
  // the exact sizes only ever narrow the range, and only for RSA
  if Result and (AFacts.Kind = TSignatureKeyKind.Rsa) and (System.Length(ARsaSizes) > 0) then
  begin
    Result := AFacts.Bits > 0;
    if Result then
      Result := TArrayUtilities.Contains<UInt32>(ARsaSizes, UInt32(AFacts.Bits));
  end;
end;

class function TComplianceCatalog.Schemes(
  const ASet: TComplianceSchemeSet): TArray<TSignatureScheme>;
var
  LScheme: TSignatureScheme;
begin
  Result := nil;
  for LScheme := Low(TSignatureScheme) to High(TSignatureScheme) do
    if LScheme in ASet then
      TArrayUtilities.Append<TSignatureScheme>(Result, LScheme);
end;

class function TComplianceCatalog.NarrowedCredential(const ACredential: TTlsCredential;
  const ASchemes: TArray<TSignatureScheme>): TTlsCredential;
begin
  Result := ACredential;
  if Result.PrivateKey <> nil then
    Result.PrivateKey := Result.PrivateKey.WithPreferredSchemes(ASchemes);
end;

class function TComplianceCatalog.Refusals(AEnforcement: TComplianceEnforcement;
  const AFindings: TArray<TComplianceFinding>): TArray<TComplianceFinding>;
var
  LI: Int32;
begin
  Result := nil;
  for LI := 0 to System.Length(AFindings) - 1 do
    if (AEnforcement = TComplianceEnforcement.Strict) or
      (AFindings[LI].Category = TComplianceFindingCategory.Configuration) then
      TArrayUtilities.Append<TComplianceFinding>(Result, AFindings[LI]);
end;

end.
