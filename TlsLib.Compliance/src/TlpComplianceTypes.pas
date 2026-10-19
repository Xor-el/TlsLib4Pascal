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
  TlpArrayUtilities,
  TlpEnumUtilities,
  TlpCipherSuiteCatalog,
  TlpTlsLibExceptions;

type
  /// <summary>The standard a cryptographic module is attested against.</summary>
  TModuleStandard = (Fips140_3);

  /// <summary>Strict refuses a platform fact that falls short; Relaxed reports it
  /// instead.</summary>
  TComplianceEnforcement = (Strict, Relaxed);

  TComplianceVerdict = (Compliant, NotCompliant);

  TModuleStatus = (Unknown, NotValidated, Validated);

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
    Requirements: TComplianceRequirements;
    Kdf: TKdfRule;
    ModuleStandard: TModuleStandard;
    /// <summary>The rules both operands allow, in A's order; raises when no curve is
    /// shared.</summary>
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

  TComplianceFindingCategory = (Rules, Configuration, Platform);

  TComplianceFindingKind = (
    RulesOutsidePresets,
    ModuleNotValidated, NoBackendReport, AlgorithmOutsideModule, KdfOutsideModule,
    CredentialKeyOutsideModule, ChainVerifiedOutsideModule, StapleVerifiedOutsideModule,
    ForeignCryptoProvider, ForeignPkixProvider, VersionNotAllowed, CipherSuiteNotAllowed,
    NamedGroupNotAllowed, SignatureSchemeNotAllowed, ExtendedMasterSecretNotRequired,
    EarlyDataEnabled, EchConfigured, ExternalPskConfigured, Tls12PskConfigured,
    KeyLogConfigured, DangerousTrustConfigured, StrengthBelowRules,
    CredentialKeyUndetermined, CredentialKeyBelowRules, CredentialSchemesNotAllowed);

  TComplianceFinding = record
    Kind: TComplianceFindingKind;
    Subject: string;
    Message: string;
    class function Create(AKind: TComplianceFindingKind;
      const ASubject, AMessage: string): TComplianceFinding; static;
    function Category: TComplianceFindingCategory;
    /// <summary>'Kind Subject: Message'.</summary>
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
    Certificate: string;
    LegacyFipsPolicy: TLegacyFipsPolicy;
  end;

  /// <summary>Lookups the policy and the refusing providers share.</summary>
  TComplianceCatalog = class sealed(TObject)
  public
    /// <summary>The classical agreement a NIST or X25519 group code names; False for
    /// others.</summary>
    class function TryKeyAgreement(AGroup: UInt16;
      out AAlgorithm: TKeyAgreementAlgorithm): Boolean; static;
    /// <summary>The hash a scheme digests with; EdDSA hashes internally, so SHA-512 stands
    /// in.</summary>
    class function SchemeHash(AScheme: TSignatureScheme): THashAlgorithm; static;
    /// <summary>The agreements the groups call for.</summary>
    class function KeyAgreements(const ARules: TComplianceRules): TComplianceKeyAgreementSet;
      static;
    /// <summary>Whether every entry of ASub is in ASuper.</summary>
    class function IsSubsetOfList(const ASub, ASuper: TArray<UInt16>): Boolean; static;
    /// <summary>Whether AStrength is at least as strict as AFloor.</summary>
    class function StrengthWithin(const AStrength,
      AFloor: TCertificateStrengthPolicy): Boolean; static;
    /// <summary>Whether a key's facts meet the strength floors.</summary>
    class function KeyMeets(const AFacts: TCertKeyFacts;
      const AStrength: TCertificateStrengthPolicy): Boolean; static;
    /// <summary>The members of ASet in enum order.</summary>
    class function Schemes(const ASet: TComplianceSchemeSet): TArray<TSignatureScheme>; static;
  end;

implementation

resourcestring
  SNoCommonCurve = 'the two rule sets share no elliptic curve';
  SModuleStandardMismatch = 'the two rule sets target different module standards';

{ TComplianceRules }

class function TComplianceRules.Intersect(const A, B: TComplianceRules): TComplianceRules;
var
  LI: Int32;
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
    TComplianceCatalog.StrengthWithin(Strength, AOther.Strength) and
    (AOther.Requirements <= Requirements) and (Kdf >= AOther.Kdf) and
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
end;

function TComplianceRules.Describe: string;
var
  LI: Int32;
  LList, LFlag, LName: string;
  LAead: TAeadAlgorithm;
  LScheme: TSignatureScheme;
  LRequirement: TComplianceRequirement;
begin
  Result := '';
  LList := '';
  for LI := 0 to System.Length(Versions) - 1 do
    LList := LList + Format(' 0x%.4X', [Versions[LI]]);
  Result := Result + 'Versions:' + LList + sLineBreak;
  LList := '';
  for LI := 0 to System.Length(CipherSuites) - 1 do
    LList := LList + ' ' + TCipherSuiteCatalog.Name(CipherSuites[LI]);
  Result := Result + 'CipherSuites:' + LList + sLineBreak;
  LList := '';
  for LAead := Low(TAeadAlgorithm) to High(TAeadAlgorithm) do
    if LAead in Aeads then
    begin
      LName := TEnumUtilities.GetName<TAeadAlgorithm>(LAead);
      LList := LList + ' ' + LName;
    end;
  Result := Result + 'Aeads:' + LList + sLineBreak;
  LList := '';
  for LI := 0 to System.Length(NamedGroups) - 1 do
    LList := LList + ' ' + TNamedGroupCatalog.Name(NamedGroups[LI]);
  Result := Result + 'NamedGroups:' + LList + sLineBreak;
  LList := '';
  for LScheme := Low(TSignatureScheme) to High(TSignatureScheme) do
    if LScheme in SignatureSchemes then
    begin
      LName := TEnumUtilities.GetName<TSignatureScheme>(LScheme);
      LList := LList + ' ' + LName;
    end;
  Result := Result + 'SignatureSchemes:' + LList + sLineBreak;
  LList := '';
  for LI := 0 to System.Length(Strength.AllowedEcCurves) - 1 do
    LList := LList + ' ' + TNamedGroupCatalog.Name(Strength.AllowedEcCurves[LI]);
  if Strength.AllowEdDsa then
    LFlag := 'yes'
  else
    LFlag := 'no';
  Result := Result + Format('Strength: RsaBits %d..%d, EdDsa=%s, curves:%s',
    [Strength.MinRsaModulusBits, Strength.MaxRsaModulusBits, LFlag, LList]) + sLineBreak;
  LList := '';
  for LRequirement := Low(TComplianceRequirement) to High(TComplianceRequirement) do
    if LRequirement in Requirements then
    begin
      LName := TEnumUtilities.GetName<TComplianceRequirement>(LRequirement);
      LList := LList + ' ' + LName;
    end;
  Result := Result + 'Requirements:' + LList + sLineBreak;
  LName := TEnumUtilities.GetName<TKdfRule>(Kdf);
  Result := Result + 'Kdf: ' + LName + sLineBreak;
  LName := TEnumUtilities.GetName<TModuleStandard>(ModuleStandard);
  Result := Result + 'ModuleStandard: ' + LName;
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
    TComplianceFindingKind.RulesOutsidePresets:
      Result := TComplianceFindingCategory.Rules;
    TComplianceFindingKind.ModuleNotValidated, TComplianceFindingKind.NoBackendReport,
      TComplianceFindingKind.AlgorithmOutsideModule, TComplianceFindingKind.KdfOutsideModule,
      TComplianceFindingKind.CredentialKeyOutsideModule,
      TComplianceFindingKind.ChainVerifiedOutsideModule,
      TComplianceFindingKind.StapleVerifiedOutsideModule:
      Result := TComplianceFindingCategory.Platform;
  else
    Result := TComplianceFindingCategory.Configuration;
  end;
end;

function TComplianceFinding.Describe: string;
begin
  Result := Format('%s %s: %s', [TEnumUtilities.GetName<TComplianceFindingKind>(Kind),
    Subject, Message]);
end;

{ TComplianceCatalog }

class function TComplianceCatalog.TryKeyAgreement(AGroup: UInt16;
  out AAlgorithm: TKeyAgreementAlgorithm): Boolean;
begin
  Result := True;
  AAlgorithm := TKeyAgreementAlgorithm.X25519;
  case AGroup of
    TNamedGroupCatalog.X25519:
      AAlgorithm := TKeyAgreementAlgorithm.X25519;
    TNamedGroupCatalog.Secp256r1:
      AAlgorithm := TKeyAgreementAlgorithm.SECP256R1;
    TNamedGroupCatalog.Secp384r1:
      AAlgorithm := TKeyAgreementAlgorithm.SECP384R1;
    TNamedGroupCatalog.Secp521r1:
      AAlgorithm := TKeyAgreementAlgorithm.SECP521R1;
  else
    Result := False;
  end;
end;

class function TComplianceCatalog.SchemeHash(AScheme: TSignatureScheme): THashAlgorithm;
begin
  case AScheme of
    TSignatureScheme.ECDSA_SECP256R1_SHA256, TSignatureScheme.RSA_PSS_RSAE_SHA256,
      TSignatureScheme.RSA_PKCS1_SHA256:
      Result := THashAlgorithm.SHA_256;
    TSignatureScheme.ECDSA_SECP384R1_SHA384, TSignatureScheme.RSA_PSS_RSAE_SHA384,
      TSignatureScheme.RSA_PKCS1_SHA384:
      Result := THashAlgorithm.SHA_384;
  else
    Result := THashAlgorithm.SHA_512;
  end;
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

class function TComplianceCatalog.StrengthWithin(const AStrength,
  AFloor: TCertificateStrengthPolicy): Boolean;
begin
  Result := (AStrength.MinRsaModulusBits >= AFloor.MinRsaModulusBits) and
    ((AFloor.MaxRsaModulusBits = 0) or ((AStrength.MaxRsaModulusBits <> 0) and
    (AStrength.MaxRsaModulusBits <= AFloor.MaxRsaModulusBits))) and
    ((System.Length(AFloor.AllowedEcCurves) = 0) or
    ((System.Length(AStrength.AllowedEcCurves) > 0) and
    TComplianceCatalog.IsSubsetOfList(AStrength.AllowedEcCurves, AFloor.AllowedEcCurves))) and
    (not AStrength.AllowEdDsa or AFloor.AllowEdDsa) and
    (AStrength.AllowedDeprecatedHashes <= AFloor.AllowedDeprecatedHashes);
end;

class function TComplianceCatalog.KeyMeets(const AFacts: TCertKeyFacts;
  const AStrength: TCertificateStrengthPolicy): Boolean;
begin
  case AFacts.Kind of
    TSignatureKeyKind.Rsa:
      Result := (AFacts.Bits >= AStrength.MinRsaModulusBits) and
        ((AStrength.MaxRsaModulusBits = 0) or (AFacts.Bits <= AStrength.MaxRsaModulusBits));
    TSignatureKeyKind.Ecdsa:
      if System.Length(AStrength.AllowedEcCurves) = 0 then
        Result := AFacts.EcNamedGroup <> 0
      else
        Result := TArrayUtilities.Contains<UInt16>(AStrength.AllowedEcCurves,
          AFacts.EcNamedGroup);
    TSignatureKeyKind.Ed25519, TSignatureKeyKind.Ed448:
      Result := AStrength.AllowEdDsa;
  else
    Result := False;
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

end.
