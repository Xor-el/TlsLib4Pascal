{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

/// <summary>Tests for the TlsLib.Compliance rules algebra, the named presets, the lookups they
/// share with the refusing providers, the report and the two exceptions.</summary>
unit ComplianceRulesTests;

{$I ..\..\TlsLib\src\Include\TlsLib.inc}

interface

uses
  SysUtils,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  TlpCryptoDomainTypes,
  TlpNegotiationTypes,
  TlpTlsVersion,
  TlpTlsAlert,
  TlpPkixDomainTypes,
  TlpCertificateStrengthPolicy,
  TlpArrayUtilities,
  TlpEnumUtilities,
  TlpISigningKey,
  TlpTlsCredential,
  TlpTlsLibExceptions,
  TlpComplianceTypes,
  TlpComplianceExceptions,
  TlpIComplianceReport,
  TlpComplianceReport,
  TlpCompliancePresets,
  TlpIModuleAttestation,
  MockCompliance,
  MockCryptoProvider,
  TlsLibTestBase;

type
  TTestCompliancePresets = class(TTlsLibAlgorithmTestCase)
  strict private
    procedure CheckCodes(const AExpected: array of UInt16; const AActual: TArray<UInt16>;
      const AMessage: string);
  published
    procedure TestFips140_3Versions;
    procedure TestFips140_3CipherSuites;
    procedure TestFips140_3Aeads;
    procedure TestFips140_3NamedGroups;
    procedure TestFips140_3SignatureSchemes;
    procedure TestFips140_3Strength;
    procedure TestFips140_3RequirementsAndKdf;
    procedure TestCnsa1Versions;
    procedure TestCnsa1CipherSuitesAndAeads;
    procedure TestCnsa1GroupsAndSchemes;
    procedure TestCnsa1Strength;
    procedure TestCnsa1RequirementsAndKdf;
    procedure TestCnsa1IsSubsetOfFips140_3;
    procedure TestFips140_3IsNotSubsetOfCnsa1;
    procedure TestNamedListsMostSpecificFirst;
    procedure TestTryMatchNamesCnsa1;
    procedure TestTryMatchNamesFips140_3;
    procedure TestTryMatchNamesTightestForNarrowerRules;
    procedure TestTryMatchNamesTheTightestPresetThatHoldsNarrowerRules;
    procedure TestTryMatchLabelsRulesBetweenTheTwoPresets;
    procedure TestEveryPresetHoldsAnchorsToTheKeyFloors;
    procedure TestCnsa1IsSubsetOfFips140_3FieldByField;
    procedure TestHandBuiltWithEd25519NotSubsetOfAnyPreset;
    procedure TestTryMatchClearsNameOnMiss;
    procedure TestFips140_3WireCodes;
    procedure TestCnsa1WireCodes;
    procedure TestCnsa1RsaSizesAreFips140_3Sizes;
    procedure TestNamedLaterIsNeverSubsetOfEarlier;
    procedure TestTryMatchNamesCnsa1NarrowedToTls13;
  end;

  TTestComplianceRules = class(TTlsLibAlgorithmTestCase)
  strict private
    procedure CheckCodes(const AExpected: array of UInt16; const AActual: TArray<UInt16>;
      const AMessage: string);
  published
    procedure TestIntersectIsSubsetOfBoth;
    procedure TestIntersectIdempotent;
    procedure TestIntersectCommutesUnderEqual;
    procedure TestIntersectFipsCnsaEqualsCnsa;
    procedure TestIntersectVersionsKeepsAOrder;
    procedure TestIntersectCipherSuitesKeepsAOrder;
    procedure TestIntersectNamedGroupsKeepsAOrder;
    procedure TestIntersectAeadsIsSetIntersection;
    procedure TestIntersectSchemesIsSetIntersection;
    procedure TestIntersectStrengthMinTakesLarger;
    procedure TestIntersectStrengthMaxBothSetTakesSmaller;
    procedure TestIntersectStrengthMaxZeroInATakesB;
    procedure TestIntersectStrengthMaxZeroInBTakesA;
    procedure TestIntersectStrengthMaxBothZeroStaysZero;
    procedure TestIntersectCurvesIntersectInAOrder;
    procedure TestIntersectCurvesEmptyAUsesB;
    procedure TestIntersectCurvesEmptyBUsesA;
    procedure TestIntersectDisjointCurvesRaises;
    procedure TestIntersectBothCurvesEmptyRaises;
    procedure TestIntersectEdDsaIsAnd;
    procedure TestIntersectDeprecatedHashesIsSetIntersection;
    procedure TestIntersectUnionsRequirements;
    procedure TestIntersectKdfRequireModuleWinsFromA;
    procedure TestIntersectKdfRequireModuleWinsFromB;
    procedure TestIntersectKdfBothComposedStaysComposed;
    procedure TestIntersectKeepsModuleStandard;
    procedure TestIntersectDoesNotShareArraysWithOperands;
    procedure TestSubsetExtraVersion;
    procedure TestSubsetExtraCipherSuite;
    procedure TestSubsetExtraNamedGroup;
    procedure TestSubsetExtraAead;
    procedure TestSubsetExtraScheme;
    procedure TestSubsetMinBitsBoundary;
    procedure TestSubsetMaxBitsBoundary;
    procedure TestSubsetUncappedSelfAgainstCappedOther;
    procedure TestSubsetCappedSelfAgainstUncappedOther;
    procedure TestSubsetCurvesBoundaries;
    procedure TestSubsetEdDsaBoundary;
    procedure TestSubsetDeprecatedHashesBoundary;
    procedure TestSubsetMissingRequirement;
    procedure TestSubsetKdfBoundary;
    procedure TestSubsetOfItself;
    procedure TestEqualIgnoresOrder;
    procedure TestEqualDetectsDifferentRules;
    procedure TestEqualDetectsDifferentRequirements;
    procedure TestCloneEqualsOriginal;
    procedure TestCloneDoesNotShareVersions;
    procedure TestCloneDoesNotShareCipherSuites;
    procedure TestCloneDoesNotShareNamedGroups;
    procedure TestCloneDoesNotShareCurves;
    procedure TestDescribeCnsa1ListsEveryField;
    procedure TestDescribeNamesGroupsInOrder;
    procedure TestDescribeListsDeprecatedHashes;
    procedure TestDescribeListsRsaSizes;
    procedure TestIntersectMinAboveMaxRaises;
    procedure TestIntersectMinEqualMaxIsKept;
    procedure TestIntersectRsaSizesIntersectInAOrder;
    procedure TestIntersectRsaSizesEmptyAUsesB;
    procedure TestIntersectRsaSizesEmptyBUsesA;
    procedure TestIntersectRsaSizesBothEmptyStaysEmpty;
    procedure TestIntersectDisjointRsaSizesRaises;
    procedure TestIntersectRsaSizesAreCutToTheRange;
    procedure TestIntersectRsaSizesOutsideTheRangeRaise;
    procedure TestIntersectRsaSizesAreNotAliased;
    procedure TestIntersectCurvesEmptyBIsNotAliased;
    procedure TestIntersectNoncomparableAeads;
    procedure TestIntersectNoncomparableEdDsaAndHashes;
    procedure TestSubsetRsaSizesBoundaries;
    procedure TestSubsetKdfBothRequireModule;
    procedure TestSubsetKdfBothComposed;
    procedure TestSubsetBothCurveListsEmpty;
    procedure TestCloneDoesNotShareRsaSizes;
    procedure TestIntersectAnchorKeyFloorsFromAWins;
    procedure TestIntersectAnchorKeyFloorsFromBWins;
    procedure TestIntersectAnchorKeyFloorsBothOffStaysOff;
    procedure TestSubsetWithoutAnchorKeyFloorsIsNotWithinAPresetThatHasThem;
    procedure TestSubsetWithAnchorKeyFloorsIsWithinRulesThatLackThem;
    procedure TestEqualDetectsDifferentAnchorKeyFloors;
  end;

  TTestComplianceCatalog = class(TTlsLibAlgorithmTestCase)
  strict private
    function Held(const AKey: ISigningKey; const AChain: array of TBytes): TTlsCredential;
  published
    procedure TestSignatureMeetsFollowsTheSchemeHashes;
    procedure TestSignatureMeetsRefusesTheHashesNoSchemeUses;
    procedure TestSignatureMeetsAdmitsADeprecatedHashTheStrengthAdmits;
    procedure TestSignatureMeetsFollowsTheEdDsaFlagForAnImplicitHash;
    procedure TestSignatureMeetsNeedsTheEdDsaSchemeInTheRules;
    procedure TestSignatureMeetsAdmitsOnlyHashesTheCoreDeprecates;
    procedure TestSignatureMeetsRefusesAFamilyTheSchemesDoNotName;
    procedure TestSignatureMeetsKeepsEcdsaOutOfRsaOnlyRules;
    procedure TestSignatureMeetsAdmitsCanonicalPssAsRsae;
    procedure TestSignatureMeetsRefusesPssUnderAPssIssuerKey;
    procedure TestSignatureMeetsRefusesNonCanonicalPss;
    procedure TestSignatureMeetsRefusesNonCanonicalPssWithAnAdmittedHash;
    procedure TestSameCredentialNeedsTheSameKeyObjectAndChainBytes;
    procedure TestTryKeyAgreementRejectsHybridAndKem;
    procedure TestKeyAgreementsFips140_3;
    procedure TestKeyAgreementsCnsa1;
    procedure TestKeyAgreementsIncludesX25519Group;
    procedure TestKeyAgreementsIgnoreNonClassicalGroup;
    procedure TestIsSubsetOfListBoundaries;
    procedure TestSchemesInEnumOrder;
    procedure TestSchemesEmptySet;
    procedure TestRsaSizesWithinBoundaries;
    procedure TestKeyMeetsRsaExactSizesListed;
    procedure TestKeyMeetsRsaExactSizesRefuseOthers;
    procedure TestKeyMeetsRsaExactSizesStillHonourRange;
    procedure TestKeyMeetsRsaExactSizesRefuseZeroBits;
    procedure TestKeyMeetsExactSizesLeaveEcdsaAlone;
    procedure TestStandardNameIsFips140_3;
  end;

  TTestComplianceReport = class(TTlsLibAlgorithmTestCase)
  published
    procedure TestVerdictCompliantWithPresetAndNoFindings;
    procedure TestVerdictPrimitivesInModuleWithComposedKeyDerivation;
    procedure TestVerdictNotCompliantWithFindingAndComposedKeyDerivation;
    procedure TestVerdictNotCompliantWhenModuleNotValidatedAndKdfInModule;
    procedure TestVerdictNotCompliantWithFinding;
    procedure TestVerdictNotCompliantWithoutPreset;
    procedure TestReportCarriesEnforcementAndPreset;
    procedure TestReportCarriesModuleFromAttestation;
    procedure TestReportFindingsAndDisclosuresRoundTrip;
    procedure TestReportCopiesFindingsOnCreate;
    procedure TestReportReturnsCopyOfFindings;
    procedure TestReportDescribeCompliant;
    procedure TestReportDescribeNotCompliant;
    procedure TestReportDescribeNamesThePrimitivesInModuleLevel;
    procedure TestFindingCreateSetsFields;
    procedure TestFindingDescribeFormat;
    procedure TestFindingCategoryPerKind;
    procedure TestUnmetExceptionCarriesFindings;
    procedure TestUnmetExceptionMessageJoinsFindings;
    procedure TestUnmetExceptionCopiesFindings;
    procedure TestRefusedExceptionIsFatalInternalError;
    procedure TestFakeAttestationAnswersGivenValues;
    procedure TestVerdictNotCompliantWhenModuleNotValidated;
    procedure TestVerdictNotCompliantWhenModuleUnknown;
    procedure TestReportCopiesDisclosuresOnCreate;
    procedure TestReportReturnsCopyOfDisclosures;
    procedure TestFindingDescribeWithoutSubject;
    procedure TestIdentityDescribeSkipsEmptyParts;
    procedure TestIdentityDescribeEmpty;
    procedure TestIdentityDescribePrintsTheArchitectureAndLegacyPolicy;
    procedure TestIdentityDescribeHidesAnUnreadMachine;
    procedure TestIdentityDescribeProcessMachineAloneHasNoDoubleSpace;
    procedure TestIdentityDescribePrintsEditionAndFirmware;
    procedure TestReportDescribeWithoutCertificate;
    procedure TestUnmetExceptionReturnsCopyOfFindings;
    procedure TestRefusedExceptionCreateRes;
  end;

implementation

resourcestring
  SRefusedProbe = 'refused %s';
  SRefusedNoArgument = 'refused without an argument';

{ TTestCompliancePresets }

procedure TTestCompliancePresets.CheckCodes(const AExpected: array of UInt16;
  const AActual: TArray<UInt16>; const AMessage: string);
var
  LI: Int32;
begin
  CheckEquals(System.Length(AExpected), System.Length(AActual), AMessage + ' length');
  for LI := 0 to System.Length(AExpected) - 1 do
    CheckEquals(AExpected[LI], AActual[LI], AMessage + ' item ' + IntToStr(LI));
end;

procedure TTestCompliancePresets.TestFips140_3Versions;
begin
  CheckCodes([TlsWireVersionTls13, TlsWireVersionTls12], TCompliancePresets.Fips140_3.Versions,
    'versions');
end;

procedure TTestCompliancePresets.TestFips140_3CipherSuites;
begin
  CheckCodes([TCipherSuites13.Aes128GcmSha256, TCipherSuites13.Aes256GcmSha384,
    TCipherSuites12.EcdheEcdsaAes128GcmSha256, TCipherSuites12.EcdheEcdsaAes256GcmSha384,
    TCipherSuites12.EcdheRsaAes128GcmSha256, TCipherSuites12.EcdheRsaAes256GcmSha384],
    TCompliancePresets.Fips140_3.CipherSuites, 'suites');
end;

procedure TTestCompliancePresets.TestFips140_3Aeads;
begin
  CheckTrue(TCompliancePresets.Fips140_3.Aeads =
    [TAeadAlgorithm.AES_128_GCM, TAeadAlgorithm.AES_256_GCM], 'AES-GCM only, no ChaCha');
end;

procedure TTestCompliancePresets.TestFips140_3NamedGroups;
begin
  CheckCodes([TNamedGroupCatalog.Secp256r1, TNamedGroupCatalog.Secp384r1,
    TNamedGroupCatalog.Secp521r1], TCompliancePresets.Fips140_3.NamedGroups, 'groups');
end;

procedure TTestCompliancePresets.TestFips140_3SignatureSchemes;
begin
  CheckTrue(TCompliancePresets.Fips140_3.SignatureSchemes =
    [TSignatureScheme.ECDSA_SECP256R1_SHA256, TSignatureScheme.ECDSA_SECP384R1_SHA384,
    TSignatureScheme.ECDSA_SECP521R1_SHA512, TSignatureScheme.RSA_PSS_RSAE_SHA256,
    TSignatureScheme.RSA_PSS_RSAE_SHA384, TSignatureScheme.RSA_PSS_RSAE_SHA512,
    TSignatureScheme.RSA_PKCS1_SHA256, TSignatureScheme.RSA_PKCS1_SHA384,
    TSignatureScheme.RSA_PKCS1_SHA512], 'ECDSA P-curves, RSA-PSS and PKCS#1, no EdDSA');
end;

procedure TTestCompliancePresets.TestFips140_3Strength;
var
  LRules: TComplianceRules;
begin
  LRules := TCompliancePresets.Fips140_3;
  CheckEquals(2048, LRules.Strength.MinRsaModulusBits, 'min RSA bits');
  CheckEquals(4096, LRules.Strength.MaxRsaModulusBits, 'max RSA bits');
  CheckEquals(3, System.Length(LRules.RsaModulusBits), 'exact RSA size count');
  CheckEquals(2048, Int32(LRules.RsaModulusBits[0]), 'first RSA size');
  CheckEquals(3072, Int32(LRules.RsaModulusBits[1]), 'second RSA size');
  CheckEquals(4096, Int32(LRules.RsaModulusBits[2]), 'third RSA size');
  CheckCodes([TNamedGroupCatalog.Secp256r1, TNamedGroupCatalog.Secp384r1,
    TNamedGroupCatalog.Secp521r1], LRules.Strength.AllowedEcCurves, 'curves');
  CheckFalse(LRules.Strength.AllowEdDsa, 'no EdDSA');
  CheckTrue(LRules.Strength.AllowedDeprecatedHashes = [], 'no deprecated hash');
end;

procedure TTestCompliancePresets.TestFips140_3RequirementsAndKdf;
var
  LRules: TComplianceRules;
begin
  LRules := TCompliancePresets.Fips140_3;
  CheckTrue(LRules.Requirements = [TComplianceRequirement.ExtendedMasterSecret,
    TComplianceRequirement.NoEarlyData, TComplianceRequirement.NoEch,
    TComplianceRequirement.NoExternalPsk, TComplianceRequirement.NoTls12Psk,
    TComplianceRequirement.NoKeyLog, TComplianceRequirement.NoDangerousTrust,
    TComplianceRequirement.InModuleChainVerification], 'every requirement');
  CheckEquals(Ord(TKdfRule.AllowComposed), Ord(LRules.Kdf), 'kdf');
  CheckEquals(Ord(TModuleStandard.Fips140_3), Ord(LRules.ModuleStandard), 'standard');
end;

procedure TTestCompliancePresets.TestCnsa1Versions;
begin
  CheckCodes([TlsWireVersionTls13, TlsWireVersionTls12], TCompliancePresets.Cnsa1.Versions,
    'versions');
end;

procedure TTestCompliancePresets.TestCnsa1CipherSuitesAndAeads;
var
  LRules: TComplianceRules;
begin
  LRules := TCompliancePresets.Cnsa1;
  CheckCodes([TCipherSuites13.Aes256GcmSha384, TCipherSuites12.EcdheEcdsaAes256GcmSha384,
    TCipherSuites12.EcdheRsaAes256GcmSha384], LRules.CipherSuites, 'suites');
  CheckTrue(LRules.Aeads = [TAeadAlgorithm.AES_256_GCM], 'AES-256 only');
end;

procedure TTestCompliancePresets.TestCnsa1GroupsAndSchemes;
var
  LRules: TComplianceRules;
begin
  LRules := TCompliancePresets.Cnsa1;
  CheckCodes([TNamedGroupCatalog.Secp384r1], LRules.NamedGroups, 'groups');
  CheckTrue(LRules.SignatureSchemes = [TSignatureScheme.ECDSA_SECP384R1_SHA384,
    TSignatureScheme.RSA_PSS_RSAE_SHA384, TSignatureScheme.RSA_PKCS1_SHA384],
    'SHA-384 schemes only');
end;

procedure TTestCompliancePresets.TestCnsa1Strength;
var
  LRules: TComplianceRules;
begin
  LRules := TCompliancePresets.Cnsa1;
  CheckEquals(3072, LRules.Strength.MinRsaModulusBits, 'min RSA bits');
  CheckEquals(4096, LRules.Strength.MaxRsaModulusBits, 'max RSA bits');
  CheckEquals(2, System.Length(LRules.RsaModulusBits), 'exact RSA size count');
  CheckEquals(3072, Int32(LRules.RsaModulusBits[0]), 'first RSA size');
  CheckEquals(4096, Int32(LRules.RsaModulusBits[1]), 'second RSA size');
  CheckCodes([TNamedGroupCatalog.Secp384r1], LRules.Strength.AllowedEcCurves, 'curves');
  CheckFalse(LRules.Strength.AllowEdDsa, 'no EdDSA');
  CheckTrue(LRules.Strength.AllowedDeprecatedHashes = [], 'no deprecated hash');
end;

procedure TTestCompliancePresets.TestCnsa1RequirementsAndKdf;
var
  LRules: TComplianceRules;
begin
  LRules := TCompliancePresets.Cnsa1;
  CheckTrue(LRules.Requirements = [Low(TComplianceRequirement) .. High(TComplianceRequirement)],
    'every requirement');
  CheckEquals(Ord(TKdfRule.AllowComposed), Ord(LRules.Kdf), 'kdf');
  CheckEquals(Ord(TModuleStandard.Fips140_3), Ord(LRules.ModuleStandard), 'standard');
end;

procedure TTestCompliancePresets.TestCnsa1IsSubsetOfFips140_3;
begin
  CheckTrue(TCompliancePresets.Cnsa1.IsSubsetOf(TCompliancePresets.Fips140_3),
    'Cnsa1 narrows Fips140_3');
end;

procedure TTestCompliancePresets.TestFips140_3IsNotSubsetOfCnsa1;
begin
  CheckFalse(TCompliancePresets.Fips140_3.IsSubsetOf(TCompliancePresets.Cnsa1),
    'Cnsa1 is the narrower preset');
end;

procedure TTestCompliancePresets.TestNamedListsMostSpecificFirst;
var
  LNamed: TArray<TCompliancePreset>;
begin
  LNamed := TCompliancePresets.Named;
  CheckEquals(2, System.Length(LNamed), 'two presets');
  CheckEquals('Cnsa1', LNamed[0].Name, 'first');
  CheckEquals('Fips140_3', LNamed[1].Name, 'second');
  CheckTrue(LNamed[0].Rules = TCompliancePresets.Cnsa1, 'Cnsa1 rules');
  CheckTrue(LNamed[1].Rules = TCompliancePresets.Fips140_3, 'Fips140_3 rules');
end;

procedure TTestCompliancePresets.TestTryMatchNamesCnsa1;
var
  LName: string;
begin
  CheckTrue(TCompliancePresets.TryMatch(TCompliancePresets.Cnsa1, LName), 'matches');
  CheckEquals('Cnsa1', LName, 'equal rules carry the bare name');
end;

procedure TTestCompliancePresets.TestTryMatchNamesFips140_3;
var
  LName: string;
begin
  CheckTrue(TCompliancePresets.TryMatch(TCompliancePresets.Fips140_3, LName), 'matches');
  CheckEquals('Fips140_3', LName, 'equal rules carry the bare name, not the narrower Cnsa1');
end;

procedure TTestCompliancePresets.TestTryMatchNamesTightestForNarrowerRules;
var
  LRules: TComplianceRules;
  LName: string;
begin
  LRules := TCompliancePresets.Fips140_3;
  LRules.Versions := TArray<UInt16>.Create(TlsWireVersionTls13);
  CheckTrue(TCompliancePresets.TryMatch(LRules, LName), 'a narrowed Fips140_3 matches');
  CheckEquals('within Fips140_3', LName, 'narrower rules are labelled as within the preset');
end;

procedure TTestCompliancePresets.TestHandBuiltWithEd25519NotSubsetOfAnyPreset;
var
  LRules: TComplianceRules;
  LName: string;
begin
  LRules := TCompliancePresets.Fips140_3;
  Include(LRules.SignatureSchemes, TSignatureScheme.ED25519);
  CheckFalse(TCompliancePresets.TryMatch(LRules, LName), 'Ed25519 fits no preset');
  CheckEquals('', LName, 'no name');
end;

procedure TTestCompliancePresets.TestTryMatchClearsNameOnMiss;
var
  LRules: TComplianceRules;
  LName: string;
begin
  LRules := TCompliancePresets.Fips140_3;
  LRules.Strength.MinRsaModulusBits := 1024;
  LName := 'stale';
  CheckFalse(TCompliancePresets.TryMatch(LRules, LName), 'a 1024-bit floor fits no preset');
  CheckEquals('', LName, 'the out name is cleared');
end;

procedure TTestCompliancePresets.TestFips140_3WireCodes;
var
  LRules: TComplianceRules;
begin
  LRules := TCompliancePresets.Fips140_3;
  CheckCodes([$0304, $0303], LRules.Versions, 'versions');
  CheckCodes([$1301, $1302, $C02B, $C02C, $C02F, $C030], LRules.CipherSuites, 'suites');
  CheckCodes([$0017, $0018, $0019], LRules.NamedGroups, 'groups');
  CheckCodes([$0017, $0018, $0019], LRules.Strength.AllowedEcCurves, 'curves');
end;

procedure TTestCompliancePresets.TestCnsa1WireCodes;
var
  LRules: TComplianceRules;
begin
  LRules := TCompliancePresets.Cnsa1;
  CheckCodes([$0304, $0303], LRules.Versions, 'versions');
  CheckCodes([$1302, $C02C, $C030], LRules.CipherSuites, 'suites');
  CheckCodes([$0018], LRules.NamedGroups, 'groups');
  CheckCodes([$0018], LRules.Strength.AllowedEcCurves, 'curves');
end;

procedure TTestCompliancePresets.TestCnsa1RsaSizesAreFips140_3Sizes;
var
  LCnsa, LFips: TComplianceRules;
  LI, LJ: Int32;
  LFound: Boolean;
begin
  LCnsa := TCompliancePresets.Cnsa1;
  LFips := TCompliancePresets.Fips140_3;
  CheckTrue(System.Length(LCnsa.RsaModulusBits) > 0, 'not vacuous');
  for LI := 0 to System.Length(LCnsa.RsaModulusBits) - 1 do
  begin
    LFound := False;
    for LJ := 0 to System.Length(LFips.RsaModulusBits) - 1 do
      if LFips.RsaModulusBits[LJ] = LCnsa.RsaModulusBits[LI] then
        LFound := True;
    CheckTrue(LFound, 'size ' + IntToStr(LCnsa.RsaModulusBits[LI]));
  end;
end;

procedure TTestCompliancePresets.TestNamedLaterIsNeverSubsetOfEarlier;
var
  LNamed: TArray<TCompliancePreset>;
  LI, LJ: Int32;
begin
  LNamed := TCompliancePresets.Named;
  CheckEquals(2, System.Length(LNamed), 'not vacuous');
  for LI := 0 to System.Length(LNamed) - 1 do
    for LJ := LI + 1 to System.Length(LNamed) - 1 do
      CheckFalse(LNamed[LJ].Rules.IsSubsetOf(LNamed[LI].Rules),
        LNamed[LJ].Name + ' is not inside the tighter ' + LNamed[LI].Name);
end;

procedure TTestCompliancePresets.TestTryMatchNamesTheTightestPresetThatHoldsNarrowerRules;
var
  LRules: TComplianceRules;
  LName: string;
begin
  LRules := TCompliancePresets.Cnsa1;
  LRules.Strength.MinRsaModulusBits := 4096;
  LRules.RsaModulusBits := TArray<UInt32>.Create(4096);
  CheckTrue(TCompliancePresets.TryMatch(LRules, LName), 'narrower than Cnsa1');
  CheckEquals('within Cnsa1', LName, 'the tightest preset is named, not Fips140_3');
end;

procedure TTestCompliancePresets.TestTryMatchLabelsRulesBetweenTheTwoPresets;
var
  LRules: TComplianceRules;
  LName: string;
begin
  LRules := TCompliancePresets.Fips140_3;
  LRules.CipherSuites := TArray<UInt16>.Create(TCipherSuites13.Aes256GcmSha384,
    TCipherSuites12.EcdheEcdsaAes256GcmSha384, TCipherSuites12.EcdheRsaAes256GcmSha384,
    TCipherSuites13.Aes128GcmSha256, TCipherSuites12.EcdheEcdsaAes128GcmSha256);
  CheckTrue(TCompliancePresets.TryMatch(LRules, LName), 'inside Fips140_3');
  CheckEquals('within Fips140_3', LName, 'wider than Cnsa1, so not labelled by it');
end;

procedure TTestCompliancePresets.TestEveryPresetHoldsAnchorsToTheKeyFloors;
var
  LNamed: TArray<TCompliancePreset>;
  LI: Int32;
begin
  LNamed := TCompliancePresets.Named;
  CheckEquals(2, System.Length(LNamed), 'not vacuous');
  for LI := 0 to System.Length(LNamed) - 1 do
    CheckTrue(LNamed[LI].Rules.Strength.AnchorKeyFloors, LNamed[LI].Name);
end;

procedure TTestCompliancePresets.TestCnsa1IsSubsetOfFips140_3FieldByField;
var
  LCnsa, LFips: TComplianceRules;
begin
  LCnsa := TCompliancePresets.Cnsa1;
  LFips := TCompliancePresets.Fips140_3;
  CheckTrue(TComplianceCatalog.IsSubsetOfList(LCnsa.Versions, LFips.Versions), 'versions');
  CheckTrue(TComplianceCatalog.IsSubsetOfList(LCnsa.CipherSuites, LFips.CipherSuites), 'suites');
  CheckTrue(LCnsa.Aeads <= LFips.Aeads, 'aeads');
  CheckTrue(TComplianceCatalog.IsSubsetOfList(LCnsa.NamedGroups, LFips.NamedGroups), 'groups');
  CheckTrue(LCnsa.SignatureSchemes <= LFips.SignatureSchemes, 'schemes');
  CheckTrue(LCnsa.Strength.IsAtLeastAsStrictAs(LFips.Strength), 'strength');
  CheckTrue(TComplianceCatalog.RsaSizesWithin(LCnsa.RsaModulusBits, LFips.RsaModulusBits),
    'RSA sizes');
  CheckTrue(LFips.Requirements <= LCnsa.Requirements, 'requirements');
  CheckEquals(Ord(LFips.Kdf), Ord(LCnsa.Kdf), 'the key-derivation rule');
  CheckEquals(Ord(LFips.ModuleStandard), Ord(LCnsa.ModuleStandard), 'the standard');
  CheckTrue(LCnsa.IsSubsetOf(LFips), 'and as a whole');
end;

procedure TTestCompliancePresets.TestTryMatchNamesCnsa1NarrowedToTls13;
var
  LRules: TComplianceRules;
  LName: string;
begin
  LRules := TCompliancePresets.Cnsa1;
  LRules.Versions := TArray<UInt16>.Create(TlsWireVersionTls13);
  LRules.CipherSuites := TArray<UInt16>.Create(TCipherSuites13.Aes256GcmSha384);
  CheckTrue(TCompliancePresets.TryMatch(LRules, LName), 'a narrowed Cnsa1 matches');
  CheckEquals('within Cnsa1', LName, 'still the tightest preset');
end;

{ TTestComplianceRules }

procedure TTestComplianceRules.CheckCodes(const AExpected: array of UInt16;
  const AActual: TArray<UInt16>; const AMessage: string);
var
  LI: Int32;
begin
  CheckEquals(System.Length(AExpected), System.Length(AActual), AMessage + ' length');
  for LI := 0 to System.Length(AExpected) - 1 do
    CheckEquals(AExpected[LI], AActual[LI], AMessage + ' item ' + IntToStr(LI));
end;

procedure TTestComplianceRules.TestIntersectIsSubsetOfBoth;
var
  LNamed: TArray<TCompliancePreset>;
  LA, LB: Int32;
  LResult: TComplianceRules;
begin
  LNamed := TCompliancePresets.Named;
  CheckEquals(2, System.Length(LNamed), 'the pairs are not vacuous');
  for LA := 0 to System.Length(LNamed) - 1 do
    for LB := 0 to System.Length(LNamed) - 1 do
    begin
      LResult := TComplianceRules.Intersect(LNamed[LA].Rules, LNamed[LB].Rules);
      CheckTrue(LResult.IsSubsetOf(LNamed[LA].Rules),
        'inside ' + LNamed[LA].Name + ' of ' + LNamed[LB].Name);
      CheckTrue(LResult.IsSubsetOf(LNamed[LB].Rules),
        'inside ' + LNamed[LB].Name + ' of ' + LNamed[LA].Name);
    end;
end;

procedure TTestComplianceRules.TestIntersectIdempotent;
var
  LNamed: TArray<TCompliancePreset>;
  LI: Int32;
begin
  LNamed := TCompliancePresets.Named;
  CheckEquals(2, System.Length(LNamed), 'not vacuous');
  for LI := 0 to System.Length(LNamed) - 1 do
    CheckTrue(TComplianceRules.Intersect(LNamed[LI].Rules, LNamed[LI].Rules) =
      LNamed[LI].Rules, LNamed[LI].Name);
end;

procedure TTestComplianceRules.TestIntersectCommutesUnderEqual;
var
  LNamed: TArray<TCompliancePreset>;
  LA, LB: Int32;
begin
  LNamed := TCompliancePresets.Named;
  CheckEquals(2, System.Length(LNamed), 'not vacuous');
  for LA := 0 to System.Length(LNamed) - 1 do
    for LB := 0 to System.Length(LNamed) - 1 do
      CheckTrue(TComplianceRules.Intersect(LNamed[LA].Rules, LNamed[LB].Rules) =
        TComplianceRules.Intersect(LNamed[LB].Rules, LNamed[LA].Rules),
        LNamed[LA].Name + ' and ' + LNamed[LB].Name);
end;

procedure TTestComplianceRules.TestIntersectFipsCnsaEqualsCnsa;
begin
  CheckTrue(TComplianceRules.Intersect(TCompliancePresets.Fips140_3,
    TCompliancePresets.Cnsa1) = TCompliancePresets.Cnsa1, 'Fips140_3 with Cnsa1');
  CheckTrue(TComplianceRules.Intersect(TCompliancePresets.Cnsa1,
    TCompliancePresets.Fips140_3) = TCompliancePresets.Cnsa1, 'Cnsa1 with Fips140_3');
end;

procedure TTestComplianceRules.TestIntersectVersionsKeepsAOrder;
var
  LA, LB: TComplianceRules;
begin
  LA := TCompliancePresets.Fips140_3;
  LA.Versions := TArray<UInt16>.Create(TlsWireVersionTls12, TlsWireVersionTls13);
  LB := TCompliancePresets.Fips140_3;
  CheckCodes([TlsWireVersionTls12, TlsWireVersionTls13],
    TComplianceRules.Intersect(LA, LB).Versions, 'A order');
  LB.Versions := TArray<UInt16>.Create(TlsWireVersionTls13);
  CheckCodes([TlsWireVersionTls13], TComplianceRules.Intersect(LA, LB).Versions, 'B narrows');
end;

procedure TTestComplianceRules.TestIntersectCipherSuitesKeepsAOrder;
var
  LA, LB: TComplianceRules;
begin
  LA := TCompliancePresets.Fips140_3;
  LA.CipherSuites := TArray<UInt16>.Create(TCipherSuites13.Aes256GcmSha384,
    TCipherSuites13.Aes128GcmSha256, TCipherSuites12.EcdheRsaAes128GcmSha256);
  LB := TCompliancePresets.Fips140_3;
  LB.CipherSuites := TArray<UInt16>.Create(TCipherSuites12.EcdheRsaAes128GcmSha256,
    TCipherSuites13.Aes256GcmSha384);
  CheckCodes([TCipherSuites13.Aes256GcmSha384, TCipherSuites12.EcdheRsaAes128GcmSha256],
    TComplianceRules.Intersect(LA, LB).CipherSuites, 'shared suites in A order');
end;

procedure TTestComplianceRules.TestIntersectNamedGroupsKeepsAOrder;
var
  LA, LB: TComplianceRules;
begin
  LA := TCompliancePresets.Fips140_3;
  LA.NamedGroups := TArray<UInt16>.Create(TNamedGroupCatalog.Secp521r1,
    TNamedGroupCatalog.Secp256r1, TNamedGroupCatalog.Secp384r1);
  LB := TCompliancePresets.Fips140_3;
  LB.NamedGroups := TArray<UInt16>.Create(TNamedGroupCatalog.Secp384r1,
    TNamedGroupCatalog.Secp521r1);
  CheckCodes([TNamedGroupCatalog.Secp521r1, TNamedGroupCatalog.Secp384r1],
    TComplianceRules.Intersect(LA, LB).NamedGroups, 'shared groups in A order');
end;

procedure TTestComplianceRules.TestIntersectAeadsIsSetIntersection;
var
  LA, LB: TComplianceRules;
begin
  LA := TCompliancePresets.Fips140_3;
  LB := TCompliancePresets.Fips140_3;
  LB.Aeads := [TAeadAlgorithm.AES_256_GCM, TAeadAlgorithm.CHACHA20_POLY1305];
  CheckTrue(TComplianceRules.Intersect(LA, LB).Aeads = [TAeadAlgorithm.AES_256_GCM],
    'only the shared AEAD');
end;

procedure TTestComplianceRules.TestIntersectSchemesIsSetIntersection;
var
  LA, LB: TComplianceRules;
begin
  LA := TCompliancePresets.Fips140_3;
  LB := TCompliancePresets.Fips140_3;
  LB.SignatureSchemes := [TSignatureScheme.ECDSA_SECP384R1_SHA384, TSignatureScheme.ED25519];
  CheckTrue(TComplianceRules.Intersect(LA, LB).SignatureSchemes =
    [TSignatureScheme.ECDSA_SECP384R1_SHA384], 'only the shared scheme');
end;

procedure TTestComplianceRules.TestIntersectStrengthMinTakesLarger;
var
  LA, LB: TComplianceRules;
begin
  LA := TCompliancePresets.Fips140_3;
  LA.Strength.MinRsaModulusBits := 3072;
  LB := TCompliancePresets.Fips140_3;
  LB.Strength.MinRsaModulusBits := 4096;
  CheckEquals(4096, TComplianceRules.Intersect(LA, LB).Strength.MinRsaModulusBits, 'B larger');
  CheckEquals(4096, TComplianceRules.Intersect(LB, LA).Strength.MinRsaModulusBits, 'A larger');
end;

procedure TTestComplianceRules.TestIntersectStrengthMaxBothSetTakesSmaller;
var
  LA, LB: TComplianceRules;
begin
  LA := TCompliancePresets.Fips140_3;
  LA.Strength.MaxRsaModulusBits := 4096;
  LB := TCompliancePresets.Fips140_3;
  LB.Strength.MaxRsaModulusBits := 8192;
  CheckEquals(4096, TComplianceRules.Intersect(LA, LB).Strength.MaxRsaModulusBits, 'A smaller');
  CheckEquals(4096, TComplianceRules.Intersect(LB, LA).Strength.MaxRsaModulusBits, 'B smaller');
end;

procedure TTestComplianceRules.TestIntersectStrengthMaxZeroInATakesB;
var
  LA, LB: TComplianceRules;
begin
  LA := TCompliancePresets.Fips140_3;
  LA.Strength.MaxRsaModulusBits := 0;
  LB := TCompliancePresets.Fips140_3;
  LB.Strength.MaxRsaModulusBits := 4096;
  CheckEquals(4096, TComplianceRules.Intersect(LA, LB).Strength.MaxRsaModulusBits,
    'no cap on A means B caps');
end;

procedure TTestComplianceRules.TestIntersectStrengthMaxZeroInBTakesA;
var
  LA, LB: TComplianceRules;
begin
  LA := TCompliancePresets.Fips140_3;
  LA.Strength.MaxRsaModulusBits := 4096;
  LB := TCompliancePresets.Fips140_3;
  LB.Strength.MaxRsaModulusBits := 0;
  CheckEquals(4096, TComplianceRules.Intersect(LA, LB).Strength.MaxRsaModulusBits,
    'no cap on B means A caps');
end;

procedure TTestComplianceRules.TestIntersectStrengthMaxBothZeroStaysZero;
var
  LA, LB: TComplianceRules;
begin
  LA := TCompliancePresets.Fips140_3;
  LA.Strength.MaxRsaModulusBits := 0;
  LB := TCompliancePresets.Fips140_3;
  LB.Strength.MaxRsaModulusBits := 0;
  CheckEquals(0, TComplianceRules.Intersect(LA, LB).Strength.MaxRsaModulusBits, 'still no cap');
end;

procedure TTestComplianceRules.TestIntersectCurvesIntersectInAOrder;
var
  LA, LB: TComplianceRules;
begin
  LA := TCompliancePresets.Fips140_3;
  LA.Strength.AllowedEcCurves := TArray<UInt16>.Create(TNamedGroupCatalog.Secp521r1,
    TNamedGroupCatalog.Secp256r1, TNamedGroupCatalog.Secp384r1);
  LB := TCompliancePresets.Fips140_3;
  LB.Strength.AllowedEcCurves := TArray<UInt16>.Create(TNamedGroupCatalog.Secp384r1,
    TNamedGroupCatalog.Secp521r1);
  CheckCodes([TNamedGroupCatalog.Secp521r1, TNamedGroupCatalog.Secp384r1],
    TComplianceRules.Intersect(LA, LB).Strength.AllowedEcCurves, 'shared curves');
end;

procedure TTestComplianceRules.TestIntersectCurvesEmptyAUsesB;
var
  LA, LB: TComplianceRules;
begin
  LA := TCompliancePresets.Fips140_3;
  LA.Strength.AllowedEcCurves := nil;
  LB := TCompliancePresets.Fips140_3;
  LB.Strength.AllowedEcCurves := TArray<UInt16>.Create(TNamedGroupCatalog.Secp384r1);
  CheckCodes([TNamedGroupCatalog.Secp384r1],
    TComplianceRules.Intersect(LA, LB).Strength.AllowedEcCurves, 'any curve on A means B');
end;

procedure TTestComplianceRules.TestIntersectCurvesEmptyBUsesA;
var
  LA, LB: TComplianceRules;
begin
  LA := TCompliancePresets.Fips140_3;
  LA.Strength.AllowedEcCurves := TArray<UInt16>.Create(TNamedGroupCatalog.Secp384r1);
  LB := TCompliancePresets.Fips140_3;
  LB.Strength.AllowedEcCurves := nil;
  CheckCodes([TNamedGroupCatalog.Secp384r1],
    TComplianceRules.Intersect(LA, LB).Strength.AllowedEcCurves, 'any curve on B means A');
end;

procedure TTestComplianceRules.TestIntersectDisjointCurvesRaises;
var
  LA, LB: TComplianceRules;
  LRaised: Boolean;
begin
  LA := TCompliancePresets.Fips140_3;
  LA.Strength.AllowedEcCurves := TArray<UInt16>.Create(TNamedGroupCatalog.Secp256r1);
  LB := TCompliancePresets.Fips140_3;
  LB.Strength.AllowedEcCurves := TArray<UInt16>.Create(TNamedGroupCatalog.Secp384r1);
  LRaised := False;
  try
    TComplianceRules.Intersect(LA, LB);
  except
    on EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'disjoint curve lists must not collapse into "any curve"');
end;

procedure TTestComplianceRules.TestIntersectBothCurvesEmptyRaises;
var
  LA, LB: TComplianceRules;
  LRaised: Boolean;
begin
  LA := TCompliancePresets.Fips140_3;
  LA.Strength.AllowedEcCurves := nil;
  LB := TCompliancePresets.Fips140_3;
  LB.Strength.AllowedEcCurves := nil;
  LRaised := False;
  try
    TComplianceRules.Intersect(LA, LB);
  except
    on EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'an empty result would mean any curve');
end;

procedure TTestComplianceRules.TestIntersectEdDsaIsAnd;
var
  LA, LB: TComplianceRules;
begin
  LA := TCompliancePresets.Fips140_3;
  LB := TCompliancePresets.Fips140_3;
  LA.Strength.AllowEdDsa := True;
  LB.Strength.AllowEdDsa := True;
  CheckTrue(TComplianceRules.Intersect(LA, LB).Strength.AllowEdDsa, 'both allow');
  LB.Strength.AllowEdDsa := False;
  CheckFalse(TComplianceRules.Intersect(LA, LB).Strength.AllowEdDsa, 'B refuses');
  LA.Strength.AllowEdDsa := False;
  LB.Strength.AllowEdDsa := True;
  CheckFalse(TComplianceRules.Intersect(LA, LB).Strength.AllowEdDsa, 'A refuses');
end;

procedure TTestComplianceRules.TestIntersectDeprecatedHashesIsSetIntersection;
var
  LA, LB: TComplianceRules;
begin
  LA := TCompliancePresets.Fips140_3;
  LA.Strength.AllowedDeprecatedHashes := [TCertSignatureHash.Sha1, TCertSignatureHash.Sha224];
  LB := TCompliancePresets.Fips140_3;
  LB.Strength.AllowedDeprecatedHashes := [TCertSignatureHash.Sha1];
  CheckTrue(TComplianceRules.Intersect(LA, LB).Strength.AllowedDeprecatedHashes =
    [TCertSignatureHash.Sha1], 'only the shared hash');
  LB.Strength.AllowedDeprecatedHashes := [];
  CheckTrue(TComplianceRules.Intersect(LA, LB).Strength.AllowedDeprecatedHashes = [],
    'nothing shared with none');
end;

procedure TTestComplianceRules.TestIntersectUnionsRequirements;
var
  LA, LB: TComplianceRules;
begin
  LA := TCompliancePresets.Fips140_3;
  LA.Requirements := [TComplianceRequirement.NoEch];
  LB := TCompliancePresets.Fips140_3;
  LB.Requirements := [TComplianceRequirement.NoKeyLog];
  CheckTrue(TComplianceRules.Intersect(LA, LB).Requirements =
    [TComplianceRequirement.NoEch, TComplianceRequirement.NoKeyLog], 'both requirements kept');
end;

procedure TTestComplianceRules.TestIntersectKdfRequireModuleWinsFromA;
var
  LA, LB: TComplianceRules;
begin
  LA := TCompliancePresets.Fips140_3;
  LA.Kdf := TKdfRule.RequireModule;
  LB := TCompliancePresets.Fips140_3;
  CheckEquals(Ord(TKdfRule.RequireModule), Ord(TComplianceRules.Intersect(LA, LB).Kdf), 'A');
end;

procedure TTestComplianceRules.TestIntersectKdfRequireModuleWinsFromB;
var
  LA, LB: TComplianceRules;
begin
  LA := TCompliancePresets.Fips140_3;
  LB := TCompliancePresets.Fips140_3;
  LB.Kdf := TKdfRule.RequireModule;
  CheckEquals(Ord(TKdfRule.RequireModule), Ord(TComplianceRules.Intersect(LA, LB).Kdf), 'B');
end;

procedure TTestComplianceRules.TestIntersectKdfBothComposedStaysComposed;
begin
  CheckEquals(Ord(TKdfRule.AllowComposed), Ord(TComplianceRules.Intersect(
    TCompliancePresets.Fips140_3, TCompliancePresets.Cnsa1).Kdf), 'neither requires the module');
end;

procedure TTestComplianceRules.TestIntersectKeepsModuleStandard;
begin
  CheckEquals(Ord(TModuleStandard.Fips140_3),
    Ord(TComplianceRules.Intersect(TCompliancePresets.Fips140_3,
    TCompliancePresets.Cnsa1).ModuleStandard), 'standard');
end;

procedure TTestComplianceRules.TestIntersectDoesNotShareArraysWithOperands;
var
  LA, LB, LResult: TComplianceRules;
begin
  LA := TCompliancePresets.Fips140_3;
  LResult := TComplianceRules.Intersect(LA, LA);
  LResult.Strength.AllowedEcCurves[0] := TNamedGroupCatalog.Secp521r1;
  CheckEquals(TNamedGroupCatalog.Secp256r1, LA.Strength.AllowedEcCurves[0],
    'editing the result leaves the operand alone');
  LA.Strength.AllowedEcCurves := nil;
  LB := TCompliancePresets.Fips140_3;
  LResult := TComplianceRules.Intersect(LA, LB);
  LResult.Strength.AllowedEcCurves[0] := TNamedGroupCatalog.Secp521r1;
  CheckEquals(TNamedGroupCatalog.Secp256r1, LB.Strength.AllowedEcCurves[0],
    'the empty-side copy is not aliased either');
end;

procedure TTestComplianceRules.TestSubsetExtraVersion;
var
  LSelf, LOther: TComplianceRules;
begin
  LSelf := TCompliancePresets.Fips140_3;
  LOther := TCompliancePresets.Fips140_3;
  LOther.Versions := TArray<UInt16>.Create(TlsWireVersionTls13);
  CheckFalse(LSelf.IsSubsetOf(LOther), 'TLS 1.2 is outside');
  CheckTrue(LOther.IsSubsetOf(LSelf), 'the narrower side fits');
end;

procedure TTestComplianceRules.TestSubsetExtraCipherSuite;
var
  LSelf, LOther: TComplianceRules;
begin
  LSelf := TCompliancePresets.Fips140_3;
  LOther := TCompliancePresets.Fips140_3;
  LOther.CipherSuites := TArray<UInt16>.Create(TCipherSuites13.Aes128GcmSha256);
  CheckFalse(LSelf.IsSubsetOf(LOther), 'extra suites are outside');
  CheckTrue(LOther.IsSubsetOf(LSelf), 'the narrower side fits');
end;

procedure TTestComplianceRules.TestSubsetExtraNamedGroup;
var
  LSelf, LOther: TComplianceRules;
begin
  LSelf := TCompliancePresets.Fips140_3;
  LOther := TCompliancePresets.Fips140_3;
  LOther.NamedGroups := TArray<UInt16>.Create(TNamedGroupCatalog.Secp256r1);
  CheckFalse(LSelf.IsSubsetOf(LOther), 'extra groups are outside');
  CheckTrue(LOther.IsSubsetOf(LSelf), 'the narrower side fits');
end;

procedure TTestComplianceRules.TestSubsetExtraAead;
var
  LSelf, LOther: TComplianceRules;
begin
  LSelf := TCompliancePresets.Fips140_3;
  LOther := TCompliancePresets.Fips140_3;
  LOther.Aeads := [TAeadAlgorithm.AES_256_GCM];
  CheckFalse(LSelf.IsSubsetOf(LOther), 'AES-128 is outside');
  CheckTrue(LOther.IsSubsetOf(LSelf), 'the narrower side fits');
end;

procedure TTestComplianceRules.TestSubsetExtraScheme;
var
  LSelf, LOther: TComplianceRules;
begin
  LSelf := TCompliancePresets.Fips140_3;
  LOther := TCompliancePresets.Fips140_3;
  Exclude(LOther.SignatureSchemes, TSignatureScheme.RSA_PKCS1_SHA512);
  CheckFalse(LSelf.IsSubsetOf(LOther), 'one extra scheme is outside');
  CheckTrue(LOther.IsSubsetOf(LSelf), 'the narrower side fits');
end;

procedure TTestComplianceRules.TestSubsetMinBitsBoundary;
var
  LSelf, LOther: TComplianceRules;
begin
  LSelf := TCompliancePresets.Fips140_3;
  LOther := TCompliancePresets.Fips140_3;
  CheckTrue(LSelf.IsSubsetOf(LOther), 'equal floors fit');
  LSelf.Strength.MinRsaModulusBits := 2047;
  CheckFalse(LSelf.IsSubsetOf(LOther), 'one bit under the other floor is outside');
  LSelf.Strength.MinRsaModulusBits := 2049;
  CheckTrue(LSelf.IsSubsetOf(LOther), 'a higher floor fits');
end;

procedure TTestComplianceRules.TestSubsetMaxBitsBoundary;
var
  LSelf, LOther: TComplianceRules;
begin
  LSelf := TCompliancePresets.Fips140_3;
  LOther := TCompliancePresets.Fips140_3;
  CheckTrue(LSelf.IsSubsetOf(LOther), 'equal caps fit');
  LSelf.Strength.MaxRsaModulusBits := 4097;
  CheckFalse(LSelf.IsSubsetOf(LOther), 'one bit over the other cap is outside');
  LSelf.Strength.MaxRsaModulusBits := 4095;
  CheckTrue(LSelf.IsSubsetOf(LOther), 'a lower cap fits');
end;

procedure TTestComplianceRules.TestSubsetUncappedSelfAgainstCappedOther;
var
  LSelf: TComplianceRules;
begin
  LSelf := TCompliancePresets.Fips140_3;
  LSelf.Strength.MaxRsaModulusBits := 0;
  CheckFalse(LSelf.IsSubsetOf(TCompliancePresets.Fips140_3), 'no cap is wider than a cap');
end;

procedure TTestComplianceRules.TestSubsetCappedSelfAgainstUncappedOther;
var
  LOther: TComplianceRules;
begin
  LOther := TCompliancePresets.Fips140_3;
  LOther.Strength.MaxRsaModulusBits := 0;
  CheckTrue(TCompliancePresets.Fips140_3.IsSubsetOf(LOther), 'any cap fits under no cap');
end;

procedure TTestComplianceRules.TestSubsetCurvesBoundaries;
var
  LSelf, LOther: TComplianceRules;
begin
  LSelf := TCompliancePresets.Fips140_3;
  LOther := TCompliancePresets.Fips140_3;
  LOther.Strength.AllowedEcCurves := nil;
  CheckTrue(LSelf.IsSubsetOf(LOther), 'any curve on the other side admits a list');
  CheckFalse(LOther.IsSubsetOf(LSelf), 'any curve is wider than a list');
  LOther.Strength.AllowedEcCurves := TArray<UInt16>.Create(TNamedGroupCatalog.Secp256r1,
    TNamedGroupCatalog.Secp384r1);
  CheckFalse(LSelf.IsSubsetOf(LOther), 'a curve the other lacks is outside');
  CheckTrue(LOther.IsSubsetOf(LSelf), 'a shorter list fits');
end;

procedure TTestComplianceRules.TestSubsetEdDsaBoundary;
var
  LSelf, LOther: TComplianceRules;
begin
  LSelf := TCompliancePresets.Fips140_3;
  LOther := TCompliancePresets.Fips140_3;
  LSelf.Strength.AllowEdDsa := True;
  CheckFalse(LSelf.IsSubsetOf(LOther), 'EdDSA the other refuses is outside');
  LOther.Strength.AllowEdDsa := True;
  CheckTrue(LSelf.IsSubsetOf(LOther), 'EdDSA both allow fits');
  LSelf.Strength.AllowEdDsa := False;
  CheckTrue(LSelf.IsSubsetOf(LOther), 'refusing EdDSA fits under allowing it');
end;

procedure TTestComplianceRules.TestSubsetDeprecatedHashesBoundary;
var
  LSelf, LOther: TComplianceRules;
begin
  LSelf := TCompliancePresets.Fips140_3;
  LOther := TCompliancePresets.Fips140_3;
  LSelf.Strength.AllowedDeprecatedHashes := [TCertSignatureHash.Sha1];
  CheckFalse(LSelf.IsSubsetOf(LOther), 'a hash the other refuses is outside');
  LOther.Strength.AllowedDeprecatedHashes := [TCertSignatureHash.Sha1];
  CheckTrue(LSelf.IsSubsetOf(LOther), 'a hash both admit fits');
end;

procedure TTestComplianceRules.TestSubsetMissingRequirement;
var
  LSelf: TComplianceRules;
begin
  LSelf := TCompliancePresets.Fips140_3;
  Exclude(LSelf.Requirements, TComplianceRequirement.NoKeyLog);
  CheckFalse(LSelf.IsSubsetOf(TCompliancePresets.Fips140_3),
    'dropping a requirement leaves the preset');
  CheckTrue(TCompliancePresets.Fips140_3.IsSubsetOf(LSelf), 'keeping more requirements fits');
end;

procedure TTestComplianceRules.TestSubsetKdfBoundary;
var
  LSelf, LOther: TComplianceRules;
begin
  LSelf := TCompliancePresets.Fips140_3;
  LOther := TCompliancePresets.Fips140_3;
  LOther.Kdf := TKdfRule.RequireModule;
  CheckFalse(LSelf.IsSubsetOf(LOther), 'allowing composed is looser than requiring the module');
  CheckTrue(LOther.IsSubsetOf(LSelf), 'requiring the module fits under allowing composed');
end;

procedure TTestComplianceRules.TestSubsetOfItself;
var
  LNamed: TArray<TCompliancePreset>;
  LI: Int32;
begin
  LNamed := TCompliancePresets.Named;
  CheckEquals(2, System.Length(LNamed), 'not vacuous');
  for LI := 0 to System.Length(LNamed) - 1 do
    CheckTrue(LNamed[LI].Rules.IsSubsetOf(LNamed[LI].Rules), LNamed[LI].Name);
end;

procedure TTestComplianceRules.TestEqualIgnoresOrder;
var
  LShuffled: TComplianceRules;
begin
  LShuffled := TCompliancePresets.Fips140_3;
  LShuffled.Versions := TArray<UInt16>.Create(TlsWireVersionTls12, TlsWireVersionTls13);
  LShuffled.CipherSuites := TArray<UInt16>.Create(TCipherSuites12.EcdheRsaAes256GcmSha384,
    TCipherSuites13.Aes128GcmSha256, TCipherSuites13.Aes256GcmSha384,
    TCipherSuites12.EcdheEcdsaAes128GcmSha256, TCipherSuites12.EcdheEcdsaAes256GcmSha384,
    TCipherSuites12.EcdheRsaAes128GcmSha256);
  LShuffled.NamedGroups := TArray<UInt16>.Create(TNamedGroupCatalog.Secp521r1,
    TNamedGroupCatalog.Secp256r1, TNamedGroupCatalog.Secp384r1);
  LShuffled.Strength.AllowedEcCurves := TArray<UInt16>.Create(TNamedGroupCatalog.Secp384r1,
    TNamedGroupCatalog.Secp521r1, TNamedGroupCatalog.Secp256r1);
  CheckTrue(LShuffled = TCompliancePresets.Fips140_3, 'same members in another order');
end;

procedure TTestComplianceRules.TestEqualDetectsDifferentRules;
begin
  CheckFalse(TCompliancePresets.Fips140_3 = TCompliancePresets.Cnsa1,
    'Fips140_3 and Cnsa1 differ');
  CheckFalse(TCompliancePresets.Cnsa1 = TCompliancePresets.Fips140_3,
    'and in the other direction');
end;

procedure TTestComplianceRules.TestEqualDetectsDifferentRequirements;
var
  LLoose: TComplianceRules;
begin
  LLoose := TCompliancePresets.Fips140_3;
  Exclude(LLoose.Requirements, TComplianceRequirement.NoEch);
  CheckFalse(LLoose = TCompliancePresets.Fips140_3, 'a missing requirement is a difference');
end;

procedure TTestComplianceRules.TestCloneEqualsOriginal;
begin
  CheckTrue(TCompliancePresets.Fips140_3.Clone = TCompliancePresets.Fips140_3,
    'a clone is the same rules');
end;

procedure TTestComplianceRules.TestCloneDoesNotShareVersions;
var
  LOriginal, LClone: TComplianceRules;
begin
  LOriginal := TCompliancePresets.Fips140_3;
  LClone := LOriginal.Clone;
  LClone.Versions[0] := TlsWireVersionTls12;
  CheckEquals(TlsWireVersionTls13, LOriginal.Versions[0], 'original untouched');
end;

procedure TTestComplianceRules.TestCloneDoesNotShareCipherSuites;
var
  LOriginal, LClone: TComplianceRules;
begin
  LOriginal := TCompliancePresets.Fips140_3;
  LClone := LOriginal.Clone;
  LClone.CipherSuites[0] := TCipherSuites13.Aes256GcmSha384;
  CheckEquals(TCipherSuites13.Aes128GcmSha256, LOriginal.CipherSuites[0], 'original untouched');
end;

procedure TTestComplianceRules.TestCloneDoesNotShareNamedGroups;
var
  LOriginal, LClone: TComplianceRules;
begin
  LOriginal := TCompliancePresets.Fips140_3;
  LClone := LOriginal.Clone;
  LClone.NamedGroups[0] := TNamedGroupCatalog.Secp521r1;
  CheckEquals(TNamedGroupCatalog.Secp256r1, LOriginal.NamedGroups[0], 'original untouched');
end;

procedure TTestComplianceRules.TestCloneDoesNotShareCurves;
var
  LOriginal, LClone: TComplianceRules;
begin
  LOriginal := TCompliancePresets.Fips140_3;
  LClone := LOriginal.Clone;
  LClone.Strength.AllowedEcCurves[0] := TNamedGroupCatalog.Secp521r1;
  CheckEquals(TNamedGroupCatalog.Secp256r1, LOriginal.Strength.AllowedEcCurves[0],
    'original untouched');
end;

procedure TTestComplianceRules.TestDescribeCnsa1ListsEveryField;
const
  Expected =
    'Versions: 0x0304 0x0303' + sLineBreak +
    'CipherSuites: TLS_AES_256_GCM_SHA384 TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 ' +
    'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384' + sLineBreak +
    'Aeads: AES_256_GCM' + sLineBreak +
    'NamedGroups: secp384r1' + sLineBreak +
    'SignatureSchemes: ECDSA_SECP384R1_SHA384 RSA_PSS_RSAE_SHA384 RSA_PKCS1_SHA384' +
    sLineBreak +
    'Strength: RsaBits 3072..4096, RsaSizes: 3072 4096, EdDsa=no, AnchorFloors=yes, ' +
    'DeprecatedHashes:, curves: secp384r1' + sLineBreak +
    'Requirements: ExtendedMasterSecret NoEarlyData NoEch NoExternalPsk NoTls12Psk NoKeyLog ' +
    'NoDangerousTrust InModuleChainVerification' + sLineBreak +
    'Kdf: AllowComposed' + sLineBreak +
    'ModuleStandard: Fips140_3';
begin
  CheckEquals(Expected, TCompliancePresets.Cnsa1.Describe, 'Cnsa1 description');
end;

procedure TTestComplianceRules.TestDescribeNamesGroupsInOrder;
begin
  CheckTrue(Pos('NamedGroups: secp256r1 secp384r1 secp521r1',
    TCompliancePresets.Fips140_3.Describe) > 0, 'the groups line');
end;

procedure TTestComplianceRules.TestDescribeListsDeprecatedHashes;
var
  LRules: TComplianceRules;
begin
  LRules := TCompliancePresets.Fips140_3;
  LRules.Strength.AllowedDeprecatedHashes := [TCertSignatureHash.Sha1, TCertSignatureHash.Sha224];
  CheckTrue(Pos('DeprecatedHashes: Sha1 Sha224, curves:', LRules.Describe) > 0,
    'the admitted hashes in enum order');
end;

procedure TTestComplianceRules.TestDescribeListsRsaSizes;
begin
  CheckTrue(Pos('RsaSizes: 2048 3072 4096, EdDsa=no', TCompliancePresets.Fips140_3.Describe) > 0,
    'the exact sizes');
end;

procedure TTestComplianceRules.TestIntersectMinAboveMaxRaises;
var
  LA, LB: TComplianceRules;
  LRaised: Boolean;
begin
  LA := TCompliancePresets.Fips140_3;
  LA.Strength.MinRsaModulusBits := 4096;
  LB := TCompliancePresets.Fips140_3;
  LB.Strength.MaxRsaModulusBits := 3072;
  LRaised := False;
  try
    TComplianceRules.Intersect(LA, LB);
  except
    on EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a floor above the cap holds no modulus');
end;

procedure TTestComplianceRules.TestIntersectMinEqualMaxIsKept;
var
  LA, LB: TComplianceRules;
  LResult: TComplianceRules;
begin
  LA := TCompliancePresets.Fips140_3;
  LA.Strength.MinRsaModulusBits := 3072;
  LB := TCompliancePresets.Fips140_3;
  LB.Strength.MaxRsaModulusBits := 3072;
  LResult := TComplianceRules.Intersect(LA, LB);
  CheckEquals(3072, LResult.Strength.MinRsaModulusBits, 'floor');
  CheckEquals(3072, LResult.Strength.MaxRsaModulusBits, 'cap');
end;

procedure TTestComplianceRules.TestIntersectRsaSizesIntersectInAOrder;
var
  LA, LB: TComplianceRules;
  LResult: TComplianceRules;
begin
  LA := TCompliancePresets.Fips140_3;
  LA.RsaModulusBits := TArray<UInt32>.Create(4096, 2048, 3072);
  LB := TCompliancePresets.Fips140_3;
  LB.RsaModulusBits := TArray<UInt32>.Create(3072, 4096);
  LResult := TComplianceRules.Intersect(LA, LB);
  CheckEquals(2, System.Length(LResult.RsaModulusBits), 'count');
  CheckEquals(4096, Int32(LResult.RsaModulusBits[0]), 'A order first');
  CheckEquals(3072, Int32(LResult.RsaModulusBits[1]), 'A order second');
end;

procedure TTestComplianceRules.TestIntersectRsaSizesEmptyAUsesB;
var
  LA, LB: TComplianceRules;
  LResult: TComplianceRules;
begin
  LA := TCompliancePresets.Fips140_3;
  LA.RsaModulusBits := nil;
  LB := TCompliancePresets.Cnsa1;
  LResult := TComplianceRules.Intersect(LA, LB);
  CheckEquals(2, System.Length(LResult.RsaModulusBits), 'count');
  CheckEquals(3072, Int32(LResult.RsaModulusBits[0]), 'first');
end;

procedure TTestComplianceRules.TestIntersectRsaSizesEmptyBUsesA;
var
  LA, LB: TComplianceRules;
  LResult: TComplianceRules;
begin
  LA := TCompliancePresets.Cnsa1;
  LB := TCompliancePresets.Fips140_3;
  LB.RsaModulusBits := nil;
  LResult := TComplianceRules.Intersect(LA, LB);
  CheckEquals(2, System.Length(LResult.RsaModulusBits), 'count');
  CheckEquals(4096, Int32(LResult.RsaModulusBits[1]), 'second');
end;

procedure TTestComplianceRules.TestIntersectRsaSizesBothEmptyStaysEmpty;
var
  LA, LB: TComplianceRules;
begin
  LA := TCompliancePresets.Fips140_3;
  LA.RsaModulusBits := nil;
  LB := TCompliancePresets.Fips140_3;
  LB.RsaModulusBits := nil;
  CheckEquals(0, System.Length(TComplianceRules.Intersect(LA, LB).RsaModulusBits),
    'the range alone');
end;

procedure TTestComplianceRules.TestIntersectDisjointRsaSizesRaises;
var
  LA, LB: TComplianceRules;
  LRaised: Boolean;
begin
  LA := TCompliancePresets.Fips140_3;
  LA.RsaModulusBits := TArray<UInt32>.Create(2048);
  LB := TCompliancePresets.Fips140_3;
  LB.RsaModulusBits := TArray<UInt32>.Create(3072);
  LRaised := False;
  try
    TComplianceRules.Intersect(LA, LB);
  except
    on EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'an empty result would mean the range alone');
end;

procedure TTestComplianceRules.TestIntersectRsaSizesAreCutToTheRange;
var
  LA, LB, LResult: TComplianceRules;
begin
  LA := TCompliancePresets.Fips140_3;
  LB := TCompliancePresets.Cnsa1;
  LB.RsaModulusBits := nil;
  LResult := TComplianceRules.Intersect(LA, LB);
  CheckEquals(2, System.Length(LResult.RsaModulusBits), 'the size under the floor is dropped');
  CheckEquals(3072, Int32(LResult.RsaModulusBits[0]), 'first kept size');
  CheckEquals(4096, Int32(LResult.RsaModulusBits[1]), 'second kept size');
end;

procedure TTestComplianceRules.TestIntersectRsaSizesOutsideTheRangeRaise;
var
  LA, LB: TComplianceRules;
  LRaised: Boolean;
begin
  LA := TCompliancePresets.Fips140_3;
  LA.RsaModulusBits := TArray<UInt32>.Create(2048);
  LB := TCompliancePresets.Cnsa1;
  LB.RsaModulusBits := nil;
  LRaised := False;
  try
    TComplianceRules.Intersect(LA, LB);
  except
    on EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a listed size below the floor leaves no size');
end;

procedure TTestComplianceRules.TestIntersectRsaSizesAreNotAliased;
var
  LA, LB, LResult: TComplianceRules;
begin
  LA := TCompliancePresets.Fips140_3;
  LA.RsaModulusBits := nil;
  LB := TCompliancePresets.Fips140_3;
  LResult := TComplianceRules.Intersect(LA, LB);
  LResult.RsaModulusBits[0] := 1;
  CheckEquals(2048, Int32(LB.RsaModulusBits[0]), 'the empty-A copy is not aliased');
  LResult := TComplianceRules.Intersect(LB, LA);
  LResult.RsaModulusBits[0] := 1;
  CheckEquals(2048, Int32(LB.RsaModulusBits[0]), 'the empty-B copy is not aliased');
end;

procedure TTestComplianceRules.TestIntersectCurvesEmptyBIsNotAliased;
var
  LA, LB, LResult: TComplianceRules;
begin
  LA := TCompliancePresets.Fips140_3;
  LB := TCompliancePresets.Fips140_3;
  LB.Strength.AllowedEcCurves := nil;
  LResult := TComplianceRules.Intersect(LA, LB);
  LResult.Strength.AllowedEcCurves[0] := TNamedGroupCatalog.Secp521r1;
  CheckEquals(TNamedGroupCatalog.Secp256r1, LA.Strength.AllowedEcCurves[0],
    'the empty-B copy is not aliased');
end;

procedure TTestComplianceRules.TestIntersectNoncomparableAeads;
var
  LA, LB, LResult: TComplianceRules;
begin
  LA := TCompliancePresets.Fips140_3;
  LA.Aeads := [TAeadAlgorithm.AES_128_GCM];
  LB := TCompliancePresets.Fips140_3;
  LB.Aeads := [TAeadAlgorithm.AES_256_GCM];
  CheckFalse(LA.IsSubsetOf(LB), 'A is not inside B');
  CheckFalse(LB.IsSubsetOf(LA), 'B is not inside A');
  LResult := TComplianceRules.Intersect(LA, LB);
  CheckTrue(LResult.IsSubsetOf(LA), 'inside A');
  CheckTrue(LResult.IsSubsetOf(LB), 'inside B');
  CheckFalse(LResult = LA, 'strictly narrower than A');
  CheckFalse(LResult = LB, 'strictly narrower than B');
  CheckTrue(LResult.Aeads = [], 'nothing shared');
end;

procedure TTestComplianceRules.TestIntersectNoncomparableEdDsaAndHashes;
var
  LA, LB, LResult: TComplianceRules;
begin
  LA := TCompliancePresets.Fips140_3;
  LA.Strength.AllowEdDsa := True;
  LB := TCompliancePresets.Fips140_3;
  LB.Strength.AllowedDeprecatedHashes := [TCertSignatureHash.Sha1];
  CheckFalse(LA.IsSubsetOf(LB), 'A admits EdDSA, B does not');
  CheckFalse(LB.IsSubsetOf(LA), 'B admits SHA-1, A does not');
  LResult := TComplianceRules.Intersect(LA, LB);
  CheckTrue(LResult.IsSubsetOf(LA), 'inside A');
  CheckTrue(LResult.IsSubsetOf(LB), 'inside B');
  CheckFalse(LResult.Strength.AllowEdDsa, 'EdDSA only where both allow');
  CheckTrue(LResult.Strength.AllowedDeprecatedHashes = [], 'SHA-1 only where both admit');
end;

procedure TTestComplianceRules.TestSubsetRsaSizesBoundaries;
var
  LSelf, LOther: TComplianceRules;
begin
  LSelf := TCompliancePresets.Fips140_3;
  LOther := TCompliancePresets.Fips140_3;
  CheckTrue(LSelf.IsSubsetOf(LOther), 'equal sizes fit');
  LOther.RsaModulusBits := nil;
  CheckTrue(LSelf.IsSubsetOf(LOther), 'no sizes on the other side admit a list');
  CheckTrue(LOther.IsSubsetOf(LOther), 'both without sizes fit');
  LSelf.RsaModulusBits := nil;
  LOther := TCompliancePresets.Fips140_3;
  CheckFalse(LSelf.IsSubsetOf(LOther), 'the range alone is wider than a list');
  LSelf.RsaModulusBits := TArray<UInt32>.Create(2048, 3072, 4096, 8192);
  CheckFalse(LSelf.IsSubsetOf(LOther), 'a size the other lacks is outside');
  LSelf.RsaModulusBits := TArray<UInt32>.Create(4096, 3072);
  CheckTrue(LSelf.IsSubsetOf(LOther), 'a shorter list in any order fits');
end;

procedure TTestComplianceRules.TestSubsetKdfBothRequireModule;
var
  LSelf, LOther: TComplianceRules;
begin
  LSelf := TCompliancePresets.Fips140_3;
  LSelf.Kdf := TKdfRule.RequireModule;
  LOther := TCompliancePresets.Fips140_3;
  LOther.Kdf := TKdfRule.RequireModule;
  CheckTrue(LSelf.IsSubsetOf(LOther), 'equal rules fit');
end;

procedure TTestComplianceRules.TestSubsetKdfBothComposed;
var
  LSelf, LOther: TComplianceRules;
begin
  LSelf := TCompliancePresets.Fips140_3;
  LOther := TCompliancePresets.Fips140_3;
  CheckEquals(Ord(TKdfRule.AllowComposed), Ord(LSelf.Kdf), 'precondition');
  CheckTrue(LSelf.IsSubsetOf(LOther), 'equal rules fit');
end;

procedure TTestComplianceRules.TestSubsetBothCurveListsEmpty;
var
  LSelf, LOther: TComplianceRules;
begin
  LSelf := TCompliancePresets.Fips140_3;
  LSelf.Strength.AllowedEcCurves := nil;
  LOther := TCompliancePresets.Fips140_3;
  LOther.Strength.AllowedEcCurves := nil;
  CheckTrue(LSelf.IsSubsetOf(LOther), 'any curve fits under any curve');
end;

procedure TTestComplianceRules.TestCloneDoesNotShareRsaSizes;
var
  LOriginal, LClone: TComplianceRules;
begin
  LOriginal := TCompliancePresets.Fips140_3;
  LClone := LOriginal.Clone;
  LClone.RsaModulusBits[0] := 1;
  CheckEquals(2048, Int32(LOriginal.RsaModulusBits[0]), 'original untouched');
end;

procedure TTestComplianceRules.TestIntersectAnchorKeyFloorsFromAWins;
var
  LA, LB: TComplianceRules;
begin
  LA := TCompliancePresets.Fips140_3;
  LB := TCompliancePresets.Fips140_3;
  LB.Strength.AnchorKeyFloors := False;
  CheckTrue(TComplianceRules.Intersect(LA, LB).Strength.AnchorKeyFloors,
    'narrowing only ever adds the flag');
end;

procedure TTestComplianceRules.TestIntersectAnchorKeyFloorsFromBWins;
var
  LA, LB: TComplianceRules;
begin
  LA := TCompliancePresets.Fips140_3;
  LA.Strength.AnchorKeyFloors := False;
  LB := TCompliancePresets.Fips140_3;
  CheckTrue(TComplianceRules.Intersect(LA, LB).Strength.AnchorKeyFloors,
    'in either operand');
end;

procedure TTestComplianceRules.TestIntersectAnchorKeyFloorsBothOffStaysOff;
var
  LA, LB: TComplianceRules;
begin
  LA := TCompliancePresets.Fips140_3;
  LA.Strength.AnchorKeyFloors := False;
  LB := LA.Clone;
  CheckFalse(TComplianceRules.Intersect(LA, LB).Strength.AnchorKeyFloors,
    'the flag is not invented');
end;

procedure TTestComplianceRules.TestSubsetWithoutAnchorKeyFloorsIsNotWithinAPresetThatHasThem;
var
  LRules: TComplianceRules;
begin
  LRules := TCompliancePresets.Fips140_3;
  LRules.Strength.AnchorKeyFloors := False;
  CheckFalse(LRules.IsSubsetOf(TCompliancePresets.Fips140_3),
    'rules that exempt anchors are looser than a preset that holds them');
end;

procedure TTestComplianceRules.TestSubsetWithAnchorKeyFloorsIsWithinRulesThatLackThem;
var
  LLoose: TComplianceRules;
begin
  LLoose := TCompliancePresets.Fips140_3;
  LLoose.Strength.AnchorKeyFloors := False;
  CheckTrue(TCompliancePresets.Fips140_3.IsSubsetOf(LLoose), 'holding anchors is stricter');
end;

procedure TTestComplianceRules.TestEqualDetectsDifferentAnchorKeyFloors;
var
  LRules: TComplianceRules;
begin
  LRules := TCompliancePresets.Fips140_3;
  LRules.Strength.AnchorKeyFloors := False;
  CheckFalse(LRules = TCompliancePresets.Fips140_3, 'the flag counts');
end;

{ TTestComplianceCatalog }

procedure TTestComplianceCatalog.TestTryKeyAgreementRejectsHybridAndKem;
var
  LAlgorithm: TKeyAgreementAlgorithm;
begin
  CheckFalse(TComplianceCatalog.TryKeyAgreement(TNamedGroupCatalog.SecP256r1MlKem768,
    LAlgorithm), 'hybrid');
  CheckFalse(TComplianceCatalog.TryKeyAgreement(TNamedGroupCatalog.MlKem768, LAlgorithm),
    'pure KEM');
  CheckFalse(TComplianceCatalog.TryKeyAgreement(0, LAlgorithm), 'zero');
end;

procedure TTestComplianceCatalog.TestKeyAgreementsFips140_3;
begin
  CheckTrue(TComplianceCatalog.KeyAgreements(TCompliancePresets.Fips140_3) =
    [TKeyAgreementAlgorithm.SECP256R1, TKeyAgreementAlgorithm.SECP384R1,
    TKeyAgreementAlgorithm.SECP521R1], 'the three NIST curves, no X25519');
end;

procedure TTestComplianceCatalog.TestKeyAgreementsCnsa1;
begin
  CheckTrue(TComplianceCatalog.KeyAgreements(TCompliancePresets.Cnsa1) =
    [TKeyAgreementAlgorithm.SECP384R1], 'P-384 only');
end;

procedure TTestComplianceCatalog.TestKeyAgreementsIncludesX25519Group;
var
  LRules: TComplianceRules;
begin
  LRules := TCompliancePresets.Cnsa1;
  LRules.NamedGroups := TArray<UInt16>.Create(TNamedGroupCatalog.X25519);
  CheckTrue(TComplianceCatalog.KeyAgreements(LRules) = [TKeyAgreementAlgorithm.X25519],
    'a listed X25519 group is called for');
end;

procedure TTestComplianceCatalog.TestKeyAgreementsIgnoreNonClassicalGroup;
var
  LRules: TComplianceRules;
begin
  LRules := TCompliancePresets.Cnsa1;
  LRules.NamedGroups := TArray<UInt16>.Create(TNamedGroupCatalog.SecP256r1MlKem768);
  CheckTrue(TComplianceCatalog.KeyAgreements(LRules) = [], 'a hybrid code calls for nothing');
end;

procedure TTestComplianceCatalog.TestIsSubsetOfListBoundaries;
begin
  CheckTrue(TComplianceCatalog.IsSubsetOfList(nil, nil), 'empty in empty');
  CheckTrue(TComplianceCatalog.IsSubsetOfList(nil, TArray<UInt16>.Create(1)), 'empty in any');
  CheckTrue(TComplianceCatalog.IsSubsetOfList(TArray<UInt16>.Create(2, 1),
    TArray<UInt16>.Create(1, 2)), 'order does not count');
  CheckFalse(TComplianceCatalog.IsSubsetOfList(TArray<UInt16>.Create(1, 3),
    TArray<UInt16>.Create(1, 2)), 'a missing last entry');
  CheckFalse(TComplianceCatalog.IsSubsetOfList(TArray<UInt16>.Create(3, 1),
    TArray<UInt16>.Create(1, 2)), 'a missing first entry');
  CheckFalse(TComplianceCatalog.IsSubsetOfList(TArray<UInt16>.Create(1), nil),
    'nothing holds an entry');
end;

procedure TTestComplianceCatalog.TestSchemesInEnumOrder;
var
  LSchemes: TArray<TSignatureScheme>;
begin
  LSchemes := TComplianceCatalog.Schemes([TSignatureScheme.RSA_PKCS1_SHA384,
    TSignatureScheme.ECDSA_SECP256R1_SHA256, TSignatureScheme.RSA_PSS_RSAE_SHA256]);
  CheckEquals(3, System.Length(LSchemes), 'count');
  CheckEquals(Ord(TSignatureScheme.ECDSA_SECP256R1_SHA256), Ord(LSchemes[0]), 'first');
  CheckEquals(Ord(TSignatureScheme.RSA_PSS_RSAE_SHA256), Ord(LSchemes[1]), 'second');
  CheckEquals(Ord(TSignatureScheme.RSA_PKCS1_SHA384), Ord(LSchemes[2]), 'third');
end;

procedure TTestComplianceCatalog.TestSchemesEmptySet;
begin
  CheckEquals(0, System.Length(TComplianceCatalog.Schemes([])), 'nothing');
end;

procedure TTestComplianceCatalog.TestRsaSizesWithinBoundaries;
begin
  CheckTrue(TComplianceCatalog.RsaSizesWithin(nil, nil), 'empty in empty');
  CheckTrue(TComplianceCatalog.RsaSizesWithin(TArray<UInt32>.Create(1), nil),
    'any list under no list');
  CheckFalse(TComplianceCatalog.RsaSizesWithin(nil, TArray<UInt32>.Create(1)),
    'no list is wider than a list');
  CheckTrue(TComplianceCatalog.RsaSizesWithin(TArray<UInt32>.Create(2, 1),
    TArray<UInt32>.Create(1, 2)), 'order does not count');
  CheckFalse(TComplianceCatalog.RsaSizesWithin(TArray<UInt32>.Create(1, 3),
    TArray<UInt32>.Create(1, 2)), 'a missing last entry');
  CheckFalse(TComplianceCatalog.RsaSizesWithin(TArray<UInt32>.Create(3, 1),
    TArray<UInt32>.Create(1, 2)), 'a missing first entry');
end;

procedure TTestComplianceCatalog.TestKeyMeetsRsaExactSizesListed;
var
  LFacts: TCertKeyFacts;
  LRules: TComplianceRules;
begin
  LRules := TCompliancePresets.Cnsa1;
  LFacts := Default(TCertKeyFacts);
  LFacts.Kind := TSignatureKeyKind.Rsa;
  LFacts.Bits := 3072;
  CheckTrue(TComplianceCatalog.KeyMeets(LFacts, LRules.Strength, LRules.RsaModulusBits),
    '3072 is listed');
  LFacts.Bits := 4096;
  CheckTrue(TComplianceCatalog.KeyMeets(LFacts, LRules.Strength, LRules.RsaModulusBits),
    '4096 is listed');
  LRules := TCompliancePresets.Fips140_3;
  LFacts.Bits := 2048;
  CheckTrue(TComplianceCatalog.KeyMeets(LFacts, LRules.Strength, LRules.RsaModulusBits),
    '2048 is listed for Fips140_3');
end;

procedure TTestComplianceCatalog.TestKeyMeetsRsaExactSizesRefuseOthers;
var
  LFacts: TCertKeyFacts;
  LRules: TComplianceRules;
begin
  LRules := TCompliancePresets.Cnsa1;
  LFacts := Default(TCertKeyFacts);
  LFacts.Kind := TSignatureKeyKind.Rsa;
  LFacts.Bits := 3200;
  CheckFalse(TComplianceCatalog.KeyMeets(LFacts, LRules.Strength, LRules.RsaModulusBits),
    '3200 is inside the range but not listed');
  LFacts.Bits := 3584;
  CheckFalse(TComplianceCatalog.KeyMeets(LFacts, LRules.Strength, LRules.RsaModulusBits),
    '3584 is inside the range but not listed');
  LRules := TCompliancePresets.Fips140_3;
  LFacts.Bits := 2560;
  CheckFalse(TComplianceCatalog.KeyMeets(LFacts, LRules.Strength, LRules.RsaModulusBits),
    '2560 is inside the range but not listed');
  CheckTrue(TComplianceCatalog.KeyMeets(LFacts, LRules.Strength, nil),
    'the range alone admits 2560');
end;

procedure TTestComplianceCatalog.TestKeyMeetsRsaExactSizesStillHonourRange;
var
  LFacts: TCertKeyFacts;
  LRules: TComplianceRules;
begin
  LRules := TCompliancePresets.Fips140_3;
  LFacts := Default(TCertKeyFacts);
  LFacts.Kind := TSignatureKeyKind.Rsa;
  LFacts.Bits := 4097;
  CheckFalse(TComplianceCatalog.KeyMeets(LFacts, LRules.Strength, LRules.RsaModulusBits),
    '4097 is over the cap');
  LFacts.Bits := 8192;
  CheckFalse(TComplianceCatalog.KeyMeets(LFacts, LRules.Strength, LRules.RsaModulusBits),
    '8192 is over the cap');
  LRules.RsaModulusBits := TArray<UInt32>.Create(1024, 4096);
  LFacts.Bits := 1024;
  CheckFalse(TComplianceCatalog.KeyMeets(LFacts, LRules.Strength, LRules.RsaModulusBits),
    'a listed size under the floor is still refused');
end;

procedure TTestComplianceCatalog.TestKeyMeetsRsaExactSizesRefuseZeroBits;
var
  LFacts: TCertKeyFacts;
  LStrength: TCertificateStrengthPolicy;
begin
  LStrength := TCompliancePresets.Fips140_3.Strength;
  LStrength.MinRsaModulusBits := 0;
  LFacts := Default(TCertKeyFacts);
  LFacts.Kind := TSignatureKeyKind.Rsa;
  LFacts.Bits := 0;
  CheckFalse(TComplianceCatalog.KeyMeets(LFacts, LStrength, TArray<UInt32>.Create(0)),
    'an unreadable modulus is never listed');
end;

procedure TTestComplianceCatalog.TestKeyMeetsExactSizesLeaveEcdsaAlone;
var
  LFacts: TCertKeyFacts;
  LRules: TComplianceRules;
begin
  LRules := TCompliancePresets.Cnsa1;
  LFacts := Default(TCertKeyFacts);
  LFacts.Kind := TSignatureKeyKind.Ecdsa;
  LFacts.EcNamedGroup := TNamedGroupCatalog.Secp384r1;
  CheckTrue(TComplianceCatalog.KeyMeets(LFacts, LRules.Strength, LRules.RsaModulusBits),
    'the RSA sizes do not apply to a curve key');
end;

procedure TTestComplianceCatalog.TestSignatureMeetsFollowsTheSchemeHashes;
begin
  CheckTrue(TComplianceCatalog.SignatureMeets(TCertSignatureFamily.Ecdsa,
    TCertSignatureHash.Sha256, False, False, TCompliancePresets.Fips140_3),
    'SHA-256 under Fips140_3');
  CheckTrue(TComplianceCatalog.SignatureMeets(TCertSignatureFamily.Ecdsa,
    TCertSignatureHash.Sha384, False, False, TCompliancePresets.Fips140_3),
    'SHA-384 under Fips140_3');
  CheckTrue(TComplianceCatalog.SignatureMeets(TCertSignatureFamily.Ecdsa,
    TCertSignatureHash.Sha512, False, False, TCompliancePresets.Fips140_3),
    'SHA-512 under Fips140_3');
  CheckTrue(TComplianceCatalog.SignatureMeets(TCertSignatureFamily.Ecdsa,
    TCertSignatureHash.Sha384, False, False, TCompliancePresets.Cnsa1), 'SHA-384 under Cnsa1');
  CheckFalse(TComplianceCatalog.SignatureMeets(TCertSignatureFamily.Ecdsa,
    TCertSignatureHash.Sha256, False, False, TCompliancePresets.Cnsa1), 'SHA-256 under Cnsa1');
  CheckFalse(TComplianceCatalog.SignatureMeets(TCertSignatureFamily.Ecdsa,
    TCertSignatureHash.Sha512, False, False, TCompliancePresets.Cnsa1), 'SHA-512 under Cnsa1');
end;

procedure TTestComplianceCatalog.TestSignatureMeetsRefusesTheHashesNoSchemeUses;
const
  Refused: array [0 .. 3] of TCertSignatureHash = (TCertSignatureHash.Md5,
    TCertSignatureHash.Sha1, TCertSignatureHash.Sha224, TCertSignatureHash.Sha3);
var
  LI: Int32;
begin
  for LI := Low(Refused) to High(Refused) do
    CheckFalse(TComplianceCatalog.SignatureMeets(TCertSignatureFamily.RsaPkcs1, Refused[LI],
      False, False, TCompliancePresets.Fips140_3), TEnumUtilities.GetName(TypeInfo(TCertSignatureHash),
      Ord(Refused[LI])));
end;

procedure TTestComplianceCatalog.TestSignatureMeetsAdmitsADeprecatedHashTheStrengthAdmits;
var
  LRules: TComplianceRules;
begin
  LRules := TCompliancePresets.Fips140_3;
  LRules.Strength.AllowedDeprecatedHashes := [TCertSignatureHash.Sha1];
  CheckTrue(TComplianceCatalog.SignatureMeets(TCertSignatureFamily.RsaPkcs1,
    TCertSignatureHash.Sha1, False, False, LRules), 'admitted');
  CheckFalse(TComplianceCatalog.SignatureMeets(TCertSignatureFamily.RsaPkcs1,
    TCertSignatureHash.Md5, False, False, LRules), 'only the hash that was admitted');
end;

procedure TTestComplianceCatalog.TestSignatureMeetsFollowsTheEdDsaFlagForAnImplicitHash;
var
  LRules: TComplianceRules;
begin
  LRules := TCompliancePresets.Fips140_3;
  CheckFalse(TComplianceCatalog.SignatureMeets(TCertSignatureFamily.Ed25519,
    TCertSignatureHash.Implicit, False, False, LRules), 'EdDSA is off in the presets');
  LRules.Strength.AllowEdDsa := True;
  LRules.SignatureSchemes := LRules.SignatureSchemes + [TSignatureScheme.ED25519];
  CheckTrue(TComplianceCatalog.SignatureMeets(TCertSignatureFamily.Ed25519,
    TCertSignatureHash.Implicit, False, False, LRules),
    'and on when the strength policy admits it');
  LRules.Strength.AllowEdDsa := False;
  CheckFalse(TComplianceCatalog.SignatureMeets(TCertSignatureFamily.Ed25519,
    TCertSignatureHash.Implicit, False, False, LRules), 'the scheme alone is not the admission');
end;

procedure TTestComplianceCatalog.TestSignatureMeetsNeedsTheEdDsaSchemeInTheRules;
var
  LRules: TComplianceRules;
begin
  LRules := TCompliancePresets.Fips140_3;
  LRules.Strength.AllowEdDsa := True;
  CheckFalse(TComplianceCatalog.SignatureMeets(TCertSignatureFamily.Ed25519,
    TCertSignatureHash.Implicit, False, False, LRules), 'Ed25519 with no EdDSA scheme listed');
  CheckFalse(TComplianceCatalog.SignatureMeets(TCertSignatureFamily.Ed448,
    TCertSignatureHash.Implicit, False, False, LRules), 'Ed448 with no EdDSA scheme listed');
  LRules.SignatureSchemes := LRules.SignatureSchemes + [TSignatureScheme.ED25519];
  CheckTrue(TComplianceCatalog.SignatureMeets(TCertSignatureFamily.Ed25519,
    TCertSignatureHash.Implicit, False, False, LRules), 'Ed25519 with its scheme');
  CheckFalse(TComplianceCatalog.SignatureMeets(TCertSignatureFamily.Ed448,
    TCertSignatureHash.Implicit, False, False, LRules), 'Ed448 needs its own scheme');
  LRules.SignatureSchemes := LRules.SignatureSchemes + [TSignatureScheme.ED448];
  CheckTrue(TComplianceCatalog.SignatureMeets(TCertSignatureFamily.Ed448,
    TCertSignatureHash.Implicit, False, False, LRules), 'Ed448 with its scheme');
end;

procedure TTestComplianceCatalog.TestSignatureMeetsAdmitsOnlyHashesTheCoreDeprecates;
var
  LRules: TComplianceRules;
begin
  LRules := TCompliancePresets.Fips140_3;
  LRules.SignatureSchemes := [TSignatureScheme.RSA_PKCS1_SHA384];
  LRules.Strength.AllowedDeprecatedHashes := [TCertSignatureHash.Sha256, TCertSignatureHash.Md5];
  CheckFalse(TComplianceCatalog.SignatureMeets(TCertSignatureFamily.RsaPkcs1,
    TCertSignatureHash.Sha256, False, False, LRules), 'a current hash is not admitted as deprecated');
  CheckFalse(TComplianceCatalog.SignatureMeets(TCertSignatureFamily.RsaPkcs1,
    TCertSignatureHash.Md5, False, False, LRules), 'a forbidden hash is never admitted');
end;

procedure TTestComplianceCatalog.TestSignatureMeetsRefusesAFamilyTheSchemesDoNotName;
var
  LRules: TComplianceRules;
begin
  LRules := TCompliancePresets.Fips140_3;
  LRules.SignatureSchemes := [TSignatureScheme.ECDSA_SECP256R1_SHA256,
    TSignatureScheme.ECDSA_SECP384R1_SHA384];
  CheckTrue(TComplianceCatalog.SignatureMeets(TCertSignatureFamily.Ecdsa,
    TCertSignatureHash.Sha384, False, False, LRules), 'ECDSA with SHA-384 is listed');
  CheckFalse(TComplianceCatalog.SignatureMeets(TCertSignatureFamily.RsaPkcs1,
    TCertSignatureHash.Sha384, False, False, LRules), 'RSA PKCS#1 with a hash an ECDSA scheme uses');
  CheckFalse(TComplianceCatalog.SignatureMeets(TCertSignatureFamily.RsaPss,
    TCertSignatureHash.Sha384, True, False, LRules), 'canonical RSA-PSS with such a hash');
end;

procedure TTestComplianceCatalog.TestSignatureMeetsKeepsEcdsaOutOfRsaOnlyRules;
var
  LRules: TComplianceRules;
begin
  LRules := TCompliancePresets.Fips140_3;
  LRules.SignatureSchemes := [TSignatureScheme.RSA_PKCS1_SHA384];
  CheckTrue(TComplianceCatalog.SignatureMeets(TCertSignatureFamily.RsaPkcs1,
    TCertSignatureHash.Sha384, False, False, LRules), 'RSA PKCS#1 with SHA-384 is listed');
  CheckFalse(TComplianceCatalog.SignatureMeets(TCertSignatureFamily.Ecdsa,
    TCertSignatureHash.Sha384, False, False, LRules), 'ECDSA is a family the rules lack');
  CheckFalse(TComplianceCatalog.SignatureMeets(TCertSignatureFamily.RsaPss,
    TCertSignatureHash.Sha384, True, False, LRules), 'and so is RSA-PSS');
end;

procedure TTestComplianceCatalog.TestSignatureMeetsAdmitsCanonicalPssAsRsae;
var
  LRules: TComplianceRules;
begin
  LRules := TCompliancePresets.Fips140_3;
  LRules.SignatureSchemes := [TSignatureScheme.RSA_PSS_RSAE_SHA256];
  CheckTrue(TComplianceCatalog.SignatureMeets(TCertSignatureFamily.RsaPss,
    TCertSignatureHash.Sha256, True, False, LRules), 'canonical parameters');
end;

procedure TTestComplianceCatalog.TestSignatureMeetsRefusesPssUnderAPssIssuerKey;
var
  LRules: TComplianceRules;
begin
  LRules := TCompliancePresets.Fips140_3;
  LRules.SignatureSchemes := [TSignatureScheme.RSA_PSS_RSAE_SHA256];
  CheckTrue(TComplianceCatalog.SignatureMeets(TCertSignatureFamily.RsaPss,
    TCertSignatureHash.Sha256, True, False, LRules), 'under an rsaEncryption issuer key');
  CheckFalse(TComplianceCatalog.SignatureMeets(TCertSignatureFamily.RsaPss,
    TCertSignatureHash.Sha256, True, True, LRules), 'under a PSS-restricted issuer key');
end;

procedure TTestComplianceCatalog.TestSignatureMeetsRefusesNonCanonicalPss;
var
  LRules: TComplianceRules;
begin
  LRules := TCompliancePresets.Fips140_3;
  CheckFalse(TComplianceCatalog.SignatureMeets(TCertSignatureFamily.RsaPss,
    TCertSignatureHash.Sha256, False, False, LRules), 'the scheme is listed, the parameters are not');
end;

procedure TTestComplianceCatalog.TestSignatureMeetsRefusesNonCanonicalPssWithAnAdmittedHash;
var
  LRules: TComplianceRules;
begin
  LRules := TCompliancePresets.Fips140_3;
  LRules.Strength.AllowedDeprecatedHashes := [TCertSignatureHash.Sha1];
  CheckFalse(TComplianceCatalog.SignatureMeets(TCertSignatureFamily.RsaPss,
    TCertSignatureHash.Sha1, False, False, LRules), 'an admitted hash does not excuse the parameters');
  CheckTrue(TComplianceCatalog.SignatureMeets(TCertSignatureFamily.RsaPss,
    TCertSignatureHash.Sha1, True, False, LRules), 'canonical, it is admitted');
  CheckFalse(TComplianceCatalog.SignatureMeets(TCertSignatureFamily.RsaPss,
    TCertSignatureHash.Sha1, True, True, LRules), 'an admitted hash does not excuse a PSS issuer key');
end;

function TTestComplianceCatalog.Held(const AKey: ISigningKey;
  const AChain: array of TBytes): TTlsCredential;
var
  LI: Int32;
begin
  Result := Default(TTlsCredential);
  Result.PrivateKey := AKey;
  for LI := 0 to System.High(AChain) do
    TArrayUtilities.Append<TBytes>(Result.CertificateChain, AChain[LI]);
end;

procedure TTestComplianceCatalog.TestSameCredentialNeedsTheSameKeyObjectAndChainBytes;
var
  LKey: ISigningKey;
begin
  LKey := TFakeSigningKey.Create(TArray<TSignatureScheme>.Create(
    TSignatureScheme.ECDSA_SECP256R1_SHA256)) as ISigningKey;
  CheckTrue(TComplianceCatalog.SameCredential(Held(LKey, [TBytes.Create(1, 2), TBytes.Create(3)]),
    Held(LKey, [TBytes.Create(1, 2), TBytes.Create(3)])), 'one key, equal bytes');
  CheckFalse(TComplianceCatalog.SameCredential(Held(LKey, [TBytes.Create(1, 2)]),
    Held(LKey, [TBytes.Create(1, 2), TBytes.Create(3)])), 'a longer chain');
  CheckFalse(TComplianceCatalog.SameCredential(Held(LKey, [TBytes.Create(1, 2)]),
    Held(LKey, [TBytes.Create(1, 9)])), 'other bytes');
  CheckFalse(TComplianceCatalog.SameCredential(Held(LKey, [TBytes.Create(1, 2)]),
    Held(TFakeSigningKey.Create(TArray<TSignatureScheme>.Create(
    TSignatureScheme.ECDSA_SECP256R1_SHA256)) as ISigningKey, [TBytes.Create(1, 2)])),
    'another key object');
  CheckTrue(TComplianceCatalog.SameCredential(Held(nil, [TBytes.Create(1)]),
    Held(nil, [TBytes.Create(1)])), 'two credentials with no key and the same chain');
end;

procedure TTestComplianceCatalog.TestStandardNameIsFips140_3;
begin
  CheckEquals('FIPS 140-3', TComplianceCatalog.StandardName(TModuleStandard.Fips140_3), 'name');
end;

{ TTestComplianceReport }

procedure TTestComplianceReport.TestVerdictCompliantWithPresetAndNoFindings;
var
  LReport: IComplianceReport;
begin
  LReport := TComplianceReport.Create(TComplianceEnforcement.Strict, 'Fips140_3',
    Default(TModuleIdentity), TModuleStatus.Validated, nil, nil, False);
  CheckEquals(Ord(TComplianceVerdict.Compliant), Ord(LReport.Verdict), 'verdict');
  CheckTrue(LReport.KeyDerivationInModule, 'every derivation is a module service');
end;

procedure TTestComplianceReport.TestVerdictPrimitivesInModuleWithComposedKeyDerivation;
var
  LReport: IComplianceReport;
begin
  LReport := TComplianceReport.Create(TComplianceEnforcement.Strict, 'Fips140_3',
    Default(TModuleIdentity), TModuleStatus.Validated, nil, nil, True);
  CheckEquals(Ord(TComplianceVerdict.PrimitivesInModule), Ord(LReport.Verdict), 'verdict');
  CheckFalse(LReport.KeyDerivationInModule, 'a derivation runs outside the module');
end;

procedure TTestComplianceReport.TestVerdictNotCompliantWithFindingAndComposedKeyDerivation;
var
  LReport: IComplianceReport;
begin
  LReport := TComplianceReport.Create(TComplianceEnforcement.Strict, 'Fips140_3',
    Default(TModuleIdentity), TModuleStatus.Validated,
    TArray<TComplianceFinding>.Create(TComplianceFinding.Create(
    TComplianceFindingKind.EchConfigured, 'ech', 'configured')), nil, True);
  CheckEquals(Ord(TComplianceVerdict.NotCompliant), Ord(LReport.Verdict),
    'a finding outweighs the middle level');
end;

procedure TTestComplianceReport.TestVerdictNotCompliantWhenModuleNotValidatedAndKdfInModule;
var
  LReport: IComplianceReport;
begin
  LReport := TComplianceReport.Create(TComplianceEnforcement.Strict, 'Fips140_3',
    Default(TModuleIdentity), TModuleStatus.NotValidated, nil, nil, False);
  CheckEquals(Ord(TComplianceVerdict.NotCompliant), Ord(LReport.Verdict),
    'no module claim without a validated module');
end;

procedure TTestComplianceReport.TestVerdictNotCompliantWithFinding;
var
  LReport: IComplianceReport;
begin
  LReport := TComplianceReport.Create(TComplianceEnforcement.Strict, 'Fips140_3',
    Default(TModuleIdentity), TModuleStatus.Validated,
    TArray<TComplianceFinding>.Create(TComplianceFinding.Create(
    TComplianceFindingKind.EchConfigured, 'ech', 'configured')), nil, False);
  CheckEquals(Ord(TComplianceVerdict.NotCompliant), Ord(LReport.Verdict), 'verdict');
end;

procedure TTestComplianceReport.TestVerdictNotCompliantWithoutPreset;
var
  LReport: IComplianceReport;
begin
  LReport := TComplianceReport.Create(TComplianceEnforcement.Relaxed, '',
    Default(TModuleIdentity), TModuleStatus.Validated, nil, nil, False);
  CheckEquals(Ord(TComplianceVerdict.NotCompliant), Ord(LReport.Verdict), 'verdict');
end;

procedure TTestComplianceReport.TestReportCarriesEnforcementAndPreset;
var
  LReport: IComplianceReport;
begin
  LReport := TComplianceReport.Create(TComplianceEnforcement.Relaxed, 'Cnsa1',
    Default(TModuleIdentity), TModuleStatus.Unknown, nil, nil, False);
  CheckEquals(Ord(TComplianceEnforcement.Relaxed), Ord(LReport.Enforcement), 'enforcement');
  CheckEquals('Cnsa1', LReport.Preset, 'preset');
end;

procedure TTestComplianceReport.TestReportCarriesModuleFromAttestation;
var
  LIdentity: TModuleIdentity;
  LAttestation: IModuleAttestation;
  LReport: IComplianceReport;
begin
  LIdentity := Default(TModuleIdentity);
  LIdentity.OsName := 'Windows';
  LIdentity.OsBuild := 22621;
  LIdentity.OsVersion := '10.0.22621.1';
  LIdentity.Certificate := '5410';
  LAttestation := TFakeModuleAttestation.Create(TModuleStatus.Validated, LIdentity);
  LReport := TComplianceReport.Create(TComplianceEnforcement.Strict, 'Fips140_3',
    LAttestation.Identity, LAttestation.Status(TModuleStandard.Fips140_3), nil, nil, False);
  CheckEquals('Windows', LReport.Module.OsName, 'os name');
  CheckEquals(22621, Int32(LReport.Module.OsBuild), 'os build');
  CheckEquals('10.0.22621.1', LReport.Module.OsVersion, 'os version');
  CheckEquals('5410', LReport.Module.Certificate, 'certificate');
  CheckEquals(Ord(TModuleStatus.Validated), Ord(LReport.ModuleStatus), 'status');
end;

procedure TTestComplianceReport.TestReportFindingsAndDisclosuresRoundTrip;
var
  LReport: IComplianceReport;
begin
  LReport := TComplianceReport.Create(TComplianceEnforcement.Strict, 'Fips140_3',
    Default(TModuleIdentity), TModuleStatus.Validated,
    TArray<TComplianceFinding>.Create(
    TComplianceFinding.Create(TComplianceFindingKind.EchConfigured, 'ech', 'one'),
    TComplianceFinding.Create(TComplianceFindingKind.KeyLogConfigured, 'log', 'two')),
    TArray<string>.Create('first', 'second', 'third'), False);
  CheckEquals(2, System.Length(LReport.Findings), 'finding count');
  CheckEquals(Ord(TComplianceFindingKind.KeyLogConfigured), Ord(LReport.Findings[1].Kind),
    'second finding');
  CheckEquals(3, System.Length(LReport.Disclosures), 'disclosure count');
  CheckEquals('third', LReport.Disclosures[2], 'third disclosure');
end;

procedure TTestComplianceReport.TestReportCopiesFindingsOnCreate;
var
  LFindings: TArray<TComplianceFinding>;
  LReport: IComplianceReport;
begin
  LFindings := TArray<TComplianceFinding>.Create(TComplianceFinding.Create(
    TComplianceFindingKind.EchConfigured, 'ech', 'one'));
  LReport := TComplianceReport.Create(TComplianceEnforcement.Strict, 'Fips140_3',
    Default(TModuleIdentity), TModuleStatus.Validated, LFindings, nil, False);
  LFindings[0].Subject := 'changed';
  CheckEquals('ech', LReport.Findings[0].Subject, 'the caller edit does not reach the report');
end;

procedure TTestComplianceReport.TestReportReturnsCopyOfFindings;
var
  LReport: IComplianceReport;
  LFindings: TArray<TComplianceFinding>;
begin
  LReport := TComplianceReport.Create(TComplianceEnforcement.Strict, 'Fips140_3',
    Default(TModuleIdentity), TModuleStatus.Validated,
    TArray<TComplianceFinding>.Create(TComplianceFinding.Create(
    TComplianceFindingKind.EchConfigured, 'ech', 'one')), nil, False);
  LFindings := LReport.Findings;
  LFindings[0].Subject := 'changed';
  CheckEquals('ech', LReport.Findings[0].Subject, 'the returned array is a copy');
end;

procedure TTestComplianceReport.TestReportDescribeCompliant;
var
  LIdentity: TModuleIdentity;
  LReport: IComplianceReport;
begin
  LIdentity := Default(TModuleIdentity);
  LIdentity.OsName := 'Windows';
  LIdentity.OsVersion := '10.0.22621.1';
  LIdentity.Product := 'Windows 11 22H2';
  LIdentity.ModuleName := 'bcryptprimitives.dll';
  LIdentity.ModuleFileVersion := '10.0.22621.2';
  LIdentity.Certificate := '5410';
  LReport := TComplianceReport.Create(TComplianceEnforcement.Strict, 'Fips140_3', LIdentity,
    TModuleStatus.Validated, nil, TArray<string>.Create('a disclosure'), False);
  CheckEquals('Verdict: Compliant (Strict)' + sLineBreak + 'Preset: Fips140_3' + sLineBreak +
    'Module: Windows 10.0.22621.1 Windows 11 22H2 bcryptprimitives.dll 10.0.22621.2, ' +
    'certificate 5410, status Validated' + sLineBreak + 'Disclosure: a disclosure',
    LReport.Describe, 'description');
end;

procedure TTestComplianceReport.TestReportDescribeNamesThePrimitivesInModuleLevel;
var
  LReport: IComplianceReport;
begin
  LReport := TComplianceReport.Create(TComplianceEnforcement.Strict, 'Cnsa1',
    Default(TModuleIdentity), TModuleStatus.Validated, nil, nil, True);
  CheckTrue(Pos('Verdict: PrimitivesInModule (Strict)', LReport.Describe) = 1,
    'the verdict line prints the level name');
end;

procedure TTestComplianceReport.TestReportDescribeNotCompliant;
var
  LReport: IComplianceReport;
begin
  LReport := TComplianceReport.Create(TComplianceEnforcement.Relaxed, '',
    Default(TModuleIdentity), TModuleStatus.NotValidated,
    TArray<TComplianceFinding>.Create(TComplianceFinding.Create(
    TComplianceFindingKind.ModuleNotValidated, '10.0.1', 'no table')), nil, False);
  CheckEquals('Verdict: NotCompliant (Relaxed)' + sLineBreak + 'Preset: none' + sLineBreak +
    'Module: unknown module, status NotValidated' + sLineBreak +
    'Finding: ModuleNotValidated 10.0.1: no table', LReport.Describe, 'description');
end;

procedure TTestComplianceReport.TestFindingCreateSetsFields;
var
  LFinding: TComplianceFinding;
begin
  LFinding := TComplianceFinding.Create(TComplianceFindingKind.KeyLogConfigured, 'subject',
    'message');
  CheckEquals(Ord(TComplianceFindingKind.KeyLogConfigured), Ord(LFinding.Kind), 'kind');
  CheckEquals('subject', LFinding.Subject, 'subject');
  CheckEquals('message', LFinding.Message, 'message');
end;

procedure TTestComplianceReport.TestFindingDescribeFormat;
begin
  CheckEquals('EchConfigured grease: GREASE counts',
    TComplianceFinding.Create(TComplianceFindingKind.EchConfigured, 'grease',
    'GREASE counts').Describe, 'Kind Subject: Message');
end;

procedure TTestComplianceReport.TestFindingCategoryPerKind;
const
  PlatformKinds = [TComplianceFindingKind.ModuleNotValidated,
    TComplianceFindingKind.NoBackendReport, TComplianceFindingKind.AlgorithmOutsideModule,
    TComplianceFindingKind.KdfOutsideModule, TComplianceFindingKind.CredentialKeyOutsideModule,
    TComplianceFindingKind.ChainVerifiedOutsideModule,
    TComplianceFindingKind.StapleVerifiedOutsideModule, TComplianceFindingKind.CryptoNotCovered];
var
  LKind: TComplianceFindingKind;
  LFinding: TComplianceFinding;
  LExpected: TComplianceFindingCategory;
begin
  for LKind := Low(TComplianceFindingKind) to High(TComplianceFindingKind) do
  begin
    LFinding := TComplianceFinding.Create(LKind, '', '');
    if LKind in PlatformKinds then
      LExpected := TComplianceFindingCategory.Platform
    else
      LExpected := TComplianceFindingCategory.Configuration;
    CheckEquals(Ord(LExpected), Ord(LFinding.Category), 'kind ' + IntToStr(Ord(LKind)));
  end;
end;

procedure TTestComplianceReport.TestUnmetExceptionCarriesFindings;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    raise EComplianceUnmetTlsLibException.Create(TArray<TComplianceFinding>.Create(
      TComplianceFinding.Create(TComplianceFindingKind.ModuleNotValidated, 'a', 'b'),
      TComplianceFinding.Create(TComplianceFindingKind.EchConfigured, 'c', 'd')));
  except
    on E: EComplianceUnmetTlsLibException do
    begin
      LRaised := True;
      CheckEquals(2, System.Length(E.Findings), 'count');
      CheckEquals(Ord(TComplianceFindingKind.EchConfigured), Ord(E.Findings[1].Kind), 'second');
    end;
  end;
  CheckTrue(LRaised, 'raised');
end;

procedure TTestComplianceReport.TestUnmetExceptionMessageJoinsFindings;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    raise EComplianceUnmetTlsLibException.Create(TArray<TComplianceFinding>.Create(
      TComplianceFinding.Create(TComplianceFindingKind.ModuleNotValidated, 'a', 'b'),
      TComplianceFinding.Create(TComplianceFindingKind.EchConfigured, 'c', 'd')));
  except
    on E: EComplianceUnmetTlsLibException do
    begin
      LRaised := True;
      CheckTrue(Pos('ModuleNotValidated a: b; EchConfigured c: d', E.Message) > 0,
        'findings are joined with a semicolon');
    end;
  end;
  CheckTrue(LRaised, 'raised');
end;

procedure TTestComplianceReport.TestUnmetExceptionCopiesFindings;
var
  LFindings: TArray<TComplianceFinding>;
  LRaised: Boolean;
begin
  LFindings := TArray<TComplianceFinding>.Create(
    TComplianceFinding.Create(TComplianceFindingKind.EchConfigured, 'c', 'd'));
  LRaised := False;
  try
    raise EComplianceUnmetTlsLibException.Create(LFindings);
  except
    on E: EComplianceUnmetTlsLibException do
    begin
      LRaised := True;
      LFindings[0].Subject := 'changed';
      CheckEquals('c', E.Findings[0].Subject, 'the caller edit does not reach the exception');
    end;
  end;
  CheckTrue(LRaised, 'raised');
end;

procedure TTestComplianceReport.TestRefusedExceptionIsFatalInternalError;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    raise EComplianceRefusedTlsLibException.CreateResFmt(@SRefusedProbe, ['x']);
  except
    on E: EFatalAlertTlsLibException do
    begin
      LRaised := True;
      CheckTrue(E is EComplianceRefusedTlsLibException, 'the refused type');
      CheckEquals(Ord(TTlsAlertDescription.InternalError), Ord(E.AlertDescription), 'alert');
      CheckEquals('refused x', E.Message, 'message');
    end;
  end;
  CheckTrue(LRaised, 'it is an EFatalAlertTlsLibException');
end;

procedure TTestComplianceReport.TestFakeAttestationAnswersGivenValues;
var
  LIdentity: TModuleIdentity;
  LAttestation: IModuleAttestation;
begin
  LIdentity := Default(TModuleIdentity);
  LIdentity.Product := 'Fake';
  LAttestation := TFakeModuleAttestation.Create(TModuleStatus.NotValidated, LIdentity);
  CheckEquals('Fake', LAttestation.Identity.Product, 'identity');
  CheckEquals(Ord(TModuleStatus.NotValidated), Ord(LAttestation.Status(TModuleStandard.Fips140_3)),
    'status');
  CheckTrue(LAttestation.Describe <> '', 'describes itself');
end;

procedure TTestComplianceReport.TestVerdictNotCompliantWhenModuleNotValidated;
var
  LReport: IComplianceReport;
begin
  LReport := TComplianceReport.Create(TComplianceEnforcement.Relaxed, 'Fips140_3',
    Default(TModuleIdentity), TModuleStatus.NotValidated, nil, nil, False);
  CheckEquals(0, System.Length(LReport.Findings), 'no finding stands');
  CheckEquals(Ord(TComplianceVerdict.NotCompliant), Ord(LReport.Verdict),
    'a preset and no finding are not enough without a validated module');
end;

procedure TTestComplianceReport.TestVerdictNotCompliantWhenModuleUnknown;
var
  LReport: IComplianceReport;
begin
  LReport := TComplianceReport.Create(TComplianceEnforcement.Relaxed, 'Cnsa1',
    Default(TModuleIdentity), TModuleStatus.Unknown, nil, nil, False);
  CheckEquals(Ord(TComplianceVerdict.NotCompliant), Ord(LReport.Verdict), 'verdict');
end;

procedure TTestComplianceReport.TestReportCopiesDisclosuresOnCreate;
var
  LDisclosures: TArray<string>;
  LReport: IComplianceReport;
begin
  LDisclosures := TArray<string>.Create('one');
  LReport := TComplianceReport.Create(TComplianceEnforcement.Strict, 'Fips140_3',
    Default(TModuleIdentity), TModuleStatus.Validated, nil, LDisclosures, False);
  LDisclosures[0] := 'changed';
  CheckEquals('one', LReport.Disclosures[0], 'the caller edit does not reach the report');
end;

procedure TTestComplianceReport.TestReportReturnsCopyOfDisclosures;
var
  LReport: IComplianceReport;
  LDisclosures: TArray<string>;
begin
  LReport := TComplianceReport.Create(TComplianceEnforcement.Strict, 'Fips140_3',
    Default(TModuleIdentity), TModuleStatus.Validated, nil, TArray<string>.Create('one'), False);
  LDisclosures := LReport.Disclosures;
  LDisclosures[0] := 'changed';
  CheckEquals('one', LReport.Disclosures[0], 'the returned array is a copy');
end;

procedure TTestComplianceReport.TestFindingDescribeWithoutSubject;
begin
  CheckEquals('EchConfigured: GREASE counts',
    TComplianceFinding.Create(TComplianceFindingKind.EchConfigured, '',
    'GREASE counts').Describe, 'Kind: Message');
end;

procedure TTestComplianceReport.TestIdentityDescribeSkipsEmptyParts;
var
  LIdentity: TModuleIdentity;
begin
  LIdentity := Default(TModuleIdentity);
  LIdentity.OsName := 'Windows';
  LIdentity.OsVersion := '10.0.1';
  LIdentity.ModuleName := 'module.dll';
  CheckEquals('Windows 10.0.1 module.dll', LIdentity.Describe, 'no gap for the empty product');
end;

procedure TTestComplianceReport.TestIdentityDescribeEmpty;
var
  LIdentity: TModuleIdentity;
begin
  LIdentity := Default(TModuleIdentity);
  CheckEquals('', LIdentity.Describe, 'nothing attested');
end;

procedure TTestComplianceReport.TestIdentityDescribePrintsTheArchitectureAndLegacyPolicy;
var
  LIdentity: TModuleIdentity;
begin
  LIdentity := Default(TModuleIdentity);
  LIdentity.OsName := 'Windows';
  LIdentity.ProductType := 3;
  LIdentity.NativeMachine := $8664;
  LIdentity.ProcessMachine := $014C;
  LIdentity.ModulePath := 'C:\m.dll';
  LIdentity.ListedModuleVersion := '10.0.1.2';
  LIdentity.LegacyFipsPolicy := TLegacyFipsPolicy.Enabled;
  CheckEquals('Windows product type 3 listed 10.0.1.2 C:\m.dll machine 0x8664 process 0x014C ' +
    'legacy FIPS policy Enabled', LIdentity.Describe, 'every fact, compactly');
end;

procedure TTestComplianceReport.TestIdentityDescribeHidesAnUnreadMachine;
var
  LIdentity: TModuleIdentity;
begin
  LIdentity := Default(TModuleIdentity);
  LIdentity.OsName := 'Windows';
  LIdentity.LegacyFipsPolicy := TLegacyFipsPolicy.Disabled;
  CheckEquals('Windows legacy FIPS policy Disabled', LIdentity.Describe,
    'no machine, product type or path');
end;

procedure TTestComplianceReport.TestIdentityDescribeProcessMachineAloneHasNoDoubleSpace;
var
  LIdentity: TModuleIdentity;
begin
  LIdentity := Default(TModuleIdentity);
  LIdentity.OsName := 'Windows';
  LIdentity.ProcessMachine := $014C;
  CheckEquals('Windows process 0x014C', LIdentity.Describe, 'no gap for the unread native machine');
end;

procedure TTestComplianceReport.TestIdentityDescribePrintsEditionAndFirmware;
var
  LIdentity: TModuleIdentity;
begin
  LIdentity := Default(TModuleIdentity);
  LIdentity.OsName := 'Windows';
  LIdentity.OsVersion := '10.0.1';
  LIdentity.Edition := 'Core';
  LIdentity.ProductType := 1;
  LIdentity.Firmware := 'UEFI';
  CheckEquals('Windows 10.0.1 edition Core product type 1 firmware UEFI', LIdentity.Describe,
    'the facts in order');
end;

procedure TTestComplianceReport.TestReportDescribeWithoutCertificate;
var
  LIdentity: TModuleIdentity;
  LReport: IComplianceReport;
begin
  LIdentity := Default(TModuleIdentity);
  LIdentity.OsName := 'Windows';
  LReport := TComplianceReport.Create(TComplianceEnforcement.Relaxed, '', LIdentity,
    TModuleStatus.NotValidated, nil, nil, False);
  CheckTrue(Pos('Module: Windows, status NotValidated', LReport.Describe) > 0,
    'no certificate clause');
end;

procedure TTestComplianceReport.TestUnmetExceptionReturnsCopyOfFindings;
var
  LRaised: Boolean;
  LFindings: TArray<TComplianceFinding>;
begin
  LRaised := False;
  try
    raise EComplianceUnmetTlsLibException.Create(TArray<TComplianceFinding>.Create(
      TComplianceFinding.Create(TComplianceFindingKind.EchConfigured, 'c', 'd')));
  except
    on E: EComplianceUnmetTlsLibException do
    begin
      LRaised := True;
      LFindings := E.Findings;
      LFindings[0].Subject := 'changed';
      CheckEquals('c', E.Findings[0].Subject, 'the returned array is a copy');
    end;
  end;
  CheckTrue(LRaised, 'raised');
end;

procedure TTestComplianceReport.TestRefusedExceptionCreateRes;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    raise EComplianceRefusedTlsLibException.CreateRes(@SRefusedNoArgument);
  except
    on E: EFatalAlertTlsLibException do
    begin
      LRaised := True;
      CheckEquals(Ord(TTlsAlertDescription.InternalError), Ord(E.AlertDescription), 'alert');
      CheckEquals('refused without an argument', E.Message, 'message');
    end;
  end;
  CheckTrue(LRaised, 'raised');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestCompliancePresets);
  RegisterTest(TTestComplianceRules);
  RegisterTest(TTestComplianceCatalog);
  RegisterTest(TTestComplianceReport);
{$ELSE}
  RegisterTest(TTestCompliancePresets.Suite);
  RegisterTest(TTestComplianceRules.Suite);
  RegisterTest(TTestComplianceCatalog.Suite);
  RegisterTest(TTestComplianceReport.Suite);
{$ENDIF FPC}

end.
