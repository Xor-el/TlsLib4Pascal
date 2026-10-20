{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit NamedGroupTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  Classes,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  TlpTlsAlert,
  TlpEnumUtilities,
  TlpAlertMapping,
  TlpTlsLibExceptions,
  TlpISecretBuffer,
  TlpSecretBuffer,
  TlpArrayUtilities,
  TlpCryptoDomainTypes,
  TlpICryptoProvider,
  TlsLibTestProviders,
  MockCryptoProvider,
  TlpINamedGroup,
  TlpIKeyExchangePrivateKey,
  TlpNamedGroups,
  TlpNegotiationTypes,
  TlsLibTestBase;

type
  TTestNamedGroups = class(TTlsLibAlgorithmTestCase)
  private
    function SecretBytes(const ASecret: ISecretBuffer): TBytes;
    function Zeros(ALength: Int32): TBytes;
    procedure CheckNistEcdhRefused(const AName, AMsg: string);
    // full KEM round-trip: A generates, B encapsulates, A decapsulates, secrets match
    procedure CheckAgreement(const AGroup: INamedGroup; AExpectedSecretLen: Int32);
    /// <summary>Decapsulate on ABadShare must reject with a contained exception that
    /// maps to illegal_parameter (no backend exception may escape the group).</summary>
    procedure CheckDecapIllegalParameter(const AGroup: INamedGroup;
      const APriv: IKeyExchangePrivateKey; const ABadShare: TBytes; const AMsg: string);
    // export a fresh key's raw scalar, re-import it, and prove the derived public and
    // the resulting agreement are identical - the neutral-currency seam HPKE relies on
    procedure CheckKeyImportRoundTrip(AAlgorithm: TKeyAgreementAlgorithm);
    // a Static-usage agreement (full scalar blinding, for a long-lived recipient key)
    // must yield the same secret as the Ephemeral one: the blind is r*n, so [k+r*n]P = [k]P
    procedure CheckStaticUsageAgreesLikeEphemeral(AAlgorithm: TKeyAgreementAlgorithm);
    // import an UNCLAMPED external X25519 scalar (RFC 7748 6.1 Alice) and prove the derived
    // public is the RFC's published value - the seam an external HPKE/ECH key crosses
    procedure CheckUnclampedScalarImport(const ACryptoProvider: ICryptoProvider);
    // pins a hybrid's wire layout: split the client share at the claimed boundary, encapsulate
    // each leg standalone, reassemble the ciphertext in the claimed order, and prove the hybrid
    // decapsulates to the concatenation in that same order - a flipped KEM/classical order fails
    procedure CheckHybridOrder(const AHybrid, AClassical, AKem: INamedGroup;
      AClassicalShareBytes, AKemEncapsBytes: Int32; AKemFirst: Boolean);
  published
    procedure TestX25519Rfc7748Kat;
    procedure TestX25519AcceptsNonCanonicalU;
    procedure TestX25519Agreement;
    procedure TestMlKem768Agreement;
    procedure TestHybridAgreement;
    procedure TestSecP256r1MlKem768Agreement;
    procedure TestHybridShareOrdering;
    procedure TestSecP256r1MlKem768DecapsulateRejectsShortCiphertext;
    procedure TestNistAgreement;
    procedure TestNistValidationRejectsBadPoints;
    procedure TestX25519ValidationRejectsWrongLength;
    procedure TestX25519RejectsAllZeroPeerShare;
    procedure TestMlKemValidationRejectsWrongLength;
    procedure TestMlKemValidationRejectsOutOfRangeCoefficient;
    procedure TestNistDecapsulateRejectsOffCurvePoint;
    procedure TestHybridDecapsulateRejectsShortCiphertext;
    procedure TestMlKemDecapsulateRejectsWrongLengthCiphertext;
    procedure TestMlKemBackendDecapsulationFaultIsInternalError;
    procedure TestRegistry;
    procedure TestCreateRegistryPreservesGivenOrder;
    procedure TestCreateRegistryLooksUpByCode;
    procedure TestCreateRegistryKeepsFirstOfDuplicateCode;
    procedure TestCreateRegistryEmptyArrayGivesEmptyRegistry;
    procedure TestCreateRegistryRejectsNilGroup;
    procedure TestClassicalRegistryOmitsPostQuantum;
    procedure TestGroupKindClassifiesEcdheKemHybrid;
    procedure TestOnlyEcdheGroupsAreTls12Eligible;
    procedure TestCatalogCompositionOfEachClassicalGroup;
    procedure TestCatalogCompositionOfTheKemAndHybridGroups;
    procedure TestCatalogCompositionAgreesWithTheBuiltGroups;
    procedure TestCatalogCompositionRefusesAnUnknownCode;
    procedure TestNistEcdhRefusesNamesThatAreNotPlainEcdhe;
    procedure TestKeyImportExportRoundTrip;
    procedure TestStaticUsageAgreesLikeEphemeral;
    procedure TestX25519ImportUnclampedScalar;
  end;

implementation

{ TTestNamedGroups }

function TTestNamedGroups.SecretBytes(const ASecret: ISecretBuffer): TBytes;
begin
  Result := nil;
  SetLength(Result, ASecret.Len);
  if ASecret.Len > 0 then
    Move(ASecret.DataPtr^, Result[0], ASecret.Len);
end;

function TTestNamedGroups.Zeros(ALength: Int32): TBytes;
begin
  Result := nil;
  SetLength(Result, ALength);
end;

procedure TTestNamedGroups.CheckAgreement(const AGroup: INamedGroup;
  AExpectedSecretLen: Int32);
var
  LPrivA: IKeyExchangePrivateKey;
  LPubA, LCiphertext: TBytes;
  LSecretA, LSecretB: ISecretBuffer;
begin
  AGroup.GenerateKeyPair(LPrivA, LPubA);
  AGroup.Encapsulate(LPubA, LCiphertext, LSecretB);
  AGroup.Decapsulate(LPrivA, LCiphertext, LSecretA);
  CheckEquals(AExpectedSecretLen, LSecretA.Len, AGroup.Name + ' secret length');
  CheckEqualBytes(AGroup.Name + ' agreement', SecretBytes(LSecretB),
    SecretBytes(LSecretA));
end;

procedure TTestNamedGroups.TestX25519Rfc7748Kat;
var
  LVec: TStringList;
  LCrypto: ICryptoProvider;
  LGroup: INamedGroup;
  LKa: IKeyAgreement;
  LKey: IKeyExchangePrivateKey;
  LSecret: ISecretBuffer;
  LPub: TBytes;
begin
  LVec := LoadVectorFields('Crypto/Ecdh/X25519Rfc7748.txt');
  try
    // portable: the vector's u lies outside the prime-order subgroup, refused by Windows Server
    // 2025 CNG (build 26100)
    LCrypto := TTlsLibTestProviders.Crypto(TCryptoProviderChoice.Portable);
    LGroup := TNamedGroups.CreateX25519(LCrypto);
    // adopt the raw RFC 7748 scalar into a key; Decapsulate is then ECDH(scalar, u)
    LKa := LCrypto.Primitives.CreateKeyAgreement(TKeyAgreementAlgorithm.X25519);
    LKey := LKa.ImportPrivateKey(TSecretBuffer.From(DecodeHex(LVec.Values['scalar'])),
      TKeyAgreementUsage.Ephemeral, LPub);
    LGroup.Decapsulate(LKey, DecodeHex(LVec.Values['u']), LSecret);
    CheckEqualBytes('X25519 RFC 7748', DecodeHex(LVec.Values['output']),
      SecretBytes(LSecret));
  finally
    LVec.Free;
  end;
end;

procedure TTestNamedGroups.TestX25519AcceptsNonCanonicalU;
var
  LVec: TStringList;
  LKa: IKeyAgreement;
  LKey: IKeyExchangePrivateKey;
  LPub, LExpected: TBytes;
begin
  // RFC 7748 5: a receiver masks bit 255 and accepts a non-canonical u, so p+9 and 9 with
  // bit 255 set both agree like u = 9 (Alice's public key)
  LVec := LoadVectorFields('Crypto/Ecdh/X25519Rfc7748.txt');
  try
    LExpected := DecodeHex(LVec.Values['alice_public']);
    LKa := Crypto.Primitives.CreateKeyAgreement(TKeyAgreementAlgorithm.X25519);
    LKey := LKa.ImportPrivateKey(TSecretBuffer.From(DecodeHex(LVec.Values['alice_private'])),
      TKeyAgreementUsage.Ephemeral, LPub);
    CheckEqualBytes('the public key of the RFC 7748 6.1 private key', LExpected, LPub);
    CheckEqualBytes('u = p+9 reduces to 9', LExpected,
      SecretBytes(LKa.Agree(LKey, DecodeHex(LVec.Values['u_p_plus_9']))));
    CheckEqualBytes('bit 255 of u is masked', LExpected,
      SecretBytes(LKa.Agree(LKey, DecodeHex(LVec.Values['u_9_bit255']))));
    CheckEqualBytes('RFC 7748 6.1 shared secret with Bob''s public key',
      DecodeHex(LVec.Values['shared_k']),
      SecretBytes(LKa.Agree(LKey, DecodeHex(LVec.Values['bob_public']))));
  finally
    LVec.Free;
  end;
end;

procedure TTestNamedGroups.TestX25519Agreement;
begin
  CheckAgreement(TNamedGroups.CreateX25519(Crypto), 32);
end;

procedure TTestNamedGroups.CheckKeyImportRoundTrip(
  AAlgorithm: TKeyAgreementAlgorithm);
var
  LKa: IKeyAgreement;
  LPriv, LPriv2, LPeerPriv: IKeyExchangePrivateKey;
  LScalar: ISecretBuffer;
  LPub, LPub2, LPeerPub: TBytes;
  LName: string;
begin
  LName := TEnumUtilities.GetName<TKeyAgreementAlgorithm>(AAlgorithm);
  LKa := Crypto.Primitives.CreateKeyAgreement(AAlgorithm);
  LKa.GenerateKeyPair(LPriv, LPub);
  // export the raw scalar and re-import it; the derived public must match the original
  LScalar := LPriv.ExportRaw;
  LPriv2 := LKa.ImportPrivateKey(LScalar, TKeyAgreementUsage.Ephemeral, LPub2);
  CheckEqualBytes(LName + ' import derives the same public', LPub, LPub2);
  // the re-imported key agrees identically with a peer (functionally the same key)
  LKa.GenerateKeyPair(LPeerPriv, LPeerPub);
  CheckEqualBytes(LName + ' re-imported key agrees identically',
    SecretBytes(LKa.Agree(LPriv, LPeerPub)),
    SecretBytes(LKa.Agree(LPriv2, LPeerPub)));
end;

procedure TTestNamedGroups.CheckStaticUsageAgreesLikeEphemeral(
  AAlgorithm: TKeyAgreementAlgorithm);
var
  LKa: IKeyAgreement;
  LPriv, LStaticPriv, LPeerPriv: IKeyExchangePrivateKey;
  LPub, LPubDup, LPeerPub: TBytes;
  LName: string;
begin
  LName := TEnumUtilities.GetName<TKeyAgreementAlgorithm>(AAlgorithm);
  LKa := Crypto.Primitives.CreateKeyAgreement(AAlgorithm);
  // one scalar adopted twice: once Ephemeral (as generated), once Static (posture-on-handle)
  LKa.GenerateKeyPair(LPriv, LPub);
  LStaticPriv := LKa.ImportPrivateKey(LPriv.ExportRaw, TKeyAgreementUsage.Static, LPubDup);
  LKa.GenerateKeyPair(LPeerPriv, LPeerPub);
  CheckEqualBytes(LName + ' static usage agrees like ephemeral',
    SecretBytes(LKa.Agree(LPriv, LPeerPub)),
    SecretBytes(LKa.Agree(LStaticPriv, LPeerPub)));
  // both parties reach the same secret under full blinding (DH is commutative)
  CheckEqualBytes(LName + ' static usage is commutative',
    SecretBytes(LKa.Agree(LStaticPriv, LPeerPub)),
    SecretBytes(LKa.Agree(LPeerPriv, LPub)));
end;

procedure TTestNamedGroups.TestKeyImportExportRoundTrip;
begin
  CheckKeyImportRoundTrip(TKeyAgreementAlgorithm.X25519);
  CheckKeyImportRoundTrip(TKeyAgreementAlgorithm.SECP256R1);
  CheckKeyImportRoundTrip(TKeyAgreementAlgorithm.SECP384R1);
  CheckKeyImportRoundTrip(TKeyAgreementAlgorithm.SECP521R1);
end;

procedure TTestNamedGroups.TestStaticUsageAgreesLikeEphemeral;
begin
  CheckStaticUsageAgreesLikeEphemeral(TKeyAgreementAlgorithm.X25519);
  CheckStaticUsageAgreesLikeEphemeral(TKeyAgreementAlgorithm.SECP256R1);
  CheckStaticUsageAgreesLikeEphemeral(TKeyAgreementAlgorithm.SECP384R1);
  CheckStaticUsageAgreesLikeEphemeral(TKeyAgreementAlgorithm.SECP521R1);
end;

procedure TTestNamedGroups.CheckUnclampedScalarImport(
  const ACryptoProvider: ICryptoProvider);
const
  // RFC 7748 6.1: Alice's private scalar is unclamped (low bits set) - the shape of an
  // external HPKE/ECH key; import must clamp it and derive Alice's published public key
  ALICE_SK = '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a';
  ALICE_PK = '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a';
var
  LKa: IKeyAgreement;
  LPub: TBytes;
begin
  LKa := ACryptoProvider.Primitives.CreateKeyAgreement(TKeyAgreementAlgorithm.X25519);
  LKa.ImportPrivateKey(TSecretBuffer.From(DecodeHex(ALICE_SK)),
    TKeyAgreementUsage.Ephemeral, LPub);
  CheckEqualBytes('X25519 unclamped import derives the RFC 7748 public',
    DecodeHex(ALICE_PK), LPub);
end;

procedure TTestNamedGroups.TestX25519ImportUnclampedScalar;
begin
  CheckUnclampedScalarImport(Crypto);
end;

procedure TTestNamedGroups.TestMlKem768Agreement;
begin
  CheckAgreement(TNamedGroups.CreateMlKem768(Crypto), 32);
end;

procedure TTestNamedGroups.TestHybridAgreement;
begin
  // shared secret = ML-KEM-768 secret (32) || X25519 secret (32)
  CheckAgreement(TNamedGroups.CreateX25519MlKem768(Crypto), 64);
end;

procedure TTestNamedGroups.TestSecP256r1MlKem768Agreement;
begin
  // shared secret = P-256 ECDH secret (32) || ML-KEM-768 secret (32) (RFC 10024)
  CheckAgreement(TNamedGroups.CreateSecP256r1MlKem768(Crypto), 64);
end;

procedure TTestNamedGroups.CheckHybridOrder(const AHybrid, AClassical,
  AKem: INamedGroup; AClassicalShareBytes, AKemEncapsBytes: Int32;
  AKemFirst: Boolean);
var
  LPriv: IKeyExchangePrivateKey;
  LPubShare, LClassPub, LKemPub, LClassCt, LKemCt, LCipher, LExpected: TBytes;
  LClassSs, LKemSs, LHybridSs: ISecretBuffer;
begin
  AHybrid.GenerateKeyPair(LPriv, LPubShare);
  // split the client share at the boundary the group's wire order claims
  if AKemFirst then
  begin
    LKemPub := System.Copy(LPubShare, 0, AKemEncapsBytes);
    LClassPub := System.Copy(LPubShare, AKemEncapsBytes, AClassicalShareBytes);
  end
  else
  begin
    LClassPub := System.Copy(LPubShare, 0, AClassicalShareBytes);
    LKemPub := System.Copy(LPubShare, AClassicalShareBytes, AKemEncapsBytes);
  end;
  AClassical.Encapsulate(LClassPub, LClassCt, LClassSs);
  AKem.Encapsulate(LKemPub, LKemCt, LKemSs);
  // reassemble the ciphertext and the expected secret in the claimed order, then decapsulate
  if AKemFirst then
  begin
    LCipher := TArrayUtilities.Concat(LKemCt, LClassCt);
    LExpected := TArrayUtilities.Concat(SecretBytes(LKemSs), SecretBytes(LClassSs));
  end
  else
  begin
    LCipher := TArrayUtilities.Concat(LClassCt, LKemCt);
    LExpected := TArrayUtilities.Concat(SecretBytes(LClassSs), SecretBytes(LKemSs));
  end;
  AHybrid.Decapsulate(LPriv, LCipher, LHybridSs);
  CheckEqualBytes(AHybrid.Name + ' share/secret ordering', LExpected,
    SecretBytes(LHybridSs));
end;

procedure TTestNamedGroups.TestHybridShareOrdering;
begin
  // X25519MLKEM768 writes ML-KEM first; SecP256r1MLKEM768 writes ECDH first (RFC 10024)
  CheckHybridOrder(TNamedGroups.CreateX25519MlKem768(Crypto),
    TNamedGroups.CreateX25519(Crypto), TNamedGroups.CreateMlKem768(Crypto),
    32, 1184, True);
  CheckHybridOrder(TNamedGroups.CreateSecP256r1MlKem768(Crypto),
    TNamedGroups.CreateNistEcdh(Crypto, 'secp256r1'),
    TNamedGroups.CreateMlKem768(Crypto), 65, 1184, False);
end;

procedure TTestNamedGroups.TestSecP256r1MlKem768DecapsulateRejectsShortCiphertext;
var
  LGroup: INamedGroup;
  LPriv: IKeyExchangePrivateKey;
  LPub: TBytes;
begin
  LGroup := TNamedGroups.CreateSecP256r1MlKem768(Crypto);
  LGroup.GenerateKeyPair(LPriv, LPub);
  // far shorter than the 65 + 1088 hybrid ciphertext; slicing must not reach the backend
  CheckDecapIllegalParameter(LGroup, LPriv, Zeros(100),
    'a short hybrid ciphertext is rejected as illegal_parameter');
end;

procedure TTestNamedGroups.TestNistAgreement;
begin
  CheckAgreement(TNamedGroups.CreateNistEcdh(Crypto, 'secp256r1'), 32);
  CheckAgreement(TNamedGroups.CreateNistEcdh(Crypto, 'secp384r1'), 48);
  CheckAgreement(TNamedGroups.CreateNistEcdh(Crypto, 'secp521r1'), 66);
end;

procedure TTestNamedGroups.TestNistValidationRejectsBadPoints;
var
  LGroup: INamedGroup;
  LPriv: IKeyExchangePrivateKey;
  LPub, LOffCurve, LCompressed: TBytes;
begin
  LGroup := TNamedGroups.CreateNistEcdh(Crypto, 'secp256r1');
  // point at infinity (single 0x00 byte)
  CheckFalse(LGroup.ValidatePeerShare(DecodeHex('00')), 'infinity rejected');
  // empty / malformed
  CheckFalse(LGroup.ValidatePeerShare(nil), 'empty rejected');
  CheckFalse(LGroup.ValidatePeerShare(DecodeHex('04AABBCC')), 'malformed rejected');
  // uncompressed 0x04 || X=1 || Y=1 - correct length, not on the curve
  LOffCurve := DecodeHex('04' +
    '0000000000000000000000000000000000000000000000000000000000000001' +
    '0000000000000000000000000000000000000000000000000000000000000001');
  CheckFalse(LGroup.ValidatePeerShare(LOffCurve), 'off-curve rejected');
  // a genuine public share is accepted
  LGroup.GenerateKeyPair(LPriv, LPub);
  CheckTrue(LGroup.ValidatePeerShare(LPub), 'valid point accepted');
  // the same on-curve point in COMPRESSED form must be rejected: modern TLS requires
  // the uncompressed form (RFC 9846 4.3.8.2, RFC 8422 5.1.2), though the curve decodes it
  LCompressed := nil;
  SetLength(LCompressed, 33);
  Move(LPub[1], LCompressed[1], 32); // the X coordinate
  // 0x02 for an even Y, 0x03 for an odd Y (parity is the last byte of Y)
  LCompressed[0] := $02 or (LPub[64] and $01);
  CheckFalse(LGroup.ValidatePeerShare(LCompressed),
    'a compressed point is rejected (TLS requires the uncompressed form)');
end;

procedure TTestNamedGroups.TestX25519ValidationRejectsWrongLength;
var
  LGroup: INamedGroup;
begin
  LGroup := TNamedGroups.CreateX25519(Crypto);
  CheckFalse(LGroup.ValidatePeerShare(DecodeHex('0011')), 'short rejected');
  CheckFalse(LGroup.ValidatePeerShare(Zeros(31)), '31 bytes rejected');
  CheckTrue(LGroup.ValidatePeerShare(Zeros(32)), 'any 32 bytes accepted');
end;

procedure TTestNamedGroups.TestX25519RejectsAllZeroPeerShare;
var
  LGroup: INamedGroup;
  LPriv: IKeyExchangePrivateKey;
  LSecret: ISecretBuffer;
  LPub: TBytes;
  LRaised: Boolean;
begin
  // an all-zero u-coordinate is a small-order point: the agreement yields an
  // all-zero (non-contributory) shared secret, which must be refused
  LGroup := TNamedGroups.CreateX25519(Crypto);
  LGroup.GenerateKeyPair(LPriv, LPub);
  LRaised := False;
  try
    LGroup.Decapsulate(LPriv, Zeros(32), LSecret);
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a small-order (all-zero) peer share must be rejected');
end;

procedure TTestNamedGroups.TestMlKemValidationRejectsWrongLength;
var
  LGroup: INamedGroup;
  LPriv: IKeyExchangePrivateKey;
  LPub: TBytes;
begin
  LGroup := TNamedGroups.CreateMlKem768(Crypto);
  CheckFalse(LGroup.ValidatePeerShare(DecodeHex('0011')), 'short rejected');
  CheckFalse(LGroup.ValidatePeerShare(Zeros(1183)), 'wrong length rejected');
  LGroup.GenerateKeyPair(LPriv, LPub);
  CheckEquals(1184, System.Length(LPub), 'encaps key size');
  CheckTrue(LGroup.ValidatePeerShare(LPub), 'valid encaps key accepted');
end;

procedure TTestNamedGroups.TestMlKemValidationRejectsOutOfRangeCoefficient;
var
  LProviders: array [0 .. 1] of ICryptoProvider;
  LI: Int32;
  LGroup: INamedGroup;
  LKey: TBytes;
  LPriv: IKeyExchangePrivateKey;
  LPub: TBytes;
begin
  // the key is 1152 bytes of 12-bit coefficients (two per three bytes) then rho; the bound
  // q = 3329 (FIPS 203 sec. 7.2) is the group's own, so it holds whichever backend sits below -
  // including one that only checks the length
  LProviders[0] := Crypto;
  LProviders[1] := TMissingAeadProvider.CreateLenientKem(Crypto) as ICryptoProvider;
  for LI := 0 to System.High(LProviders) do
  begin
    LGroup := TNamedGroups.CreateMlKem768(LProviders[LI]);
    LKey := Zeros(1184);
    CheckTrue(LGroup.ValidatePeerShare(LKey), 'all-zero coefficients are accepted');
    LKey[1] := $0D; // 0xD00 = 3328 = q - 1
    CheckTrue(LGroup.ValidatePeerShare(LKey), 'q - 1 is the largest accepted value');
    LKey[0] := $01; // 0xD01 = 3329 = q
    CheckFalse(LGroup.ValidatePeerShare(LKey), 'a first coefficient of q is refused');
    LKey[0] := $00;
    LKey[1] := $10; // coefficient 1 = (b1 >> 4) | (b2 << 4)
    LKey[2] := $D0; // 0xD01 = 3329
    CheckFalse(LGroup.ValidatePeerShare(LKey), 'a second coefficient of q is refused');
    LKey := Zeros(1184);
    LKey[1149] := $01;
    LKey[1150] := $0D;
    CheckFalse(LGroup.ValidatePeerShare(LKey), 'the last coefficient pair is checked');

    // both hybrids carry the same ML-KEM half, so the bound covers them too
    LGroup := TNamedGroups.CreateX25519MlKem768(LProviders[LI]);
    LGroup.GenerateKeyPair(LPriv, LPub);
    CheckTrue(LGroup.ValidatePeerShare(LPub), 'a generated hybrid share is accepted');
    LPub[0] := $01;
    LPub[1] := (LPub[1] and $F0) or $0D; // first ML-KEM coefficient = q
    CheckFalse(LGroup.ValidatePeerShare(LPub), 'X25519MLKEM768 refuses a coefficient of q');
    LGroup := TNamedGroups.CreateSecP256r1MlKem768(LProviders[LI]);
    LGroup.GenerateKeyPair(LPriv, LPub);
    CheckTrue(LGroup.ValidatePeerShare(LPub), 'a generated SecP256r1 hybrid share is accepted');
    LPub[65] := $01; // the classical half comes first
    LPub[66] := (LPub[66] and $F0) or $0D;
    CheckFalse(LGroup.ValidatePeerShare(LPub), 'SecP256r1MLKEM768 refuses a coefficient of q');
  end;
end;

procedure TTestNamedGroups.CheckDecapIllegalParameter(const AGroup: INamedGroup;
  const APriv: IKeyExchangePrivateKey; const ABadShare: TBytes; const AMsg: string);
var
  LSecret: ISecretBuffer;
  LOutcome: string;
begin
  LOutcome := 'no exception';
  try
    AGroup.Decapsulate(APriv, ABadShare, LSecret);
  except
    // a contained (Tlp) failure maps to illegal_parameter; a leaked backend
    // exception is not an EBaseTlsLibException and lands in the second handler
    on E: EBaseTlsLibException do
      if TAlertMapping.AlertFor(E).Description = TTlsAlertDescription.IllegalParameter then
        LOutcome := 'illegal_parameter'
      else
        LOutcome := 'wrong alert';
    on E: Exception do
      LOutcome := 'leaked ' + E.ClassName;
  end;
  CheckEquals('illegal_parameter', LOutcome, AMsg);
end;

procedure TTestNamedGroups.TestNistDecapsulateRejectsOffCurvePoint;
var
  LGroup: INamedGroup;
  LPriv: IKeyExchangePrivateKey;
  LPub, LBad: TBytes;
begin
  LGroup := TNamedGroups.CreateNistEcdh(Crypto, 'secp256r1');
  LGroup.GenerateKeyPair(LPriv, LPub);
  // an uncompressed point whose coordinates are not on the curve
  LBad := nil;
  SetLength(LBad, 65);
  FillChar(LBad[0], 65, $01);
  LBad[0] := $04;
  CheckDecapIllegalParameter(LGroup, LPriv, LBad,
    'an off-curve NIST peer point is rejected as illegal_parameter');
end;

procedure TTestNamedGroups.TestHybridDecapsulateRejectsShortCiphertext;
var
  LGroup: INamedGroup;
  LPriv: IKeyExchangePrivateKey;
  LPub: TBytes;
begin
  LGroup := TNamedGroups.CreateX25519MlKem768(Crypto);
  LGroup.GenerateKeyPair(LPriv, LPub);
  // far shorter than the 1088 + 32 hybrid ciphertext; slicing must not reach the backend
  CheckDecapIllegalParameter(LGroup, LPriv, Zeros(100),
    'a short hybrid ciphertext is rejected as illegal_parameter');
end;

procedure TTestNamedGroups.TestMlKemDecapsulateRejectsWrongLengthCiphertext;
var
  LGroup: INamedGroup;
  LPriv: IKeyExchangePrivateKey;
  LPub: TBytes;
begin
  LGroup := TNamedGroups.CreateMlKem768(Crypto);
  LGroup.GenerateKeyPair(LPriv, LPub);
  // RFC 10024 4.2: a ciphertext that is not 1088 bytes is illegal_parameter, at the exact bounds
  CheckDecapIllegalParameter(LGroup, LPriv, Zeros(100),
    'a short ML-KEM-768 ciphertext is rejected as illegal_parameter');
  CheckDecapIllegalParameter(LGroup, LPriv, Zeros(1087),
    'a ciphertext one byte short is rejected as illegal_parameter');
  CheckDecapIllegalParameter(LGroup, LPriv, Zeros(1089),
    'a ciphertext one byte long is rejected as illegal_parameter');
end;

procedure TTestNamedGroups.TestMlKemBackendDecapsulationFaultIsInternalError;
var
  LKem: IKem;
  LPriv: IKeyExchangePrivateKey;
  LPub: TBytes;
  LSecret: ISecretBuffer;
  LAlert: Int32;
  LLeaked: string;
begin
  LKem := Crypto.Primitives.CreateKem(TKemAlgorithm.ML_KEM_768);
  LKem.GenerateKeyPair(LPriv, LPub);
  LAlert := -1;
  LLeaked := '';
  try
    // below the group's length check the backend fault is local, not peer input
    LKem.Decapsulate(LPriv, Zeros(100), LSecret);
  except
    on E: EBaseTlsLibException do
      LAlert := Ord(TAlertMapping.AlertFor(E).Description);
    on E: Exception do
      LLeaked := E.ClassName;
  end;
  CheckEquals('', LLeaked, 'no backend exception escapes the KEM');
  CheckEquals(Ord(TTlsAlertDescription.InternalError), LAlert,
    'a backend decapsulation fault maps to internal_error');
end;

procedure TTestNamedGroups.TestRegistry;
var
  LReg: INamedGroupRegistry;
  LBuilder: INamedGroupRegistryBuilder;
  LGroup: INamedGroup;
begin
  LReg := TNamedGroups.CreateDefaultRegistry(Crypto);
  CheckTrue(LReg.Contains(TNamedGroupCatalog.X25519), 'has X25519');
  CheckTrue(LReg.Contains(TNamedGroupCatalog.X25519MlKem768), 'has the hybrid');
  CheckTrue(LReg.Contains(TNamedGroupCatalog.SecP256r1MlKem768), 'has the P-256 hybrid');
  CheckTrue(LReg.TryGet(TNamedGroupCatalog.X25519, LGroup), 'lookup by code');
  CheckEquals('X25519', LGroup.Name, 'get returns the group');
  LBuilder := LReg.ToBuilder;
  LBuilder.Prune(TNamedGroupCatalog.Secp521r1);
  CheckTrue(LReg.Contains(TNamedGroupCatalog.Secp521r1), 'the built registry is unchanged');
  LReg := LBuilder.Build;
  CheckFalse(LReg.Contains(TNamedGroupCatalog.Secp521r1), 'pruned entry gone');
  LBuilder.Add(TNamedGroups.CreateNistEcdh(Crypto, 'secp521r1'));
  CheckFalse(LReg.Contains(TNamedGroupCatalog.Secp521r1), 'a later Add does not reach a built registry');
  LReg := LBuilder.Build;
  CheckTrue(LReg.Contains(TNamedGroupCatalog.Secp521r1), 're-added');
  CheckFalse(LReg.TryGet($FFFF, LGroup), 'unknown code is not found');
end;

procedure TTestNamedGroups.TestCreateRegistryPreservesGivenOrder;
var
  LReg: INamedGroupRegistry;
  LItems: TArray<INamedGroup>;
begin
  LReg := TNamedGroups.CreateRegistry(TArray<INamedGroup>.Create(
    TNamedGroups.CreateNistEcdh(Crypto, 'secp384r1'), TNamedGroups.CreateX25519(Crypto)));
  LItems := LReg.Items;
  CheckEquals(2, System.Length(LItems), 'exactly the given groups');
  CheckEquals(TNamedGroupCatalog.Secp384r1, LItems[0].Code, 'first given group first');
  CheckEquals(TNamedGroupCatalog.X25519, LItems[1].Code, 'second given group second');
end;

procedure TTestNamedGroups.TestCreateRegistryLooksUpByCode;
var
  LReg: INamedGroupRegistry;
  LGroup: INamedGroup;
begin
  LReg := TNamedGroups.CreateRegistry(TArray<INamedGroup>.Create(
    TNamedGroups.CreateX25519(Crypto)));
  CheckTrue(LReg.TryGet(TNamedGroupCatalog.X25519, LGroup), 'given code found');
  CheckEquals('X25519', LGroup.Name, 'lookup returns the group');
  CheckFalse(LReg.Contains(TNamedGroupCatalog.Secp256r1), 'a group not given is absent');
end;

procedure TTestNamedGroups.TestCreateRegistryKeepsFirstOfDuplicateCode;
var
  LReg: INamedGroupRegistry;
  LFirst, LSecond, LFound: INamedGroup;
begin
  LFirst := TNamedGroups.CreateX25519(Crypto);
  LSecond := TNamedGroups.CreateX25519(Crypto);
  LReg := TNamedGroups.CreateRegistry(TArray<INamedGroup>.Create(LFirst, LSecond));
  CheckEquals(1, System.Length(LReg.Items), 'one entry for the repeated code');
  CheckTrue(LReg.TryGet(TNamedGroupCatalog.X25519, LFound), 'code present');
  CheckTrue(LFound = LFirst, 'the first entry wins');
end;

procedure TTestNamedGroups.TestCreateRegistryEmptyArrayGivesEmptyRegistry;
var
  LReg: INamedGroupRegistry;
begin
  LReg := TNamedGroups.CreateRegistry(nil);
  CheckEquals(0, System.Length(LReg.Items), 'no groups');
  CheckFalse(LReg.Contains(TNamedGroupCatalog.X25519), 'nothing registered');
end;

procedure TTestNamedGroups.TestCreateRegistryRejectsNilGroup;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    TNamedGroups.CreateRegistry(TArray<INamedGroup>.Create(
      TNamedGroups.CreateX25519(Crypto), nil));
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a nil group is an argument error');
end;

procedure TTestNamedGroups.TestClassicalRegistryOmitsPostQuantum;
var
  LReg: INamedGroupRegistry;
begin
  // the classical registry is the default minus the post-quantum hybrids, so a ClientHello
  // driven off it carries no ~1KB ML-KEM key share (the constrained-path escape hatch)
  LReg := TNamedGroups.CreateClassicalRegistry(Crypto);
  CheckTrue(LReg.Contains(TNamedGroupCatalog.X25519), 'has X25519');
  CheckTrue(LReg.Contains(TNamedGroupCatalog.Secp256r1), 'has secp256r1');
  CheckTrue(LReg.Contains(TNamedGroupCatalog.Secp384r1), 'has secp384r1');
  CheckTrue(LReg.Contains(TNamedGroupCatalog.Secp521r1), 'has secp521r1');
  CheckFalse(LReg.Contains(TNamedGroupCatalog.X25519MlKem768), 'no hybrid');
  CheckFalse(LReg.Contains(TNamedGroupCatalog.SecP256r1MlKem768), 'no P-256 hybrid');
  CheckFalse(LReg.Contains(TNamedGroupCatalog.MlKem768), 'no ML-KEM');
end;

procedure TTestNamedGroups.TestGroupKindClassifiesEcdheKemHybrid;
begin
  CheckTrue(TNamedGroups.CreateX25519(Crypto).Kind = TNamedGroupKind.Ecdhe,
    'X25519 is classical ECDHE');
  CheckTrue(TNamedGroups.CreateNistEcdh(Crypto, 'secp256r1').Kind =
    TNamedGroupKind.Ecdhe, 'secp256r1 is classical ECDHE');
  CheckTrue(TNamedGroups.CreateMlKem768(Crypto).Kind = TNamedGroupKind.Kem,
    'ML-KEM-768 is a KEM');
  CheckTrue(TNamedGroups.CreateX25519MlKem768(Crypto).Kind =
    TNamedGroupKind.Hybrid, 'X25519MLKEM768 is a hybrid');
  CheckTrue(TNamedGroups.CreateSecP256r1MlKem768(Crypto).Kind =
    TNamedGroupKind.Hybrid, 'SecP256r1MLKEM768 is a hybrid');
end;

procedure TTestNamedGroups.TestOnlyEcdheGroupsAreTls12Eligible;
var
  LReg: INamedGroupRegistry;
  LGroup: INamedGroup;
begin
  // the hybrid and pure-KEM groups are excluded from a TLS 1.2 handshake: only
  // Kind = Ecdhe is eligible (the filter the 1.2 negotiation applies)
  LReg := TNamedGroups.CreateDefaultRegistry(Crypto);
  CheckTrue(LReg.TryGet(TNamedGroupCatalog.X25519MlKem768, LGroup), 'hybrid present');
  CheckFalse(LGroup.Kind = TNamedGroupKind.Ecdhe, 'the hybrid is not 1.2-eligible');
  CheckTrue(LReg.TryGet(TNamedGroupCatalog.MlKem768, LGroup), 'ML-KEM present');
  CheckFalse(LGroup.Kind = TNamedGroupKind.Ecdhe, 'ML-KEM is not 1.2-eligible');
  CheckTrue(LReg.TryGet(TNamedGroupCatalog.Secp256r1, LGroup), 'secp256r1 present');
  CheckTrue(LGroup.Kind = TNamedGroupKind.Ecdhe, 'secp256r1 is 1.2-eligible');
end;

procedure TTestNamedGroups.TestCatalogCompositionOfEachClassicalGroup;
var
  LComposition: TNamedGroupComposition;
begin
  CheckTrue(TNamedGroupCatalog.TryComposition(TNamedGroupCatalog.X25519, LComposition),
    'X25519 is built in');
  CheckTrue(LComposition.Kind = TNamedGroupKind.Ecdhe, 'X25519 kind');
  CheckTrue(LComposition.KeyAgreement = TKeyAgreementAlgorithm.X25519, 'X25519 agreement');
  CheckTrue(TNamedGroupCatalog.TryComposition(TNamedGroupCatalog.Secp256r1, LComposition),
    'secp256r1 is built in');
  CheckTrue(LComposition.Kind = TNamedGroupKind.Ecdhe, 'secp256r1 kind');
  CheckTrue(LComposition.KeyAgreement = TKeyAgreementAlgorithm.SECP256R1,
    'secp256r1 agreement');
  CheckTrue(TNamedGroupCatalog.TryComposition(TNamedGroupCatalog.Secp384r1, LComposition),
    'secp384r1 is built in');
  CheckTrue(LComposition.Kind = TNamedGroupKind.Ecdhe, 'secp384r1 kind');
  CheckTrue(LComposition.KeyAgreement = TKeyAgreementAlgorithm.SECP384R1,
    'secp384r1 agreement');
  CheckTrue(TNamedGroupCatalog.TryComposition(TNamedGroupCatalog.Secp521r1, LComposition),
    'secp521r1 is built in');
  CheckTrue(LComposition.Kind = TNamedGroupKind.Ecdhe, 'secp521r1 kind');
  CheckTrue(LComposition.KeyAgreement = TKeyAgreementAlgorithm.SECP521R1,
    'secp521r1 agreement');
end;

procedure TTestNamedGroups.TestCatalogCompositionOfTheKemAndHybridGroups;
var
  LComposition: TNamedGroupComposition;
begin
  CheckTrue(TNamedGroupCatalog.TryComposition(TNamedGroupCatalog.MlKem768, LComposition),
    'ML-KEM-768 is built in');
  CheckTrue(LComposition.Kind = TNamedGroupKind.Kem, 'ML-KEM-768 kind');
  CheckTrue(LComposition.Kem = TKemAlgorithm.ML_KEM_768, 'ML-KEM-768 kem');
  CheckTrue(TNamedGroupCatalog.TryComposition(TNamedGroupCatalog.X25519MlKem768,
    LComposition), 'X25519MLKEM768 is built in');
  CheckTrue(LComposition.Kind = TNamedGroupKind.Hybrid, 'X25519MLKEM768 kind');
  CheckTrue(LComposition.KeyAgreement = TKeyAgreementAlgorithm.X25519,
    'X25519MLKEM768 agreement');
  CheckTrue(LComposition.Kem = TKemAlgorithm.ML_KEM_768, 'X25519MLKEM768 kem');
  CheckTrue(TNamedGroupCatalog.TryComposition(TNamedGroupCatalog.SecP256r1MlKem768,
    LComposition), 'SecP256r1MLKEM768 is built in');
  CheckTrue(LComposition.Kind = TNamedGroupKind.Hybrid, 'SecP256r1MLKEM768 kind');
  CheckTrue(LComposition.KeyAgreement = TKeyAgreementAlgorithm.SECP256R1,
    'SecP256r1MLKEM768 agreement');
  CheckTrue(LComposition.Kem = TKemAlgorithm.ML_KEM_768, 'SecP256r1MLKEM768 kem');
end;

procedure TTestNamedGroups.TestCatalogCompositionAgreesWithTheBuiltGroups;
var
  LGroup: INamedGroup;
  LComposition: TNamedGroupComposition;
begin
  // only the two hybrid rows are independent evidence: every other group reads its composition
  // from the same table, while a hybrid derives its own from its legs
  CheckEquals(7, System.Length(TNamedGroups.CreateDefaultRegistry(Crypto).Items),
    'the default registry holds every built-in group');
  for LGroup in TNamedGroups.CreateDefaultRegistry(Crypto).Items do
  begin
    CheckTrue(TNamedGroupCatalog.TryComposition(LGroup.Code, LComposition),
      LGroup.Name + ' is in the catalog');
    CheckTrue(LGroup.Composition.Kind = LComposition.Kind, LGroup.Name + ' kind');
    if LComposition.Kind <> TNamedGroupKind.Kem then
      CheckTrue(LGroup.Composition.KeyAgreement = LComposition.KeyAgreement,
        LGroup.Name + ' agreement');
    if LComposition.Kind <> TNamedGroupKind.Ecdhe then
      CheckTrue(LGroup.Composition.Kem = LComposition.Kem, LGroup.Name + ' kem');
  end;
end;

procedure TTestNamedGroups.TestCatalogCompositionRefusesAnUnknownCode;
var
  LComposition: TNamedGroupComposition;
begin
  CheckFalse(TNamedGroupCatalog.TryComposition($FFFF, LComposition),
    'a code outside the built-in groups');
  CheckFalse(TNamedGroupCatalog.TryComposition(0, LComposition), 'code zero');
end;

procedure TTestNamedGroups.TestNistEcdhRefusesNamesThatAreNotPlainEcdhe;
begin
  CheckNistEcdhRefused('ML-KEM-768', 'a KEM name is not an ECDHE group');
  CheckNistEcdhRefused('X25519MLKEM768', 'a hybrid name is not an ECDHE group');
  CheckNistEcdhRefused('secp999r1', 'an unknown name is not a group');
end;

procedure TTestNamedGroups.CheckNistEcdhRefused(const AName, AMsg: string);
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    TNamedGroups.CreateNistEcdh(Crypto, AName);
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, AMsg);
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestNamedGroups);
{$ELSE}
  RegisterTest(TTestNamedGroups.Suite);
{$ENDIF FPC}

end.
