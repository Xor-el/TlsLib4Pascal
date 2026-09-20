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
  TlpAlertMapping,
  TlpTlsLibExceptions,
  TlpISecretBuffer,
  TlpSecretBuffer,
  TlpArrayUtilities,
  TlpCryptoDomainTypes,
  TlpICryptoProvider,
  TlpDefaultCryptoProvider,
  TlpOSCryptoProvider,
  TlpINamedGroup,
  TlpNamedGroups,
  TlpNegotiationTypes,
  TlsLibTestBase;

type
  TTestNamedGroups = class(TTlsLibAlgorithmTestCase)
  private
    function SecretBytes(const ASecret: ISecretBuffer): TBytes;
    function Zeros(ALength: Int32): TBytes;
    // full KEM round-trip: A generates, B encapsulates, A decapsulates, secrets match
    procedure CheckAgreement(const AGroup: INamedGroup; AExpectedSecretLen: Int32);
    /// <summary>Decapsulate on ABadShare must reject with a contained exception that
    /// maps to illegal_parameter (no backend exception may escape the group).</summary>
    procedure CheckDecapIllegalParameter(const AGroup: INamedGroup;
      const APriv: ISecretBuffer; const ABadShare: TBytes; const AMsg: string);
    // export a fresh key's raw scalar, re-import it, and prove the derived public and
    // the resulting agreement are identical - the neutral-currency seam HPKE relies on
    procedure CheckKeyImportRoundTrip(AAlgorithm: TKeyAgreementAlgorithm);
    // a Static-usage agreement (full scalar blinding, for a long-lived recipient key)
    // must yield the same secret as the Ephemeral one: the blind is r*n, so [k+r*n]P = [k]P
    procedure CheckStaticUsageAgreesLikeEphemeral(AAlgorithm: TKeyAgreementAlgorithm);
    // import an UNCLAMPED external X25519 scalar (RFC 7748 6.1 Alice) and prove the derived
    // public is the RFC's published value - the seam an external HPKE/ECH key crosses
    procedure CheckUnclampedScalarImport(const AProvider: ICryptoProvider);
    // pins a hybrid's wire layout: split the client share at the claimed boundary, encapsulate
    // each leg standalone, reassemble the ciphertext in the claimed order, and prove the hybrid
    // decapsulates to the concatenation in that same order - a flipped KEM/classical order fails
    procedure CheckHybridOrder(const AHybrid, AClassical, AKem: INamedGroup;
      AClassicalShareBytes, AKemEncapsBytes: Int32; AKemFirst: Boolean);
  published
    procedure TestX25519Rfc7748Kat;
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
    procedure TestNistDecapsulateRejectsOffCurvePoint;
    procedure TestHybridDecapsulateRejectsShortCiphertext;
    procedure TestRegistry;
    procedure TestClassicalRegistryOmitsPostQuantum;
    procedure TestGroupKindClassifiesEcdheKemHybrid;
    procedure TestOnlyEcdheGroupsAreTls12Eligible;
    procedure TestKeyImportExportRoundTrip;
    procedure TestStaticUsageAgreesLikeEphemeral;
    procedure TestX25519ImportUnclampedScalar;
    procedure TestSystemX25519ImportUnclampedScalar;
    procedure TestSystemHybridAgreement;
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
  LPrivA: ISecretBuffer;
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
  LGroup: INamedGroup;
  LSecret: ISecretBuffer;
begin
  LVec := LoadVectorFields('Crypto/Ecdh/X25519Rfc7748.txt');
  try
    LGroup := TNamedGroups.CreateX25519(Provider);
    // Decapsulate is ECDH(scalar, u), the raw RFC 7748 scalar multiplication
    LGroup.Decapsulate(TSecretBuffer.From(DecodeHex(LVec.Values['scalar'])),
      DecodeHex(LVec.Values['u']), LSecret);
    CheckEqualBytes('X25519 RFC 7748', DecodeHex(LVec.Values['output']),
      SecretBytes(LSecret));
  finally
    LVec.Free;
  end;
end;

procedure TTestNamedGroups.TestX25519Agreement;
begin
  CheckAgreement(TNamedGroups.CreateX25519(Provider), 32);
end;

procedure TTestNamedGroups.CheckKeyImportRoundTrip(
  AAlgorithm: TKeyAgreementAlgorithm);
var
  LKa: IKeyAgreement;
  LPriv, LScalar, LPriv2, LPeerPriv: ISecretBuffer;
  LPub, LPub2, LPeerPub: TBytes;
begin
  LKa := Provider.Primitives.CreateKeyAgreement(AAlgorithm);
  LKa.GenerateKeyPair(LPriv, LPub);
  // export the raw scalar and re-import it; the derived public must match the original
  LScalar := LKa.ExportPrivateKey(LPriv);
  LPriv2 := LKa.ImportPrivateKey(LScalar, LPub2);
  CheckEqualBytes(LKa.Name + ' import derives the same public', LPub, LPub2);
  // the re-imported key agrees identically with a peer (functionally the same key)
  LKa.GenerateKeyPair(LPeerPriv, LPeerPub);
  CheckEqualBytes(LKa.Name + ' re-imported key agrees identically',
    SecretBytes(LKa.Agree(LPriv, LPeerPub, TKeyAgreementUsage.Ephemeral)),
    SecretBytes(LKa.Agree(LPriv2, LPeerPub, TKeyAgreementUsage.Ephemeral)));
end;

procedure TTestNamedGroups.CheckStaticUsageAgreesLikeEphemeral(
  AAlgorithm: TKeyAgreementAlgorithm);
var
  LKa: IKeyAgreement;
  LPriv, LPeerPriv: ISecretBuffer;
  LPub, LPeerPub: TBytes;
begin
  LKa := Provider.Primitives.CreateKeyAgreement(AAlgorithm);
  LKa.GenerateKeyPair(LPriv, LPub);
  LKa.GenerateKeyPair(LPeerPriv, LPeerPub);
  CheckEqualBytes(LKa.Name + ' static usage agrees like ephemeral',
    SecretBytes(LKa.Agree(LPriv, LPeerPub, TKeyAgreementUsage.Ephemeral)),
    SecretBytes(LKa.Agree(LPriv, LPeerPub, TKeyAgreementUsage.Static)));
  // both parties reach the same secret under full blinding (DH is commutative)
  CheckEqualBytes(LKa.Name + ' static usage is commutative',
    SecretBytes(LKa.Agree(LPriv, LPeerPub, TKeyAgreementUsage.Static)),
    SecretBytes(LKa.Agree(LPeerPriv, LPub, TKeyAgreementUsage.Static)));
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
  const AProvider: ICryptoProvider);
const
  // RFC 7748 6.1: Alice's private scalar is unclamped (low bits set) - the shape of an
  // external HPKE/ECH key; import must clamp it and derive Alice's published public key
  ALICE_SK = '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a';
  ALICE_PK = '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a';
var
  LKa: IKeyAgreement;
  LPub: TBytes;
begin
  LKa := AProvider.Primitives.CreateKeyAgreement(TKeyAgreementAlgorithm.X25519);
  LKa.ImportPrivateKey(TSecretBuffer.From(DecodeHex(ALICE_SK)), LPub);
  CheckEqualBytes('X25519 unclamped import derives the RFC 7748 public',
    DecodeHex(ALICE_PK), LPub);
end;

procedure TTestNamedGroups.TestX25519ImportUnclampedScalar;
begin
  CheckUnclampedScalarImport(Provider);
end;

procedure TTestNamedGroups.TestSystemX25519ImportUnclampedScalar;
begin
  // the OS-native overlay: exercises the native X25519 import where present, portable
  // fallback elsewhere, so the KAT holds on every host while guarding the native clamp
  CheckUnclampedScalarImport(
    TOSCryptoProvider.Compose(TDefaultCryptoProvider.Create as ICryptoProvider));
end;

procedure TTestNamedGroups.TestMlKem768Agreement;
begin
  CheckAgreement(TNamedGroups.CreateMlKem768(Provider), 32);
end;

procedure TTestNamedGroups.TestSystemHybridAgreement;
var
  LProvider: ICryptoProvider;
begin
  // the OS-native overlay: both hybrids compose over its primitives (P-256/X25519 + ML-KEM-768),
  // native where CNG serves them and portable otherwise, so the round-trip holds on every host
  LProvider := TOSCryptoProvider.Compose(TDefaultCryptoProvider.Create as ICryptoProvider);
  CheckAgreement(TNamedGroups.CreateX25519MlKem768(LProvider), 64);
  CheckAgreement(TNamedGroups.CreateSecP256r1MlKem768(LProvider), 64);
end;

procedure TTestNamedGroups.TestHybridAgreement;
begin
  // shared secret = ML-KEM-768 secret (32) || X25519 secret (32)
  CheckAgreement(TNamedGroups.CreateX25519MlKem768(Provider), 64);
end;

procedure TTestNamedGroups.TestSecP256r1MlKem768Agreement;
begin
  // shared secret = P-256 ECDH secret (32) || ML-KEM-768 secret (32) (RFC 10024)
  CheckAgreement(TNamedGroups.CreateSecP256r1MlKem768(Provider), 64);
end;

procedure TTestNamedGroups.CheckHybridOrder(const AHybrid, AClassical,
  AKem: INamedGroup; AClassicalShareBytes, AKemEncapsBytes: Int32;
  AKemFirst: Boolean);
var
  LPriv: ISecretBuffer;
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
  CheckHybridOrder(TNamedGroups.CreateX25519MlKem768(Provider),
    TNamedGroups.CreateX25519(Provider), TNamedGroups.CreateMlKem768(Provider),
    32, 1184, True);
  CheckHybridOrder(TNamedGroups.CreateSecP256r1MlKem768(Provider),
    TNamedGroups.CreateNistEcdh(Provider, 'secp256r1'),
    TNamedGroups.CreateMlKem768(Provider), 65, 1184, False);
end;

procedure TTestNamedGroups.TestSecP256r1MlKem768DecapsulateRejectsShortCiphertext;
var
  LGroup: INamedGroup;
  LPriv: ISecretBuffer;
  LPub: TBytes;
begin
  LGroup := TNamedGroups.CreateSecP256r1MlKem768(Provider);
  LGroup.GenerateKeyPair(LPriv, LPub);
  // far shorter than the 65 + 1088 hybrid ciphertext; slicing must not reach the backend
  CheckDecapIllegalParameter(LGroup, LPriv, Zeros(100),
    'a short hybrid ciphertext is rejected as illegal_parameter');
end;

procedure TTestNamedGroups.TestNistAgreement;
begin
  CheckAgreement(TNamedGroups.CreateNistEcdh(Provider, 'secp256r1'), 32);
  CheckAgreement(TNamedGroups.CreateNistEcdh(Provider, 'secp384r1'), 48);
  CheckAgreement(TNamedGroups.CreateNistEcdh(Provider, 'secp521r1'), 66);
end;

procedure TTestNamedGroups.TestNistValidationRejectsBadPoints;
var
  LGroup: INamedGroup;
  LPriv: ISecretBuffer;
  LPub, LOffCurve, LCompressed: TBytes;
begin
  LGroup := TNamedGroups.CreateNistEcdh(Provider, 'secp256r1');
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
  // the uncompressed form (RFC 8446 4.2.8.2, RFC 8422 5.1.2), though the curve decodes it
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
  LGroup := TNamedGroups.CreateX25519(Provider);
  CheckFalse(LGroup.ValidatePeerShare(DecodeHex('0011')), 'short rejected');
  CheckFalse(LGroup.ValidatePeerShare(Zeros(31)), '31 bytes rejected');
  CheckTrue(LGroup.ValidatePeerShare(Zeros(32)), 'any 32 bytes accepted');
end;

procedure TTestNamedGroups.TestX25519RejectsAllZeroPeerShare;
var
  LGroup: INamedGroup;
  LPriv, LSecret: ISecretBuffer;
  LPub: TBytes;
  LRaised: Boolean;
begin
  // an all-zero u-coordinate is a small-order point: the agreement yields an
  // all-zero (non-contributory) shared secret, which must be refused
  LGroup := TNamedGroups.CreateX25519(Provider);
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
  LPriv: ISecretBuffer;
  LPub: TBytes;
begin
  LGroup := TNamedGroups.CreateMlKem768(Provider);
  CheckFalse(LGroup.ValidatePeerShare(DecodeHex('0011')), 'short rejected');
  CheckFalse(LGroup.ValidatePeerShare(Zeros(1183)), 'wrong length rejected');
  LGroup.GenerateKeyPair(LPriv, LPub);
  CheckEquals(1184, System.Length(LPub), 'encaps key size');
  CheckTrue(LGroup.ValidatePeerShare(LPub), 'valid encaps key accepted');
end;

procedure TTestNamedGroups.CheckDecapIllegalParameter(const AGroup: INamedGroup;
  const APriv: ISecretBuffer; const ABadShare: TBytes; const AMsg: string);
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
  LPriv: ISecretBuffer;
  LPub, LBad: TBytes;
begin
  LGroup := TNamedGroups.CreateNistEcdh(Provider, 'secp256r1');
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
  LPriv: ISecretBuffer;
  LPub: TBytes;
begin
  LGroup := TNamedGroups.CreateX25519MlKem768(Provider);
  LGroup.GenerateKeyPair(LPriv, LPub);
  // far shorter than the 1088 + 32 hybrid ciphertext; slicing must not reach the backend
  CheckDecapIllegalParameter(LGroup, LPriv, Zeros(100),
    'a short hybrid ciphertext is rejected as illegal_parameter');
end;

procedure TTestNamedGroups.TestRegistry;
var
  LReg: INamedGroupRegistry;
  LGroup: INamedGroup;
begin
  LReg := TNamedGroups.CreateDefaultRegistry(Provider);
  CheckTrue(LReg.Contains(TNamedGroupCatalog.X25519), 'has X25519');
  CheckTrue(LReg.Contains(TNamedGroupCatalog.X25519MlKem768), 'has the hybrid');
  CheckTrue(LReg.Contains(TNamedGroupCatalog.SecP256r1MlKem768), 'has the P-256 hybrid');
  CheckTrue(LReg.TryGet(TNamedGroupCatalog.X25519, LGroup), 'lookup by code');
  CheckEquals('X25519', LGroup.Name, 'get returns the group');
  LReg.Prune(TNamedGroupCatalog.Secp521r1);
  CheckFalse(LReg.Contains(TNamedGroupCatalog.Secp521r1), 'pruned entry gone');
  LReg.Add(TNamedGroups.CreateNistEcdh(Provider, 'secp521r1'));
  CheckTrue(LReg.Contains(TNamedGroupCatalog.Secp521r1), 're-added');
  CheckFalse(LReg.TryGet($FFFF, LGroup), 'unknown code is not found');
end;

procedure TTestNamedGroups.TestClassicalRegistryOmitsPostQuantum;
var
  LReg: INamedGroupRegistry;
begin
  // the classical registry is the default minus the post-quantum hybrids, so a ClientHello
  // driven off it carries no ~1KB ML-KEM key share (the constrained-path escape hatch)
  LReg := TNamedGroups.CreateClassicalRegistry(Provider);
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
  CheckTrue(TNamedGroups.CreateX25519(Provider).Kind = TNamedGroupKind.Ecdhe,
    'X25519 is classical ECDHE');
  CheckTrue(TNamedGroups.CreateNistEcdh(Provider, 'secp256r1').Kind =
    TNamedGroupKind.Ecdhe, 'secp256r1 is classical ECDHE');
  CheckTrue(TNamedGroups.CreateMlKem768(Provider).Kind = TNamedGroupKind.Kem,
    'ML-KEM-768 is a KEM');
  CheckTrue(TNamedGroups.CreateX25519MlKem768(Provider).Kind =
    TNamedGroupKind.Hybrid, 'X25519MLKEM768 is a hybrid');
  CheckTrue(TNamedGroups.CreateSecP256r1MlKem768(Provider).Kind =
    TNamedGroupKind.Hybrid, 'SecP256r1MLKEM768 is a hybrid');
end;

procedure TTestNamedGroups.TestOnlyEcdheGroupsAreTls12Eligible;
var
  LReg: INamedGroupRegistry;
  LGroup: INamedGroup;
begin
  // the hybrid and pure-KEM groups are excluded from a TLS 1.2 handshake: only
  // Kind = Ecdhe is eligible (the filter the 1.2 negotiation applies)
  LReg := TNamedGroups.CreateDefaultRegistry(Provider);
  CheckTrue(LReg.TryGet(TNamedGroupCatalog.X25519MlKem768, LGroup), 'hybrid present');
  CheckFalse(LGroup.Kind = TNamedGroupKind.Ecdhe, 'the hybrid is not 1.2-eligible');
  CheckTrue(LReg.TryGet(TNamedGroupCatalog.MlKem768, LGroup), 'ML-KEM present');
  CheckFalse(LGroup.Kind = TNamedGroupKind.Ecdhe, 'ML-KEM is not 1.2-eligible');
  CheckTrue(LReg.TryGet(TNamedGroupCatalog.Secp256r1, LGroup), 'secp256r1 present');
  CheckTrue(LGroup.Kind = TNamedGroupKind.Ecdhe, 'secp256r1 is 1.2-eligible');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestNamedGroups);
{$ELSE}
  RegisterTest(TTestNamedGroups.Suite);
{$ENDIF FPC}

end.
