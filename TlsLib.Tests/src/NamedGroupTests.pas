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
  TlpCryptoAlgorithms,
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
  published
    procedure TestX25519Rfc7748Kat;
    procedure TestX25519Agreement;
    procedure TestMlKem768Agreement;
    procedure TestHybridAgreement;
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

procedure TTestNamedGroups.TestMlKem768Agreement;
begin
  CheckAgreement(TNamedGroups.CreateMlKem768(Provider), 32);
end;

procedure TTestNamedGroups.TestHybridAgreement;
begin
  // shared secret = ML-KEM-768 secret (32) || X25519 secret (32)
  CheckAgreement(TNamedGroups.CreateX25519MlKem768(Provider), 64);
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
