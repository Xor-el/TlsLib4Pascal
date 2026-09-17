{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpNamedGroups;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpArrayUtilities,
  TlpCodeKeyedRegistry,
  TlpCryptoDomainTypes,
  TlpEnumUtilities,
  TlpNegotiationTypes,
  TlpICryptoProvider,
  TlpINamedGroup,
  TlpISecretBuffer,
  TlpSecretBuffer,
  TlpSecureMemory,
  TlpTlsLibExceptions;

type
  /// <summary>
  /// Factory for the named groups and a default registry. Every group is built
  /// over primitives vended by the supplied provider, so a different crypto
  /// backend flows straight through. The concrete group classes stay private to
  /// this unit; callers hold <see cref="INamedGroup" />.
  /// </summary>
  TNamedGroups = class sealed(TObject)
  public
    /// <summary>X25519 (key agreement wrapped as a KEM).</summary>
    class function CreateX25519(const AProvider: ICryptoProvider): INamedGroup; static;
    /// <summary>A NIST prime-curve ECDH group (e.g. "secp256r1").</summary>
    class function CreateNistEcdh(const AProvider: ICryptoProvider;
      const ACurveName: string): INamedGroup; static;
    /// <summary>ML-KEM-768 (post-quantum KEM).</summary>
    class function CreateMlKem768(const AProvider: ICryptoProvider): INamedGroup; static;
    /// <summary>The X25519MLKEM768 hybrid (ML-KEM-768 first).</summary>
    class function CreateX25519MlKem768(const AProvider: ICryptoProvider): INamedGroup; static;
    /// <summary>The SecP256r1MLKEM768 hybrid (P-256 ECDH first, RFC 10024).</summary>
    class function CreateSecP256r1MlKem768(const AProvider: ICryptoProvider): INamedGroup; static;
    /// <summary>A registry pre-loaded with the default groups.</summary>
    class function CreateDefaultRegistry(const AProvider: ICryptoProvider): INamedGroupRegistry; static;
    /// <summary>The default registry with the post-quantum groups removed - classical ECDHE only.
    /// A post-quantum key share enlarges the ClientHello enough to fail on some constrained paths
    /// (reduced-MTU tunnels/VPNs, or middleboxes intolerant of a fragmented ClientHello); this
    /// trades post-quantum protection for a smaller ClientHello there. Install it with
    /// WithNamedGroups.</summary>
    class function CreateClassicalRegistry(const AProvider: ICryptoProvider): INamedGroupRegistry; static;
  end;

implementation

const
  X25519KeyBytes = 32; // X25519 raw public = private = shared-secret length (RFC 7748)
  SecP256r1ShareBytes = 65; // uncompressed SEC1 P-256 point: 0x04 || X(32) || Y(32)
  // FIPS 203 ML-KEM-768 fixed sizes, shared by both hybrids
  MlKem768EncapsulationKeyBytes = 1184;
  MlKem768CiphertextBytes = 1088;
  MlKem768PrivateKeyBytes = 2400; // decapsulation key; fixed, so it splits the stored private

resourcestring
  SInvalidPeerShare = 'invalid peer key share for group %s';
  SUnknownCurve = 'unknown named-group curve "%s"';

type
  // wraps a key agreement (Diffie-Hellman) as a KEM-shaped group: the ciphertext
  // is a fresh ephemeral public value.
  TKeyAgreementGroup = class(TInterfacedObject, INamedGroup)
  strict private
  var
    FComposition: TNamedGroupComposition;
    FAgreement: IKeyAgreement;
    FCode: UInt16;
  public
    constructor Create(const AProvider: ICryptoProvider;
      AAlgorithm: TKeyAgreementAlgorithm; ACode: UInt16);
    function Code: UInt16;
    function Name: string;
    function Kind: TNamedGroupKind;
    function Composition: TNamedGroupComposition;
    procedure GenerateKeyPair(out APriv: ISecretBuffer; out APubShare: TBytes);
    procedure Encapsulate(const APeerPub: TBytes; out ACiphertext: TBytes;
      out ASharedSecret: ISecretBuffer);
    procedure Decapsulate(const APriv: ISecretBuffer; const ACiphertext: TBytes;
      out ASharedSecret: ISecretBuffer);
    function ValidatePeerShare(const AShare: TBytes): Boolean;
  end;

  // wraps a KEM primitive as a group.
  TKemGroup = class(TInterfacedObject, INamedGroup)
  strict private
  var
    FComposition: TNamedGroupComposition;
    FKem: IKem;
    FCode: UInt16;
  public
    constructor Create(const AProvider: ICryptoProvider;
      AAlgorithm: TKemAlgorithm; ACode: UInt16);
    function Code: UInt16;
    function Name: string;
    function Kind: TNamedGroupKind;
    function Composition: TNamedGroupComposition;
    procedure GenerateKeyPair(out APriv: ISecretBuffer; out APubShare: TBytes);
    procedure Encapsulate(const APeerPub: TBytes; out ACiphertext: TBytes;
      out ASharedSecret: ISecretBuffer);
    procedure Decapsulate(const APriv: ISecretBuffer; const ACiphertext: TBytes;
      out ASharedSecret: ISecretBuffer);
    function ValidatePeerShare(const AShare: TBytes): Boolean;
  end;

  // which of a hybrid's two legs is written first on the wire (RFC 10024 fixes it per group)
  THybridLegOrder = (KemFirst, ClassicalFirst);

  // combinator over a classical (DH-as-KEM) leg and a KEM leg (RFC 10024 PQ/T hybrid). The wire
  // layout is data: the fixed leg sizes and the leg order. That one order governs the client
  // share, the server ciphertext and the concatenated secret alike.
  THybridGroup = class(TInterfacedObject, INamedGroup)
  strict private
  var
    FComposition: TNamedGroupComposition;
    FClassical: INamedGroup;
    FKem: INamedGroup;
    FCode: UInt16;
    FName: string;
    FClassicalShareBytes: Int32;
    FKemEncapsKeyBytes: Int32;
    FKemCiphertextBytes: Int32;
    FKemPrivBytes: Int32;
    FOrder: THybridLegOrder;
    // the only two places FOrder is consulted
    function Join(const AClassical, AKem: TBytes): TBytes;
    procedure Split(const ABytes: TBytes; AClassicalLen, AKemLen: Int32;
      out AClassical, AKem: TBytes);
  public
    constructor Create(const AClassical, AKem: INamedGroup; ACode: UInt16;
      const AName: string; AClassicalShareBytes, AKemEncapsKeyBytes,
      AKemCiphertextBytes, AKemPrivBytes: Int32; AOrder: THybridLegOrder);
    function Code: UInt16;
    function Name: string;
    function Kind: TNamedGroupKind;
    function Composition: TNamedGroupComposition;
    procedure GenerateKeyPair(out APriv: ISecretBuffer; out APubShare: TBytes);
    procedure Encapsulate(const APeerPub: TBytes; out ACiphertext: TBytes;
      out ASharedSecret: ISecretBuffer);
    procedure Decapsulate(const APriv: ISecretBuffer; const ACiphertext: TBytes;
      out ASharedSecret: ISecretBuffer);
    function ValidatePeerShare(const AShare: TBytes): Boolean;
  end;

  TNamedGroupRegistry = class sealed(TCodeKeyedRegistry<INamedGroup>,
    INamedGroupRegistry)
  strict private
    class function CodeOf(const AGroup: INamedGroup): UInt16; static;
  public
    constructor Create;
  end;

{ TKeyAgreementGroup }

constructor TKeyAgreementGroup.Create(const AProvider: ICryptoProvider;
  AAlgorithm: TKeyAgreementAlgorithm; ACode: UInt16);
begin
  inherited Create;
  FComposition := TNamedGroupComposition.From(AAlgorithm);
  FAgreement := AProvider.Primitives.CreateKeyAgreement(FComposition.KeyAgreement);
  FCode := ACode;
end;

function TKeyAgreementGroup.Code: UInt16;
begin
  Result := FCode;
end;

function TKeyAgreementGroup.Name: string;
begin
  Result := FAgreement.Name;
end;

function TKeyAgreementGroup.Kind: TNamedGroupKind;
begin
  Result := FComposition.Kind;
end;

function TKeyAgreementGroup.Composition: TNamedGroupComposition;
begin
  Result := FComposition;
end;

procedure TKeyAgreementGroup.GenerateKeyPair(out APriv: ISecretBuffer;
  out APubShare: TBytes);
begin
  FAgreement.GenerateKeyPair(APriv, APubShare);
end;

procedure TKeyAgreementGroup.Encapsulate(const APeerPub: TBytes;
  out ACiphertext: TBytes; out ASharedSecret: ISecretBuffer);
var
  LEphPriv: ISecretBuffer;
begin
  if not ValidatePeerShare(APeerPub) then
    raise EPeerInputTlsLibException.CreateResFmt(@SInvalidPeerShare, [Name]);
  // a fresh ephemeral pair; the ciphertext is its public value
  FAgreement.GenerateKeyPair(LEphPriv, ACiphertext);
  ASharedSecret := FAgreement.Agree(LEphPriv, APeerPub);
end;

procedure TKeyAgreementGroup.Decapsulate(const APriv: ISecretBuffer;
  const ACiphertext: TBytes; out ASharedSecret: ISecretBuffer);
begin
  // the ciphertext is the peer's ephemeral public value; validate it before the
  // agreement, symmetric with Encapsulate
  if not ValidatePeerShare(ACiphertext) then
    raise EPeerInputTlsLibException.CreateResFmt(@SInvalidPeerShare, [Name]);
  ASharedSecret := FAgreement.Agree(APriv, ACiphertext);
end;

function TKeyAgreementGroup.ValidatePeerShare(const AShare: TBytes): Boolean;
begin
  Result := FAgreement.ValidatePublicKey(AShare);
end;

{ TKemGroup }

constructor TKemGroup.Create(const AProvider: ICryptoProvider;
  AAlgorithm: TKemAlgorithm; ACode: UInt16);
begin
  inherited Create;
  FComposition := TNamedGroupComposition.From(AAlgorithm);
  FKem := AProvider.Primitives.CreateKem(FComposition.Kem);
  FCode := ACode;
end;

function TKemGroup.Code: UInt16;
begin
  Result := FCode;
end;

function TKemGroup.Name: string;
begin
  Result := FKem.Name;
end;

function TKemGroup.Kind: TNamedGroupKind;
begin
  Result := FComposition.Kind;
end;

function TKemGroup.Composition: TNamedGroupComposition;
begin
  Result := FComposition;
end;

procedure TKemGroup.GenerateKeyPair(out APriv: ISecretBuffer; out APubShare: TBytes);
begin
  FKem.GenerateKeyPair(APriv, APubShare);
end;

procedure TKemGroup.Encapsulate(const APeerPub: TBytes; out ACiphertext: TBytes;
  out ASharedSecret: ISecretBuffer);
begin
  if not ValidatePeerShare(APeerPub) then
    raise EPeerInputTlsLibException.CreateResFmt(@SInvalidPeerShare, [Name]);
  FKem.Encapsulate(APeerPub, ACiphertext, ASharedSecret);
end;

procedure TKemGroup.Decapsulate(const APriv: ISecretBuffer; const ACiphertext: TBytes;
  out ASharedSecret: ISecretBuffer);
begin
  FKem.Decapsulate(APriv, ACiphertext, ASharedSecret);
end;

function TKemGroup.ValidatePeerShare(const AShare: TBytes): Boolean;
begin
  Result := FKem.ValidatePublicKey(AShare);
end;

{ THybridGroup }

constructor THybridGroup.Create(const AClassical, AKem: INamedGroup; ACode: UInt16;
  const AName: string; AClassicalShareBytes, AKemEncapsKeyBytes,
  AKemCiphertextBytes, AKemPrivBytes: Int32; AOrder: THybridLegOrder);
begin
  inherited Create;
  FClassical := AClassical;
  FKem := AKem;
  FComposition := TNamedGroupComposition.From(AClassical.Composition.KeyAgreement,
    AKem.Composition.Kem);
  FCode := ACode;
  FName := AName;
  FClassicalShareBytes := AClassicalShareBytes;
  FKemEncapsKeyBytes := AKemEncapsKeyBytes;
  FKemCiphertextBytes := AKemCiphertextBytes;
  FKemPrivBytes := AKemPrivBytes;
  FOrder := AOrder;
end;

function THybridGroup.Join(const AClassical, AKem: TBytes): TBytes;
begin
  if FOrder = THybridLegOrder.KemFirst then
    Result := TArrayUtilities.Concat(AKem, AClassical)
  else
    Result := TArrayUtilities.Concat(AClassical, AKem);
end;

procedure THybridGroup.Split(const ABytes: TBytes; AClassicalLen, AKemLen: Int32;
  out AClassical, AKem: TBytes);
begin
  if FOrder = THybridLegOrder.KemFirst then
  begin
    AKem := System.Copy(ABytes, 0, AKemLen);
    AClassical := System.Copy(ABytes, AKemLen, AClassicalLen);
  end
  else
  begin
    AClassical := System.Copy(ABytes, 0, AClassicalLen);
    AKem := System.Copy(ABytes, AClassicalLen, AKemLen);
  end;
end;

function THybridGroup.Code: UInt16;
begin
  Result := FCode;
end;

function THybridGroup.Name: string;
begin
  Result := FName;
end;

function THybridGroup.Kind: TNamedGroupKind;
begin
  Result := FComposition.Kind;
end;

function THybridGroup.Composition: TNamedGroupComposition;
begin
  Result := FComposition;
end;

procedure THybridGroup.GenerateKeyPair(out APriv: ISecretBuffer;
  out APubShare: TBytes);
var
  LCPriv, LKPriv: ISecretBuffer;
  LCPub, LKPub, LCPrivBytes, LKPrivBytes, LPrivBytes: TBytes;
begin
  FClassical.GenerateKeyPair(LCPriv, LCPub);
  FKem.GenerateKeyPair(LKPriv, LKPub);
  APubShare := Join(LCPub, LKPub);
  // the private key stays classical || KEM off the wire, independent of the wire order
  LCPrivBytes := LCPriv.ToBytes;
  LKPrivBytes := LKPriv.ToBytes;
  LPrivBytes := TArrayUtilities.Concat(LCPrivBytes, LKPrivBytes);
  try
    APriv := TSecretBuffer.From(LPrivBytes);
  finally
    TSecureMemory.WipeBytes(LPrivBytes);
    TSecureMemory.WipeBytes(LCPrivBytes);
    TSecureMemory.WipeBytes(LKPrivBytes);
  end;
end;

procedure THybridGroup.Encapsulate(const APeerPub: TBytes;
  out ACiphertext: TBytes; out ASharedSecret: ISecretBuffer);
var
  LCPub, LKPub, LCCt, LKCt, LCSsBytes, LKSsBytes, LSsBytes: TBytes;
  LCSs, LKSs: ISecretBuffer;
begin
  if not ValidatePeerShare(APeerPub) then
    raise EPeerInputTlsLibException.CreateResFmt(@SInvalidPeerShare, [Name]);
  Split(APeerPub, FClassicalShareBytes, FKemEncapsKeyBytes, LCPub, LKPub);
  FClassical.Encapsulate(LCPub, LCCt, LCSs);
  FKem.Encapsulate(LKPub, LKCt, LKSs);
  ACiphertext := Join(LCCt, LKCt);
  LCSsBytes := LCSs.ToBytes;
  LKSsBytes := LKSs.ToBytes;
  LSsBytes := Join(LCSsBytes, LKSsBytes);
  try
    ASharedSecret := TSecretBuffer.From(LSsBytes);
  finally
    TSecureMemory.WipeBytes(LSsBytes);
    TSecureMemory.WipeBytes(LCSsBytes);
    TSecureMemory.WipeBytes(LKSsBytes);
  end;
end;

procedure THybridGroup.Decapsulate(const APriv: ISecretBuffer;
  const ACiphertext: TBytes; out ASharedSecret: ISecretBuffer);
var
  LPrivBytes, LCPrivBytes, LKPrivBytes, LCCt, LKCt, LCSsBytes, LKSsBytes,
    LSsBytes: TBytes;
  LClassicalLen: Int32;
  LCPriv, LKPriv, LCSs, LKSs: ISecretBuffer;
begin
  // reject a short/long ciphertext before the fixed-offset slices reach the backend
  if System.Length(ACiphertext) <> FClassicalShareBytes + FKemCiphertextBytes then
    raise EPeerInputTlsLibException.CreateResFmt(@SInvalidPeerShare, [Name]);
  LPrivBytes := APriv.ToBytes;
  // the stored key is classical || KEM; the classical half is whatever the provider produced (a
  // raw scalar or a backend key blob), so split off the fixed-length KEM tail, not a fixed head
  LClassicalLen := System.Length(LPrivBytes) - FKemPrivBytes;
  LCPrivBytes := System.Copy(LPrivBytes, 0, LClassicalLen);
  LKPrivBytes := System.Copy(LPrivBytes, LClassicalLen, FKemPrivBytes);
  try
    LCPriv := TSecretBuffer.From(LCPrivBytes);
    LKPriv := TSecretBuffer.From(LKPrivBytes);
  finally
    TSecureMemory.WipeBytes(LPrivBytes);
    TSecureMemory.WipeBytes(LCPrivBytes);
    TSecureMemory.WipeBytes(LKPrivBytes);
  end;
  Split(ACiphertext, FClassicalShareBytes, FKemCiphertextBytes, LCCt, LKCt);
  FClassical.Decapsulate(LCPriv, LCCt, LCSs);
  FKem.Decapsulate(LKPriv, LKCt, LKSs);
  LCSsBytes := LCSs.ToBytes;
  LKSsBytes := LKSs.ToBytes;
  LSsBytes := Join(LCSsBytes, LKSsBytes);
  try
    ASharedSecret := TSecretBuffer.From(LSsBytes);
  finally
    TSecureMemory.WipeBytes(LSsBytes);
    TSecureMemory.WipeBytes(LCSsBytes);
    TSecureMemory.WipeBytes(LKSsBytes);
  end;
end;

function THybridGroup.ValidatePeerShare(const AShare: TBytes): Boolean;
var
  LCPub, LKPub: TBytes;
begin
  if System.Length(AShare) <> FClassicalShareBytes + FKemEncapsKeyBytes then
    Exit(False);
  Split(AShare, FClassicalShareBytes, FKemEncapsKeyBytes, LCPub, LKPub);
  Result := FClassical.ValidatePeerShare(LCPub) and FKem.ValidatePeerShare(LKPub);
end;

{ TNamedGroupRegistry }

constructor TNamedGroupRegistry.Create;
begin
  inherited Create(CodeOf);
end;

class function TNamedGroupRegistry.CodeOf(const AGroup: INamedGroup): UInt16;
begin
  Result := AGroup.Code;
end;

{ TNamedGroups }

class function TNamedGroups.CreateX25519(const AProvider: ICryptoProvider): INamedGroup;
begin
  Result := TKeyAgreementGroup.Create(AProvider, TKeyAgreementAlgorithm.X25519,
    TNamedGroupCatalog.X25519);
end;

class function TNamedGroups.CreateNistEcdh(const AProvider: ICryptoProvider;
  const ACurveName: string): INamedGroup;
var
  LCode: UInt16;
  LAlg: TKeyAgreementAlgorithm;
  LHasCode, LHasAlg: Boolean;
begin
  // the group name is the curve name; it must resolve to both a wire codepoint and the
  // key-agreement enum (secp256r1 -> SECP256R1), else it is not a group we can build
  LHasCode := TNamedGroupCatalog.TryCode(ACurveName, LCode);
  LHasAlg := TEnumUtilities.TryGetEnumValue<TKeyAgreementAlgorithm>(ACurveName, LAlg);
  if (not LHasCode) or (not LHasAlg) then
    raise EArgumentTlsLibException.CreateResFmt(@SUnknownCurve, [ACurveName]);
  Result := TKeyAgreementGroup.Create(AProvider, LAlg, LCode);
end;

class function TNamedGroups.CreateMlKem768(const AProvider: ICryptoProvider): INamedGroup;
begin
  Result := TKemGroup.Create(AProvider, TKemAlgorithm.ML_KEM_768, TNamedGroupCatalog.MlKem768);
end;

class function TNamedGroups.CreateX25519MlKem768(const AProvider: ICryptoProvider): INamedGroup;
begin
  Result := THybridGroup.Create(CreateX25519(AProvider), CreateMlKem768(AProvider),
    TNamedGroupCatalog.X25519MlKem768, 'X25519MLKEM768', X25519KeyBytes,
    MlKem768EncapsulationKeyBytes, MlKem768CiphertextBytes, MlKem768PrivateKeyBytes,
    THybridLegOrder.KemFirst);
end;

class function TNamedGroups.CreateSecP256r1MlKem768(const AProvider: ICryptoProvider): INamedGroup;
begin
  Result := THybridGroup.Create(CreateNistEcdh(AProvider, 'secp256r1'),
    CreateMlKem768(AProvider), TNamedGroupCatalog.SecP256r1MlKem768, 'SecP256r1MLKEM768',
    SecP256r1ShareBytes, MlKem768EncapsulationKeyBytes, MlKem768CiphertextBytes,
    MlKem768PrivateKeyBytes, THybridLegOrder.ClassicalFirst);
end;

class function TNamedGroups.CreateDefaultRegistry(const AProvider: ICryptoProvider): INamedGroupRegistry;
begin
  Result := TNamedGroupRegistry.Create;
  Result.Add(CreateX25519(AProvider));
  Result.Add(CreateX25519MlKem768(AProvider));
  Result.Add(CreateSecP256r1MlKem768(AProvider));
  Result.Add(CreateMlKem768(AProvider));
  Result.Add(CreateNistEcdh(AProvider, 'secp256r1'));
  Result.Add(CreateNistEcdh(AProvider, 'secp384r1'));
  Result.Add(CreateNistEcdh(AProvider, 'secp521r1'));
end;

class function TNamedGroups.CreateClassicalRegistry(const AProvider: ICryptoProvider): INamedGroupRegistry;
var
  LDefault: INamedGroupRegistry;
  LGroup: INamedGroup;
begin
  // derived from the default registry with the post-quantum (KEM/hybrid) groups filtered out, so
  // a classical group added to CreateDefaultRegistry is carried here without a second hand-kept list
  Result := TNamedGroupRegistry.Create;
  LDefault := CreateDefaultRegistry(AProvider);
  for LGroup in LDefault.Items do
    if LGroup.Kind = TNamedGroupKind.Ecdhe then
      Result.Add(LGroup);
end;

end.
