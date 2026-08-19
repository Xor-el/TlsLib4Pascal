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
  TlpCryptoAlgorithms,
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
    /// <summary>The X25519MLKEM768 hybrid combinator.</summary>
    class function CreateX25519MlKem768(const AProvider: ICryptoProvider): INamedGroup; static;
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
  X25519KeyBytes = 32;
  // FIPS 203 ML-KEM-768 fixed sizes (the X25519MLKEM768 wire layout)
  MlKem768EncapsulationKeyBytes = 1184;
  MlKem768CiphertextBytes = 1088;

resourcestring
  SInvalidPeerShare = 'invalid peer key share for group %s';

type
  // wraps a key agreement (Diffie-Hellman) as a KEM-shaped group: the ciphertext
  // is a fresh ephemeral public value.
  TKeyAgreementGroup = class(TInterfacedObject, INamedGroup)
  strict private
  var
    FAgreement: IKeyAgreement;
    FCode: UInt16;
  public
    constructor Create(const AAgreement: IKeyAgreement; ACode: UInt16);
    function Code: UInt16;
    function Name: string;
    function Kind: TNamedGroupKind;
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
    FKem: IKem;
    FCode: UInt16;
  public
    constructor Create(const AKem: IKem; ACode: UInt16);
    function Code: UInt16;
    function Name: string;
    function Kind: TNamedGroupKind;
    procedure GenerateKeyPair(out APriv: ISecretBuffer; out APubShare: TBytes);
    procedure Encapsulate(const APeerPub: TBytes; out ACiphertext: TBytes;
      out ASharedSecret: ISecretBuffer);
    procedure Decapsulate(const APriv: ISecretBuffer; const ACiphertext: TBytes;
      out ASharedSecret: ISecretBuffer);
    function ValidatePeerShare(const AShare: TBytes): Boolean;
  end;

  // combinator: shares/ciphertext/secret concatenate ML-KEM then X25519.
  TX25519MlKem768Group = class(TInterfacedObject, INamedGroup)
  strict private
  var
    FX25519: INamedGroup;
    FMlKem: INamedGroup;
  public
    constructor Create(const AProvider: ICryptoProvider);
    function Code: UInt16;
    function Name: string;
    function Kind: TNamedGroupKind;
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

constructor TKeyAgreementGroup.Create(const AAgreement: IKeyAgreement; ACode: UInt16);
begin
  inherited Create;
  FAgreement := AAgreement;
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
  Result := TNamedGroupKind.Ecdhe;
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

constructor TKemGroup.Create(const AKem: IKem; ACode: UInt16);
begin
  inherited Create;
  FKem := AKem;
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
  Result := TNamedGroupKind.Kem;
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

{ TX25519MlKem768Group }

constructor TX25519MlKem768Group.Create(const AProvider: ICryptoProvider);
begin
  inherited Create;
  FX25519 := TKeyAgreementGroup.Create(AProvider.CreateKeyAgreement(TKeyAgreementAlgorithm.X25519),
    TNamedGroupCatalog.X25519);
  FMlKem := TKemGroup.Create(AProvider.CreateKem(TKemAlgorithm.ML_KEM_768),
    TNamedGroupCatalog.MlKem768);
end;

function TX25519MlKem768Group.Code: UInt16;
begin
  Result := TNamedGroupCatalog.X25519MlKem768;
end;

function TX25519MlKem768Group.Name: string;
begin
  Result := 'X25519MLKEM768';
end;

function TX25519MlKem768Group.Kind: TNamedGroupKind;
begin
  Result := TNamedGroupKind.Hybrid;
end;

procedure TX25519MlKem768Group.GenerateKeyPair(out APriv: ISecretBuffer;
  out APubShare: TBytes);
var
  LXPriv, LMPriv: ISecretBuffer;
  LXPub, LMPub, LXPrivBytes, LMPrivBytes, LPrivBytes: TBytes;
begin
  FX25519.GenerateKeyPair(LXPriv, LXPub);
  FMlKem.GenerateKeyPair(LMPriv, LMPub);
  APubShare := TArrayUtilities.Concat(LMPub, LXPub);
  // private (internal, off-wire): X25519 first, then ML-KEM
  LXPrivBytes := LXPriv.ToBytes;
  LMPrivBytes := LMPriv.ToBytes;
  LPrivBytes := TArrayUtilities.Concat(LXPrivBytes, LMPrivBytes);
  try
    APriv := TSecretBuffer.From(LPrivBytes);
  finally
    TSecureMemory.WipeBytes(LPrivBytes);
    TSecureMemory.WipeBytes(LXPrivBytes);
    TSecureMemory.WipeBytes(LMPrivBytes);
  end;
end;

procedure TX25519MlKem768Group.Encapsulate(const APeerPub: TBytes;
  out ACiphertext: TBytes; out ASharedSecret: ISecretBuffer);
var
  LMPub, LXPub, LMCt, LXCt, LMSsBytes, LXSsBytes, LSsBytes: TBytes;
  LMSs, LXSs: ISecretBuffer;
begin
  if not ValidatePeerShare(APeerPub) then
    raise EPeerInputTlsLibException.CreateResFmt(@SInvalidPeerShare, [Name]);
  LMPub := System.Copy(APeerPub, 0, MlKem768EncapsulationKeyBytes);
  LXPub := System.Copy(APeerPub, MlKem768EncapsulationKeyBytes, X25519KeyBytes);
  FMlKem.Encapsulate(LMPub, LMCt, LMSs);
  FX25519.Encapsulate(LXPub, LXCt, LXSs);
  ACiphertext := TArrayUtilities.Concat(LMCt, LXCt);
  LMSsBytes := LMSs.ToBytes;
  LXSsBytes := LXSs.ToBytes;
  LSsBytes := TArrayUtilities.Concat(LMSsBytes, LXSsBytes);
  try
    ASharedSecret := TSecretBuffer.From(LSsBytes);
  finally
    TSecureMemory.WipeBytes(LSsBytes);
    TSecureMemory.WipeBytes(LMSsBytes);
    TSecureMemory.WipeBytes(LXSsBytes);
  end;
end;

procedure TX25519MlKem768Group.Decapsulate(const APriv: ISecretBuffer;
  const ACiphertext: TBytes; out ASharedSecret: ISecretBuffer);
var
  LPrivBytes, LXPrivBytes, LMPrivBytes, LMCt, LXCt, LMSsBytes, LXSsBytes,
    LSsBytes: TBytes;
  LXPriv, LMPriv, LMSs, LXSs: ISecretBuffer;
begin
  // reject a short/long ciphertext before the fixed-offset slices reach the backend
  if System.Length(ACiphertext) <> MlKem768CiphertextBytes + X25519KeyBytes then
    raise EPeerInputTlsLibException.CreateResFmt(@SInvalidPeerShare, [Name]);
  LPrivBytes := APriv.ToBytes;
  LXPrivBytes := System.Copy(LPrivBytes, 0, X25519KeyBytes);
  LMPrivBytes := System.Copy(LPrivBytes, X25519KeyBytes,
    System.Length(LPrivBytes) - X25519KeyBytes);
  try
    LXPriv := TSecretBuffer.From(LXPrivBytes);
    LMPriv := TSecretBuffer.From(LMPrivBytes);
  finally
    TSecureMemory.WipeBytes(LPrivBytes);
    TSecureMemory.WipeBytes(LXPrivBytes);
    TSecureMemory.WipeBytes(LMPrivBytes);
  end;
  LMCt := System.Copy(ACiphertext, 0, MlKem768CiphertextBytes);
  LXCt := System.Copy(ACiphertext, MlKem768CiphertextBytes, X25519KeyBytes);
  FMlKem.Decapsulate(LMPriv, LMCt, LMSs);
  FX25519.Decapsulate(LXPriv, LXCt, LXSs);
  LMSsBytes := LMSs.ToBytes;
  LXSsBytes := LXSs.ToBytes;
  LSsBytes := TArrayUtilities.Concat(LMSsBytes, LXSsBytes);
  try
    ASharedSecret := TSecretBuffer.From(LSsBytes);
  finally
    TSecureMemory.WipeBytes(LSsBytes);
    TSecureMemory.WipeBytes(LMSsBytes);
    TSecureMemory.WipeBytes(LXSsBytes);
  end;
end;

function TX25519MlKem768Group.ValidatePeerShare(const AShare: TBytes): Boolean;
begin
  Result := (System.Length(AShare) = MlKem768EncapsulationKeyBytes + X25519KeyBytes) and
    FMlKem.ValidatePeerShare(System.Copy(AShare, 0, MlKem768EncapsulationKeyBytes)) and
    FX25519.ValidatePeerShare(System.Copy(AShare, MlKem768EncapsulationKeyBytes, X25519KeyBytes));
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
  Result := TKeyAgreementGroup.Create(AProvider.CreateKeyAgreement(TKeyAgreementAlgorithm.X25519),
    TNamedGroupCatalog.X25519);
end;

class function TNamedGroups.CreateNistEcdh(const AProvider: ICryptoProvider;
  const ACurveName: string): INamedGroup;
var
  LCode: UInt16;
  LAlg: TKeyAgreementAlgorithm;
begin
  // the group name is the curve name; an unknown curve maps to code 0 (non-negotiable)
  TNamedGroupCatalog.TryCode(ACurveName, LCode);
  // the curve name resolves to the key-agreement enum (secp256r1 -> SECP256R1)
  TEnumUtilities.TryGetEnumValue<TKeyAgreementAlgorithm>(ACurveName, LAlg);
  Result := TKeyAgreementGroup.Create(AProvider.CreateKeyAgreement(LAlg), LCode);
end;

class function TNamedGroups.CreateMlKem768(const AProvider: ICryptoProvider): INamedGroup;
begin
  Result := TKemGroup.Create(AProvider.CreateKem(TKemAlgorithm.ML_KEM_768),
    TNamedGroupCatalog.MlKem768);
end;

class function TNamedGroups.CreateX25519MlKem768(const AProvider: ICryptoProvider): INamedGroup;
begin
  Result := TX25519MlKem768Group.Create(AProvider);
end;

class function TNamedGroups.CreateDefaultRegistry(const AProvider: ICryptoProvider): INamedGroupRegistry;
begin
  Result := TNamedGroupRegistry.Create;
  Result.Add(CreateX25519(AProvider));
  Result.Add(CreateX25519MlKem768(AProvider));
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
