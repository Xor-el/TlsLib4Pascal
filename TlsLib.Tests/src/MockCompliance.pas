{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit MockCompliance;

{$I ..\..\TlsLib\src\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpCryptoDomainTypes,
  TlpICryptoProvider,
  TlpISecretBuffer,
  TlpIKeyExchangePrivateKey,
  TlpINamedGroup,
  TlpISigningKey,
  TlpImportedCredential,
  TlpICryptoBackendReport,
  TlpSystemCryptoTypes,
  TlpSystemCryptoBase,
  TlpComplianceTypes,
  TlpIModuleAttestation,
  MockCryptoProvider,
  MockSystemCrypto,
  TlpTlsLibExceptions,
  TlsLibTestProviders;

type
  /// <summary>An <see cref="IModuleAttestation" /> that answers a fixed status and identity, so a
  /// test drives the module verdict on any host. It covers every crypto provider unless told
  /// not to. Never for production use.</summary>
  TFakeModuleAttestation = class sealed(TInterfacedObject, IModuleAttestation)
  strict private
  var
    FStatus: TModuleStatus;
    FIdentity: TModuleIdentity;
    FCovered: Boolean;
    FDisclosed: TArray<string>;
  public
    constructor Create(AStatus: TModuleStatus; const AIdentity: TModuleIdentity);
    /// <summary>Whether Covers answers True; True by default.</summary>
    property Covered: Boolean read FCovered write FCovered;
    /// <summary>What Disclosures answers; none by default.</summary>
    property Disclosed: TArray<string> read FDisclosed write FDisclosed;
    function Identity: TModuleIdentity;
    function Status(AStandard: TModuleStandard): TModuleStatus;
    function Describe: string;
    function Covers(const ACrypto: ICryptoProvider): Boolean;
    function Disclosures: TArray<string>;
  end;

  TComplianceHashSet = set of THashAlgorithm;

  /// <summary>A backend report that places every operation in the OS module except the entries
  /// it is told to keep portable (the AEADs at construction, the rest through the properties,
  /// all empty by default) and the KEMs, which no module serves. Never for production
  /// use.</summary>
  TFakeBackendReport = class sealed(TMarkedBackendReportBase)
  strict private
  var
    FPortableAeads: TComplianceAeadSet;
    FPortableRandom: Boolean;
    FPortableHashes: TComplianceHashSet;
    FPortableHmacs: TComplianceHashSet;
    FPortableCurves: TComplianceKeyAgreementSet;
    FPortableVerification: TComplianceSchemeSet;
    FNativePrf: Boolean;
    FComposedPrfHashes: TComplianceHashSet;
  public
    constructor Create(APortableAeads: TComplianceAeadSet);
    /// <summary>Whether the module serves the TLS 1.2 PRF itself; off, it is composed over the
    /// HMAC.</summary>
    property NativePrf: Boolean read FNativePrf write FNativePrf;
    /// <summary>The PRF hashes composed over the HMAC even while NativePrf is on.</summary>
    property ComposedPrfHashes: TComplianceHashSet read FComposedPrfHashes
      write FComposedPrfHashes;
    property PortableRandom: Boolean read FPortableRandom write FPortableRandom;
    property PortableHashes: TComplianceHashSet read FPortableHashes write FPortableHashes;
    property PortableHmacs: TComplianceHashSet read FPortableHmacs write FPortableHmacs;
    property PortableCurves: TComplianceKeyAgreementSet read FPortableCurves
      write FPortableCurves;
    property PortableVerification: TComplianceSchemeSet read FPortableVerification
      write FPortableVerification;
    function RandomBackend: TCryptoBackendEntry; override;
    function HashBackend(AAlgorithm: THashAlgorithm): TCryptoBackendEntry; override;
    function HmacBackend(AAlgorithm: THashAlgorithm): TCryptoBackendEntry; override;
    function AeadBackend(AAlgorithm: TAeadAlgorithm): TCryptoBackendEntry; override;
    function Tls12PrfBackend(AAlgorithm: THashAlgorithm): TCryptoBackendEntry; override;
    function KeyAgreementBackend(AAlgorithm: TKeyAgreementAlgorithm): TCryptoBackendEntry; override;
    function SigningBackend(AScheme: TSignatureScheme): TCryptoBackendEntry; override;
    function VerificationBackend(AScheme: TSignatureScheme): TCryptoBackendEntry; override;
    function Describe: string; override;
  end;

  /// <summary>A backend report that places everything in the OS module and answers every verifier
  /// as told, whatever marker it carries, so a test shows a decision follows the report and not
  /// the marker. Never for production use.</summary>
  TFakeVerifierReport = class sealed(TInterfacedObject, ICryptoBackendReport)
  strict private
  var
    FVerifiersInModule: Boolean;
    class function Placed(AInModule: Boolean): TCryptoBackendEntry; static;
  public
    constructor Create(AVerifiersInModule: Boolean);
    function RandomBackend: TCryptoBackendEntry;
    function HashBackend(AAlgorithm: THashAlgorithm): TCryptoBackendEntry;
    function HmacBackend(AAlgorithm: THashAlgorithm): TCryptoBackendEntry;
    function HkdfBackend(AAlgorithm: THashAlgorithm): TCryptoBackendEntry;
    function Tls12PrfBackend(AAlgorithm: THashAlgorithm): TCryptoBackendEntry;
    function AeadBackend(AAlgorithm: TAeadAlgorithm): TCryptoBackendEntry;
    function KeyAgreementBackend(AAlgorithm: TKeyAgreementAlgorithm): TCryptoBackendEntry;
    function KemBackend(AAlgorithm: TKemAlgorithm): TCryptoBackendEntry;
    function SigningBackend(AScheme: TSignatureScheme): TCryptoBackendEntry;
    function SigningKeyBackend(const AKey: ISigningKey): TCryptoBackendEntry;
    function VerificationBackend(AScheme: TSignatureScheme): TCryptoBackendEntry;
    function VerifierBackend(const AVerifier: ISignatureVerifier): TCryptoBackendEntry;
    function FacetBackend(AFacet: TCryptoFacet): TCryptoBackendEntry;
    function Describe: string;
  end;

  /// <summary>A signer that signs nothing; a test only asks whether one was granted.</summary>
  TFakeSigner = class sealed(TInterfacedObject, ISignatureSigner)
  public
    procedure Update(const AData: TBytes; AOffset, ALength: Int32);
    function Sign: TBytes;
  end;

  /// <summary>A signing facet that hands out one given key and fixed-shape signers and
  /// verifiers, the verifiers marked as OS-served or not as told.</summary>
  TFakeSigningCrypto = class sealed(TInterfacedObject, ISigningCrypto)
  strict private
  var
    FKey: ISigningKey;
    FNativeVerifiers: Boolean;
    FImportedInput: TBytes;
  public
    constructor Create(const AKey: ISigningKey; ANativeVerifiers: Boolean);
    /// <summary>The bytes the last ImportSigningKey call was given.</summary>
    property ImportedInput: TBytes read FImportedInput;
    function ImportSigningKey(const AData: TBytes;
      const APassword: ISecretBuffer): ISigningKey;
    function ImportPkcs12(const AData: TBytes;
      const APassword: ISecretBuffer): TImportedCredential;
    function CreateSignatureSigner(AScheme: TSignatureScheme;
      const AKey: ISigningKey): ISignatureSigner;
    function CreateSignatureVerifier(AScheme: TSignatureScheme;
      const APublicKeyDer: TBytes): ISignatureVerifier;
  end;

  /// <summary>A classical group a host wrote, answering ACode; it agrees nothing. Never for
  /// production use.</summary>
  TFakeNamedGroup = class sealed(TInterfacedObject, INamedGroup)
  strict private
  var
    FCode: UInt16;
  public
    constructor Create(ACode: UInt16);
    function Code: UInt16;
    function Name: string;
    function Kind: TNamedGroupKind;
    function Composition: TNamedGroupComposition;
    procedure GenerateKeyPair(out APriv: IKeyExchangePrivateKey; out APubShare: TBytes);
    procedure Encapsulate(const APeerPub: TBytes; out ACiphertext: TBytes;
      out ASharedSecret: ISecretBuffer);
    procedure Decapsulate(const APriv: IKeyExchangePrivateKey; const ACiphertext: TBytes;
      out ASharedSecret: ISecretBuffer);
    function ValidatePeerShare(const AShare: TBytes): Boolean;
  end;

  TComplianceFakes = class sealed(TObject)
  public
    /// <summary>A provider over the portable one that reports AReport and, when ASigning is not
    /// nil, signs through it; its HPKE is AHpke when given and otherwise rides the portable
    /// primitives.</summary>
    class function FakeSystemBase(const AReport: ICryptoBackendReport;
      const ASigning: ISigningCrypto; const AHpke: IHpkeCrypto): ICryptoProvider; static;
    /// <summary>A FakeSystemBase reporting every operation in the OS module except the AEADs in
    /// APortableAeads, which stay portable; signing and HPKE ride the portable
    /// primitives.</summary>
    class function SystemOver(APortableAeads: TComplianceAeadSet): ICryptoProvider; static;
  end;

implementation

resourcestring
  SFakeGroupAgrees = 'the fake group agrees nothing';

{ TFakeModuleAttestation }

constructor TFakeModuleAttestation.Create(AStatus: TModuleStatus;
  const AIdentity: TModuleIdentity);
begin
  inherited Create;
  FStatus := AStatus;
  FIdentity := AIdentity;
  FCovered := True;
end;

function TFakeModuleAttestation.Covers(const ACrypto: ICryptoProvider): Boolean;
begin
  Result := FCovered;
end;

function TFakeModuleAttestation.Identity: TModuleIdentity;
begin
  Result := FIdentity;
end;

function TFakeModuleAttestation.Status(AStandard: TModuleStandard): TModuleStatus;
begin
  Result := FStatus;
end;

function TFakeModuleAttestation.Describe: string;
begin
  Result := 'fake module attestation';
end;

function TFakeModuleAttestation.Disclosures: TArray<string>;
begin
  Result := System.Copy(FDisclosed);
end;

{ TFakeBackendReport }

constructor TFakeBackendReport.Create(APortableAeads: TComplianceAeadSet);
begin
  inherited Create(False);
  FPortableAeads := APortableAeads;
end;

function TFakeBackendReport.RandomBackend: TCryptoBackendEntry;
begin
  if FPortableRandom then
    Result := NotNative
  else
    Result := Ent(TCryptoBackend.System, TCryptoBackendReason.NotFallback);
end;

function TFakeBackendReport.HashBackend(AAlgorithm: THashAlgorithm): TCryptoBackendEntry;
begin
  if AAlgorithm in FPortableHashes then
    Result := NotNative
  else
    Result := Ent(TCryptoBackend.System, TCryptoBackendReason.NotFallback);
end;

function TFakeBackendReport.HmacBackend(AAlgorithm: THashAlgorithm): TCryptoBackendEntry;
begin
  if AAlgorithm in FPortableHmacs then
    Result := NotNative
  else
    Result := Ent(TCryptoBackend.System, TCryptoBackendReason.NotFallback);
end;

function TFakeBackendReport.AeadBackend(AAlgorithm: TAeadAlgorithm): TCryptoBackendEntry;
begin
  if AAlgorithm in FPortableAeads then
    Result := NotNative
  else
    Result := Ent(TCryptoBackend.System, TCryptoBackendReason.NotFallback);
end;

function TFakeBackendReport.Tls12PrfBackend(AAlgorithm: THashAlgorithm): TCryptoBackendEntry;
begin
  if FNativePrf and not (AAlgorithm in FComposedPrfHashes) then
    Result := Ent(TCryptoBackend.System, TCryptoBackendReason.NotFallback)
  else
    Result := inherited Tls12PrfBackend(AAlgorithm);
end;

function TFakeBackendReport.KeyAgreementBackend(
  AAlgorithm: TKeyAgreementAlgorithm): TCryptoBackendEntry;
begin
  if AAlgorithm in FPortableCurves then
    Result := NotNative
  else
    Result := Ent(TCryptoBackend.System, TCryptoBackendReason.NotFallback);
end;

function TFakeBackendReport.SigningBackend(AScheme: TSignatureScheme): TCryptoBackendEntry;
begin
  Result := Ent(TCryptoBackend.System, TCryptoBackendReason.NotFallback);
end;

function TFakeBackendReport.VerificationBackend(
  AScheme: TSignatureScheme): TCryptoBackendEntry;
begin
  if AScheme in FPortableVerification then
    Result := NotNative
  else
    Result := Ent(TCryptoBackend.System, TCryptoBackendReason.NotFallback);
end;

function TFakeBackendReport.Describe: string;
begin
  Result := 'fake backend report';
end;

{ TFakeVerifierReport }

constructor TFakeVerifierReport.Create(AVerifiersInModule: Boolean);
begin
  inherited Create;
  FVerifiersInModule := AVerifiersInModule;
end;

class function TFakeVerifierReport.Placed(AInModule: Boolean): TCryptoBackendEntry;
begin
  if AInModule then
  begin
    Result.Backend := TCryptoBackend.System;
    Result.Reason := TCryptoBackendReason.NotFallback;
  end
  else
  begin
    Result.Backend := TCryptoBackend.Portable;
    Result.Reason := TCryptoBackendReason.NoNativeImpl;
  end;
end;

function TFakeVerifierReport.RandomBackend: TCryptoBackendEntry;
begin
  Result := Placed(True);
end;

function TFakeVerifierReport.HashBackend(AAlgorithm: THashAlgorithm): TCryptoBackendEntry;
begin
  Result := Placed(True);
end;

function TFakeVerifierReport.HmacBackend(AAlgorithm: THashAlgorithm): TCryptoBackendEntry;
begin
  Result := Placed(True);
end;

function TFakeVerifierReport.HkdfBackend(AAlgorithm: THashAlgorithm): TCryptoBackendEntry;
begin
  Result := Placed(True);
end;

function TFakeVerifierReport.Tls12PrfBackend(AAlgorithm: THashAlgorithm): TCryptoBackendEntry;
begin
  Result := Placed(True);
end;

function TFakeVerifierReport.AeadBackend(AAlgorithm: TAeadAlgorithm): TCryptoBackendEntry;
begin
  Result := Placed(True);
end;

function TFakeVerifierReport.KeyAgreementBackend(
  AAlgorithm: TKeyAgreementAlgorithm): TCryptoBackendEntry;
begin
  Result := Placed(True);
end;

function TFakeVerifierReport.KemBackend(AAlgorithm: TKemAlgorithm): TCryptoBackendEntry;
begin
  Result := Placed(False);
end;

function TFakeVerifierReport.SigningBackend(AScheme: TSignatureScheme): TCryptoBackendEntry;
begin
  Result := Placed(True);
end;

function TFakeVerifierReport.SigningKeyBackend(const AKey: ISigningKey): TCryptoBackendEntry;
begin
  Result := Placed(True);
end;

function TFakeVerifierReport.VerificationBackend(
  AScheme: TSignatureScheme): TCryptoBackendEntry;
begin
  Result := Placed(FVerifiersInModule);
end;

function TFakeVerifierReport.VerifierBackend(
  const AVerifier: ISignatureVerifier): TCryptoBackendEntry;
begin
  Result := Placed(FVerifiersInModule);
end;

function TFakeVerifierReport.FacetBackend(AFacet: TCryptoFacet): TCryptoBackendEntry;
begin
  Result := Placed(False);
end;

function TFakeVerifierReport.Describe: string;
begin
  Result := 'fake verifier report';
end;

{ TFakeSigner }

procedure TFakeSigner.Update(const AData: TBytes; AOffset, ALength: Int32);
begin
end;

function TFakeSigner.Sign: TBytes;
begin
  Result := nil;
end;

{ TFakeSigningCrypto }

constructor TFakeSigningCrypto.Create(const AKey: ISigningKey; ANativeVerifiers: Boolean);
begin
  inherited Create;
  FKey := AKey;
  FNativeVerifiers := ANativeVerifiers;
end;

function TFakeSigningCrypto.ImportSigningKey(const AData: TBytes;
  const APassword: ISecretBuffer): ISigningKey;
begin
  FImportedInput := AData;
  Result := FKey;
end;

function TFakeSigningCrypto.ImportPkcs12(const AData: TBytes;
  const APassword: ISecretBuffer): TImportedCredential;
begin
  Result.CertificateChain := nil;
  Result.PrivateKey := FKey;
end;

function TFakeSigningCrypto.CreateSignatureSigner(AScheme: TSignatureScheme;
  const AKey: ISigningKey): ISignatureSigner;
begin
  Result := TFakeSigner.Create as ISignatureSigner;
end;

function TFakeSigningCrypto.CreateSignatureVerifier(AScheme: TSignatureScheme;
  const APublicKeyDer: TBytes): ISignatureVerifier;
begin
  if FNativeVerifiers then
    Result := TFakeSystemVerifier.Create as ISignatureVerifier
  else
    Result := TRejectingSignatureVerifier.Create as ISignatureVerifier;
end;

{ TFakeNamedGroup }

constructor TFakeNamedGroup.Create(ACode: UInt16);
begin
  inherited Create;
  FCode := ACode;
end;

function TFakeNamedGroup.Code: UInt16;
begin
  Result := FCode;
end;

function TFakeNamedGroup.Name: string;
begin
  Result := 'fake';
end;

function TFakeNamedGroup.Kind: TNamedGroupKind;
begin
  Result := TNamedGroupKind.Ecdhe;
end;

function TFakeNamedGroup.Composition: TNamedGroupComposition;
var
  LAlgorithm: TKeyAgreementAlgorithm;
begin
  // the key agreement the code names, P-256 for a code the compliance catalog does not map
  if not TComplianceCatalog.TryKeyAgreement(FCode, LAlgorithm) then
    LAlgorithm := TKeyAgreementAlgorithm.SECP256R1;
  Result := TNamedGroupComposition.From(LAlgorithm);
end;

procedure TFakeNamedGroup.GenerateKeyPair(out APriv: IKeyExchangePrivateKey;
  out APubShare: TBytes);
begin
  raise EInvalidOperationTlsLibException.CreateRes(@SFakeGroupAgrees);
end;

procedure TFakeNamedGroup.Encapsulate(const APeerPub: TBytes; out ACiphertext: TBytes;
  out ASharedSecret: ISecretBuffer);
begin
  raise EInvalidOperationTlsLibException.CreateRes(@SFakeGroupAgrees);
end;

procedure TFakeNamedGroup.Decapsulate(const APriv: IKeyExchangePrivateKey;
  const ACiphertext: TBytes; out ASharedSecret: ISecretBuffer);
begin
  raise EInvalidOperationTlsLibException.CreateRes(@SFakeGroupAgrees);
end;

function TFakeNamedGroup.ValidatePeerShare(const AShare: TBytes): Boolean;
begin
  Result := False;
end;

{ TComplianceFakes }

class function TComplianceFakes.FakeSystemBase(const AReport: ICryptoBackendReport;
  const ASigning: ISigningCrypto; const AHpke: IHpkeCrypto): ICryptoProvider;
begin
  Result := TOverlayCryptoProvider.Create(
    TTlsLibTestProviders.Crypto(TCryptoProviderChoice.Portable), nil, ASigning, AReport, AHpke);
end;

class function TComplianceFakes.SystemOver(APortableAeads: TComplianceAeadSet): ICryptoProvider;
begin
  Result := FakeSystemBase(TFakeBackendReport.Create(APortableAeads) as ICryptoBackendReport, nil,
    nil);
end;

end.
