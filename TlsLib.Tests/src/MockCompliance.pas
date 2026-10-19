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
  TlpISigningKey,
  TlpImportedCredential,
  TlpISystemSigningKey,
  TlpISystemSignatureVerifier,
  TlpICryptoBackendReport,
  TlpSystemCryptoTypes,
  TlpSystemCryptoBase,
  TlpComplianceTypes,
  TlpIModuleAttestation,
  TlpArrayUtilities,
  TlpICertificateTrust,
  TlpICertificateVerifierSource,
  TlpTrustPolicy,
  TlpISystemVerifierSource,
  TlpTlsLibExceptions,
  TlsLibTestProviders;

type
  /// <summary>An <see cref="IModuleAttestation" /> that answers a fixed status and identity, so a
  /// test drives the module verdict on any host. Never for production use.</summary>
  TFakeModuleAttestation = class sealed(TInterfacedObject, IModuleAttestation)
  strict private
  var
    FStatus: TModuleStatus;
    FIdentity: TModuleIdentity;
  public
    constructor Create(AStatus: TModuleStatus; const AIdentity: TModuleIdentity);
    function Identity: TModuleIdentity;
    function Status(AStandard: TModuleStandard): TModuleStatus;
    function Describe: string;
  end;

  TComplianceHashSet = set of THashAlgorithm;

  /// <summary>A backend report that places every operation in the OS module except the entries
  /// it is told to keep portable (the AEADs at construction, the rest through the properties,
  /// all empty by default) and the KEMs, which no module serves; a signing key answers by its
  /// <see cref="ISystemSigningKey" /> marker and a verifier by its
  /// <see cref="ISystemSignatureVerifier" /> marker. Never for production use.</summary>
  TFakeBackendReport = class sealed(TSystemBackendReportBase)
  strict private
  var
    FPortableAeads: TComplianceAeadSet;
    FPortableRandom: Boolean;
    FPortableHashes: TComplianceHashSet;
    FPortableHmacs: TComplianceHashSet;
    FPortableCurves: TComplianceKeyAgreementSet;
    FPortableVerification: TComplianceSchemeSet;
  public
    constructor Create(APortableAeads: TComplianceAeadSet);
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

  /// <summary>A signing key that reports fixed schemes and a fixed public key, and has no
  /// private key material; it carries no OS marker, as a key the portable facet imported.</summary>
  TFakeSigningKey = class(TInterfacedObject, ISigningKey)
  strict private
  var
    FSchemes: TArray<TSignatureScheme>;
    FPublicKeyInfo: TBytes;
  strict protected
    function Narrowed(const ASchemes: TArray<TSignatureScheme>): ISigningKey; virtual;
  public
    constructor Create(const ASchemes: TArray<TSignatureScheme>); overload;
    constructor Create(const ASchemes: TArray<TSignatureScheme>;
      const APublicKeyInfo: TBytes); overload;
    function CapableSchemes: TArray<TSignatureScheme>;
    function PublicKeyInfo: TBytes;
    function WithPreferredSchemes(const ASchemes: TArray<TSignatureScheme>): ISigningKey;
  end;

  /// <summary>A <see cref="TFakeSigningKey" /> that carries the OS marker and keeps it when
  /// narrowed.</summary>
  TFakeSystemSigningKey = class sealed(TFakeSigningKey, ISystemSigningKey)
  strict protected
    function Narrowed(const ASchemes: TArray<TSignatureScheme>): ISigningKey; override;
  end;

  /// <summary>A signer that signs nothing; a test only asks whether one was granted.</summary>
  TFakeSigner = class sealed(TInterfacedObject, ISignatureSigner)
  public
    procedure Update(const AData: TBytes; AOffset, ALength: Int32);
    function Sign: TBytes;
  end;

  /// <summary>A verifier that verifies nothing and carries no OS marker, as the portable
  /// fallback does.</summary>
  TFakeVerifier = class(TInterfacedObject, ISignatureVerifier)
  public
    procedure Update(const AData: TBytes; AOffset, ALength: Int32);
    function Verify(const ASignature: TBytes): Boolean;
  end;

  /// <summary>A <see cref="TFakeVerifier" /> that carries the OS marker.</summary>
  TFakeSystemVerifier = class sealed(TFakeVerifier, ISystemSignatureVerifier);

  /// <summary>A signing facet that hands out one given key and fixed-shape signers and
  /// verifiers, the verifiers marked as OS-served or not as told.</summary>
  TFakeSigningCrypto = class sealed(TInterfacedObject, ISigningCrypto)
  strict private
  var
    FKey: ISigningKey;
    FNativeVerifiers: Boolean;
  public
    constructor Create(const AKey: ISigningKey; ANativeVerifiers: Boolean);
    function ImportSigningKey(const AData: TBytes;
      const APassword: ISecretBuffer): ISigningKey;
    function ImportPkcs12(const AData: TBytes;
      const APassword: ISecretBuffer): TImportedCredential;
    function CreateSignatureSigner(AScheme: TSignatureScheme;
      const AKey: ISigningKey): ISignatureSigner;
    function CreateSignatureVerifier(AScheme: TSignatureScheme;
      const APublicKeyDer: TBytes): ISignatureVerifier;
  end;

  /// <summary>A verifier source that carries the OS marker and builds no verifier, so a config
  /// can hold one on any host; a connection that asks it for a verifier fails. Never for
  /// production use.</summary>
  TFakeSystemVerifierSource = class sealed(TInterfacedObject,
    IServerCertificateVerifierSource, IClientCertificateVerifierSource, ISystemVerifierSource)
  public
    function CreateServerVerifier(const AContext: TServerTrustContext)
      : IServerCertificateVerifier;
    function CreateClientVerifier(const AContext: TClientTrustContext)
      : IClientCertificateVerifier;
    function Anchors: TArray<TBytes>;
    function ExtraAnchors: TArray<TBytes>;
    function Distrusted: TArray<TBytes>;
  end;

  /// <summary>An HPKE suite that seals nothing; a test only asks whether one was granted.</summary>
  TFakeHpkeSuite = class sealed(TInterfacedObject, IHpkeSuite)
  strict private
  var
    FKem, FKdf, FAead: UInt16;
  public
    constructor Create(AKem, AKdf, AAead: UInt16);
    function Kem: UInt16;
    function Kdf: UInt16;
    function Aead: UInt16;
    function AeadTagLength: Int32;
    procedure SetupSealer(const ARecipientPublicKey, AInfo: TBytes; out AEnc: TBytes;
      out ASealer: IHpkeSealer);
  end;

  /// <summary>A foreign HPKE facet, not composed over any primitives, that offers every KEM and
  /// the three AEADs and counts the key operations that reach it. Never for production
  /// use.</summary>
  TFakeHpke = class sealed(TInterfacedObject, IHpkeCrypto)
  strict private
  var
    FRecipientImports: Int32;
    FKeyPairs: Int32;
    FPrivateImports: Int32;
  public
    function Suite(AKem, AKdf, AAead: UInt16): IHpkeSuite;
    function ImportRecipientKey(AKem: UInt16;
      const APrivateKey: ISecretBuffer): IHpkeRecipientKey;
    procedure GenerateKeyPair(AKem: UInt16; out APublicKey: TBytes;
      out APrivateKey: ISecretBuffer);
    function ImportPrivateKey(AKem: UInt16; const APkcs8Der: TBytes): ISecretBuffer;
    function SupportedSuites(AKem: UInt16): TArray<THpkeSuiteId>;
    function ValidatePublicKey(AKem: UInt16; const APublicKey: TBytes): Boolean;
    function RandomEncapsulation(AKem: UInt16): TBytes;
    property RecipientImports: Int32 read FRecipientImports;
    property KeyPairs: Int32 read FKeyPairs;
    property PrivateImports: Int32 read FPrivateImports;
  end;

  TComplianceFakes = class sealed(TObject)
  public
    /// <summary>A provider over the portable one that reports AReport and, when ASigning is not
    /// nil, signs through it; its HPKE is AHpke when given and otherwise rides the portable
    /// primitives.</summary>
    class function FakeSystemBase(const AReport: ICryptoBackendReport;
      const ASigning: ISigningCrypto; const AHpke: IHpkeCrypto): ICryptoProvider; static;
  end;

implementation

resourcestring
  SFakeVerifierAsked = 'the fake system verifier source builds no verifier';
  SFakeHpkeSealer = 'the fake HPKE suite seals nothing';

{ TFakeModuleAttestation }

constructor TFakeModuleAttestation.Create(AStatus: TModuleStatus;
  const AIdentity: TModuleIdentity);
begin
  inherited Create;
  FStatus := AStatus;
  FIdentity := AIdentity;
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

{ TFakeSigningKey }

constructor TFakeSigningKey.Create(const ASchemes: TArray<TSignatureScheme>);
begin
  Create(ASchemes, nil);
end;

constructor TFakeSigningKey.Create(const ASchemes: TArray<TSignatureScheme>;
  const APublicKeyInfo: TBytes);
begin
  inherited Create;
  FSchemes := ASchemes;
  FPublicKeyInfo := APublicKeyInfo;
end;

function TFakeSigningKey.Narrowed(const ASchemes: TArray<TSignatureScheme>): ISigningKey;
begin
  Result := TFakeSigningKey.Create(ASchemes, FPublicKeyInfo) as ISigningKey;
end;

function TFakeSigningKey.CapableSchemes: TArray<TSignatureScheme>;
begin
  Result := FSchemes;
end;

function TFakeSigningKey.PublicKeyInfo: TBytes;
begin
  Result := FPublicKeyInfo;
end;

function TFakeSigningKey.WithPreferredSchemes(
  const ASchemes: TArray<TSignatureScheme>): ISigningKey;
var
  LKept: TArray<TSignatureScheme>;
  LI: Int32;
begin
  if System.Length(ASchemes) = 0 then
    Exit(Self as ISigningKey);
  LKept := nil;
  for LI := 0 to System.Length(ASchemes) - 1 do
    if TArrayUtilities.Contains<TSignatureScheme>(FSchemes, ASchemes[LI]) then
      TArrayUtilities.Append<TSignatureScheme>(LKept, ASchemes[LI]);
  Result := Narrowed(LKept);
end;

{ TFakeSystemSigningKey }

function TFakeSystemSigningKey.Narrowed(const ASchemes: TArray<TSignatureScheme>): ISigningKey;
begin
  Result := TFakeSystemSigningKey.Create(ASchemes, PublicKeyInfo) as ISigningKey;
end;

{ TFakeSigner }

procedure TFakeSigner.Update(const AData: TBytes; AOffset, ALength: Int32);
begin
end;

function TFakeSigner.Sign: TBytes;
begin
  Result := nil;
end;

{ TFakeVerifier }

procedure TFakeVerifier.Update(const AData: TBytes; AOffset, ALength: Int32);
begin
end;

function TFakeVerifier.Verify(const ASignature: TBytes): Boolean;
begin
  Result := False;
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
    Result := TFakeVerifier.Create as ISignatureVerifier;
end;

{ TFakeSystemVerifierSource }

function TFakeSystemVerifierSource.CreateServerVerifier(const AContext: TServerTrustContext)
  : IServerCertificateVerifier;
begin
  raise EInvalidOperationTlsLibException.CreateRes(@SFakeVerifierAsked);
end;

function TFakeSystemVerifierSource.CreateClientVerifier(const AContext: TClientTrustContext)
  : IClientCertificateVerifier;
begin
  raise EInvalidOperationTlsLibException.CreateRes(@SFakeVerifierAsked);
end;

function TFakeSystemVerifierSource.Anchors: TArray<TBytes>;
begin
  Result := nil;
end;

function TFakeSystemVerifierSource.ExtraAnchors: TArray<TBytes>;
begin
  Result := nil;
end;

function TFakeSystemVerifierSource.Distrusted: TArray<TBytes>;
begin
  Result := nil;
end;

{ TFakeHpkeSuite }

constructor TFakeHpkeSuite.Create(AKem, AKdf, AAead: UInt16);
begin
  inherited Create;
  FKem := AKem;
  FKdf := AKdf;
  FAead := AAead;
end;

function TFakeHpkeSuite.Kem: UInt16;
begin
  Result := FKem;
end;

function TFakeHpkeSuite.Kdf: UInt16;
begin
  Result := FKdf;
end;

function TFakeHpkeSuite.Aead: UInt16;
begin
  Result := FAead;
end;

function TFakeHpkeSuite.AeadTagLength: Int32;
begin
  Result := 16;
end;

procedure TFakeHpkeSuite.SetupSealer(const ARecipientPublicKey, AInfo: TBytes;
  out AEnc: TBytes; out ASealer: IHpkeSealer);
begin
  raise EInvalidOperationTlsLibException.CreateRes(@SFakeHpkeSealer);
end;

{ TFakeHpke }

function TFakeHpke.Suite(AKem, AKdf, AAead: UInt16): IHpkeSuite;
begin
  Result := TFakeHpkeSuite.Create(AKem, AKdf, AAead) as IHpkeSuite;
end;

function TFakeHpke.ImportRecipientKey(AKem: UInt16;
  const APrivateKey: ISecretBuffer): IHpkeRecipientKey;
begin
  Inc(FRecipientImports);
  Result := nil;
end;

procedure TFakeHpke.GenerateKeyPair(AKem: UInt16; out APublicKey: TBytes;
  out APrivateKey: ISecretBuffer);
begin
  Inc(FKeyPairs);
  APublicKey := nil;
  APrivateKey := nil;
end;

function TFakeHpke.ImportPrivateKey(AKem: UInt16; const APkcs8Der: TBytes): ISecretBuffer;
begin
  Inc(FPrivateImports);
  Result := nil;
end;

function TFakeHpke.SupportedSuites(AKem: UInt16): TArray<THpkeSuiteId>;
begin
  Result := TArray<THpkeSuiteId>.Create(
    THpkeSuiteId.Create(AKem, THpkeKdf.HKDF_SHA256, THpkeAead.AES_128_GCM),
    THpkeSuiteId.Create(AKem, THpkeKdf.HKDF_SHA256, THpkeAead.AES_256_GCM),
    THpkeSuiteId.Create(AKem, THpkeKdf.HKDF_SHA256, THpkeAead.CHACHA20_POLY1305));
end;

function TFakeHpke.ValidatePublicKey(AKem: UInt16; const APublicKey: TBytes): Boolean;
begin
  Result := True;
end;

function TFakeHpke.RandomEncapsulation(AKem: UInt16): TBytes;
begin
  Result := TBytes.Create(1);
end;

{ TComplianceFakes }

class function TComplianceFakes.FakeSystemBase(const AReport: ICryptoBackendReport;
  const ASigning: ISigningCrypto; const AHpke: IHpkeCrypto): ICryptoProvider;
begin
  Result := TOverlayCryptoProvider.Create(
    TTlsLibTestProviders.Crypto(TCryptoProviderChoice.Portable), nil, ASigning, AReport, AHpke);
end;

end.
