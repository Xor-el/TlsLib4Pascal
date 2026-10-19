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

  /// <summary>A backend report that places every operation in the OS module except the AEADs it
  /// is told to keep portable; a signing key answers by its <see cref="ISystemSigningKey" />
  /// marker. Never for production use.</summary>
  TFakeBackendReport = class sealed(TSystemBackendReportBase)
  strict private
  var
    FPortableAeads: TComplianceAeadSet;
  public
    constructor Create(APortableAeads: TComplianceAeadSet);
    function RandomBackend: TCryptoBackendEntry; override;
    function HashBackend(AAlgorithm: THashAlgorithm): TCryptoBackendEntry; override;
    function HmacBackend(AAlgorithm: THashAlgorithm): TCryptoBackendEntry; override;
    function AeadBackend(AAlgorithm: TAeadAlgorithm): TCryptoBackendEntry; override;
    function KeyAgreementBackend(AAlgorithm: TKeyAgreementAlgorithm): TCryptoBackendEntry; override;
    function SigningBackend(AScheme: TSignatureScheme): TCryptoBackendEntry; override;
    function Describe: string; override;
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

  TComplianceFakes = class sealed(TObject)
  public
    /// <summary>A provider over the portable one that reports AReport and, when ASigning is not
    /// nil, signs through it; its HPKE rides the portable primitives.</summary>
    class function FakeSystemBase(const AReport: ICryptoBackendReport;
      const ASigning: ISigningCrypto): ICryptoProvider; static;
  end;

implementation

resourcestring
  SFakeVerifierAsked = 'the fake system verifier source builds no verifier';

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
  Result := Ent(TCryptoBackend.System, TCryptoBackendReason.NotFallback);
end;

function TFakeBackendReport.HashBackend(AAlgorithm: THashAlgorithm): TCryptoBackendEntry;
begin
  Result := Ent(TCryptoBackend.System, TCryptoBackendReason.NotFallback);
end;

function TFakeBackendReport.HmacBackend(AAlgorithm: THashAlgorithm): TCryptoBackendEntry;
begin
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
  Result := Ent(TCryptoBackend.System, TCryptoBackendReason.NotFallback);
end;

function TFakeBackendReport.SigningBackend(AScheme: TSignatureScheme): TCryptoBackendEntry;
begin
  Result := Ent(TCryptoBackend.System, TCryptoBackendReason.NotFallback);
end;

function TFakeBackendReport.Describe: string;
begin
  Result := 'fake backend report';
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

{ TComplianceFakes }

class function TComplianceFakes.FakeSystemBase(const AReport: ICryptoBackendReport;
  const ASigning: ISigningCrypto): ICryptoProvider;
begin
  Result := TOverlayCryptoProvider.Create(
    TTlsLibTestProviders.Crypto(TCryptoProviderChoice.Portable), nil, ASigning, AReport);
end;

end.
