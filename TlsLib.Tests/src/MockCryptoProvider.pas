{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit MockCryptoProvider;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  TlpCryptoAlgorithms,
  TlpISigningKey,
  TlpTlsCredential,
  TlpICryptoProvider;

type
  /// <summary>
  /// A test <see cref="ICryptoProvider" /> that returns a caller-supplied
  /// (deterministic) <see cref="IRandom" /> and delegates every other primitive
  /// to an inner provider. This is the seam an engine leans on to run with a
  /// fixed randomness stream. Skeleton for now; grown as tests need it.
  /// </summary>
  TMockCryptoProvider = class(TInterfacedObject, ICryptoProvider)
  strict private
  var
    FInner: ICryptoProvider;
    FRandom: IRandom;
  public
    constructor Create(const AInner: ICryptoProvider; const ARandom: IRandom);
    function GetRandom: IRandom;
    function CreateHash(AAlgorithm: THashAlgorithm): IHash;
    function CreateHmac(AAlgorithm: THashAlgorithm): IHmac;
    function CreateHkdf(AAlgorithm: THashAlgorithm): IHkdf;
    function CreateAead(AAlgorithm: TAeadAlgorithm): IAead;
    function ImportSigningKey(const AData: TBytes): ISigningKey; overload;
    function ImportSigningKey(const AData: TBytes;
      const APassword: string): ISigningKey; overload;
    function CreateSignatureSigner(AScheme: TSignatureScheme;
      const AKey: ISigningKey): ISignatureSigner;
    function CreateSignatureVerifier(AScheme: TSignatureScheme;
      const APublicKeyDer: TBytes): ISignatureVerifier;
    function LoadCertificateChain(const AData: TBytes): TArray<TBytes>;
    function IsWellFormedCertificate(const ADer: TBytes): Boolean;
    function ImportPkcs12(const AData: TBytes;
      const APassword: string): TTlsCredential;
    function CertificatePublicKeyInfo(const ACertificateDer: TBytes): TBytes;
    function CertificateDnsNames(const ACertificateDer: TBytes): TArray<string>;
    function CertificateIpAddresses(const ACertificateDer: TBytes): TArray<TBytes>;
    procedure ValidateCertificatePath(const AChain, ATrustAnchors: TArray<TBytes>;
      const AValidationTimeUtc: TDateTime);
    function ValidateOcspStaple(const ALeafCert, AIssuerCert,
      AOcspResponseDer: TBytes; const AValidationTimeUtc: TDateTime;
      out AStatus: TOcspStatus;
      out AThisUpdate, ANextUpdate: TDateTime): Boolean;
    function BuildOcspRequest(const ALeafCert, AIssuerCert: TBytes;
      out ARequestDer: TBytes): Boolean;
    function TryGetOcspResponderUrl(const ACert: TBytes;
      out AUrl: string): Boolean;
    function TryGetCrlDistributionPoints(const ACert: TBytes;
      out AUrls: TArray<string>): Boolean;
    function CheckCrlRevocation(const ALeafCert, AIssuerCert, ACrlDer: TBytes;
      out ARevoked: Boolean): Boolean;
    function CertificatePeerInfo(const ACertificateDer: TBytes;
      out ASubject, AIssuer, ACommonName, ASerialHex: string): Boolean;
    function CertificateTlsFeatures(const ACert: TBytes;
      out AFeatures: TArray<UInt16>): Boolean;
    function CertificateKeyUsagePermits(const ACertificateDer: TBytes;
      AUsage: TCertKeyUsage; out APermitted: Boolean): Boolean;
    function CertificateHasRsaPssKey(const ACertificateDer: TBytes;
      out AIsRsaPss: Boolean): Boolean;
    function CertificateKeyKind(const ACertificateDer: TBytes;
      out AKind: TCertKeyKind; out AEcNamedGroup: UInt16): Boolean;
    function CreateKeyAgreement(AName: TKeyAgreementAlgorithm): IKeyAgreement;
    function CreateKem(AName: TKemAlgorithm): IKem;
    function HasHardwareAes: Boolean;
  end;

  /// <summary>
  /// A test <see cref="ICryptoProvider" /> that forces a fixed
  /// <c>HasHardwareAes</c> answer and delegates every primitive to an inner
  /// provider. It makes the CPU-adaptive AEAD ordering deterministic in tests.
  /// </summary>
  TFixedAesProvider = class(TInterfacedObject, ICryptoProvider)
  strict private
  var
    FInner: ICryptoProvider;
    FHasHardwareAes: Boolean;
  public
    constructor Create(const AInner: ICryptoProvider; AHasHardwareAes: Boolean);
    function GetRandom: IRandom;
    function CreateHash(AAlgorithm: THashAlgorithm): IHash;
    function CreateHmac(AAlgorithm: THashAlgorithm): IHmac;
    function CreateHkdf(AAlgorithm: THashAlgorithm): IHkdf;
    function CreateAead(AAlgorithm: TAeadAlgorithm): IAead;
    function ImportSigningKey(const AData: TBytes): ISigningKey; overload;
    function ImportSigningKey(const AData: TBytes;
      const APassword: string): ISigningKey; overload;
    function CreateSignatureSigner(AScheme: TSignatureScheme;
      const AKey: ISigningKey): ISignatureSigner;
    function CreateSignatureVerifier(AScheme: TSignatureScheme;
      const APublicKeyDer: TBytes): ISignatureVerifier;
    function LoadCertificateChain(const AData: TBytes): TArray<TBytes>;
    function IsWellFormedCertificate(const ADer: TBytes): Boolean;
    function ImportPkcs12(const AData: TBytes;
      const APassword: string): TTlsCredential;
    function CertificatePublicKeyInfo(const ACertificateDer: TBytes): TBytes;
    function CertificateDnsNames(const ACertificateDer: TBytes): TArray<string>;
    function CertificateIpAddresses(const ACertificateDer: TBytes): TArray<TBytes>;
    procedure ValidateCertificatePath(const AChain, ATrustAnchors: TArray<TBytes>;
      const AValidationTimeUtc: TDateTime);
    function ValidateOcspStaple(const ALeafCert, AIssuerCert,
      AOcspResponseDer: TBytes; const AValidationTimeUtc: TDateTime;
      out AStatus: TOcspStatus;
      out AThisUpdate, ANextUpdate: TDateTime): Boolean;
    function BuildOcspRequest(const ALeafCert, AIssuerCert: TBytes;
      out ARequestDer: TBytes): Boolean;
    function TryGetOcspResponderUrl(const ACert: TBytes;
      out AUrl: string): Boolean;
    function TryGetCrlDistributionPoints(const ACert: TBytes;
      out AUrls: TArray<string>): Boolean;
    function CheckCrlRevocation(const ALeafCert, AIssuerCert, ACrlDer: TBytes;
      out ARevoked: Boolean): Boolean;
    function CertificatePeerInfo(const ACertificateDer: TBytes;
      out ASubject, AIssuer, ACommonName, ASerialHex: string): Boolean;
    function CertificateTlsFeatures(const ACert: TBytes;
      out AFeatures: TArray<UInt16>): Boolean;
    function CertificateKeyUsagePermits(const ACertificateDer: TBytes;
      AUsage: TCertKeyUsage; out APermitted: Boolean): Boolean;
    function CertificateHasRsaPssKey(const ACertificateDer: TBytes;
      out AIsRsaPss: Boolean): Boolean;
    function CertificateKeyKind(const ACertificateDer: TBytes;
      out AKind: TCertKeyKind; out AEcNamedGroup: UInt16): Boolean;
    function CreateKeyAgreement(AName: TKeyAgreementAlgorithm): IKeyAgreement;
    function CreateKem(AName: TKemAlgorithm): IKem;
    function HasHardwareAes: Boolean;
  end;

implementation

{ TMockCryptoProvider }

constructor TMockCryptoProvider.Create(const AInner: ICryptoProvider;
  const ARandom: IRandom);
begin
  inherited Create;
  FInner := AInner;
  FRandom := ARandom;
end;

function TMockCryptoProvider.GetRandom: IRandom;
begin
  Result := FRandom;
end;

function TMockCryptoProvider.CreateHash(AAlgorithm: THashAlgorithm): IHash;
begin
  Result := FInner.CreateHash(AAlgorithm);
end;

function TMockCryptoProvider.CreateHmac(AAlgorithm: THashAlgorithm): IHmac;
begin
  Result := FInner.CreateHmac(AAlgorithm);
end;

function TMockCryptoProvider.CreateHkdf(AAlgorithm: THashAlgorithm): IHkdf;
begin
  Result := FInner.CreateHkdf(AAlgorithm);
end;

function TMockCryptoProvider.CreateAead(AAlgorithm: TAeadAlgorithm): IAead;
begin
  Result := FInner.CreateAead(AAlgorithm);
end;

function TMockCryptoProvider.ImportSigningKey(const AData: TBytes): ISigningKey;
begin
  Result := FInner.ImportSigningKey(AData);
end;

function TMockCryptoProvider.ImportSigningKey(const AData: TBytes;
  const APassword: string): ISigningKey;
begin
  Result := FInner.ImportSigningKey(AData, APassword);
end;

function TMockCryptoProvider.CreateSignatureSigner(AScheme: TSignatureScheme;
  const AKey: ISigningKey): ISignatureSigner;
begin
  Result := FInner.CreateSignatureSigner(AScheme, AKey);
end;

function TMockCryptoProvider.CreateSignatureVerifier(AScheme: TSignatureScheme;
  const APublicKeyDer: TBytes): ISignatureVerifier;
begin
  Result := FInner.CreateSignatureVerifier(AScheme, APublicKeyDer);
end;

function TMockCryptoProvider.LoadCertificateChain(
  const AData: TBytes): TArray<TBytes>;
begin
  Result := FInner.LoadCertificateChain(AData);
end;

function TMockCryptoProvider.IsWellFormedCertificate(
  const ADer: TBytes): Boolean;
begin
  Result := FInner.IsWellFormedCertificate(ADer);
end;

function TMockCryptoProvider.ImportPkcs12(const AData: TBytes;
  const APassword: string): TTlsCredential;
begin
  Result := FInner.ImportPkcs12(AData, APassword);
end;

function TMockCryptoProvider.CertificatePublicKeyInfo(
  const ACertificateDer: TBytes): TBytes;
begin
  Result := FInner.CertificatePublicKeyInfo(ACertificateDer);
end;

function TMockCryptoProvider.CertificateDnsNames(
  const ACertificateDer: TBytes): TArray<string>;
begin
  Result := FInner.CertificateDnsNames(ACertificateDer);
end;

function TMockCryptoProvider.CertificateIpAddresses(
  const ACertificateDer: TBytes): TArray<TBytes>;
begin
  Result := FInner.CertificateIpAddresses(ACertificateDer);
end;

procedure TMockCryptoProvider.ValidateCertificatePath(const AChain,
  ATrustAnchors: TArray<TBytes>; const AValidationTimeUtc: TDateTime);
begin
  FInner.ValidateCertificatePath(AChain, ATrustAnchors, AValidationTimeUtc);
end;

function TMockCryptoProvider.ValidateOcspStaple(const ALeafCert, AIssuerCert,
  AOcspResponseDer: TBytes; const AValidationTimeUtc: TDateTime;
  out AStatus: TOcspStatus; out AThisUpdate, ANextUpdate: TDateTime): Boolean;
begin
  Result := FInner.ValidateOcspStaple(ALeafCert, AIssuerCert, AOcspResponseDer,
    AValidationTimeUtc, AStatus, AThisUpdate, ANextUpdate);
end;

function TMockCryptoProvider.BuildOcspRequest(const ALeafCert, AIssuerCert: TBytes;
  out ARequestDer: TBytes): Boolean;
begin
  Result := FInner.BuildOcspRequest(ALeafCert, AIssuerCert, ARequestDer);
end;

function TMockCryptoProvider.TryGetOcspResponderUrl(const ACert: TBytes;
  out AUrl: string): Boolean;
begin
  Result := FInner.TryGetOcspResponderUrl(ACert, AUrl);
end;

function TMockCryptoProvider.TryGetCrlDistributionPoints(const ACert: TBytes;
  out AUrls: TArray<string>): Boolean;
begin
  Result := FInner.TryGetCrlDistributionPoints(ACert, AUrls);
end;

function TMockCryptoProvider.CheckCrlRevocation(const ALeafCert, AIssuerCert,
  ACrlDer: TBytes; out ARevoked: Boolean): Boolean;
begin
  Result := FInner.CheckCrlRevocation(ALeafCert, AIssuerCert, ACrlDer, ARevoked);
end;

function TMockCryptoProvider.CertificatePeerInfo(const ACertificateDer: TBytes;
  out ASubject, AIssuer, ACommonName, ASerialHex: string): Boolean;
begin
  Result := FInner.CertificatePeerInfo(ACertificateDer, ASubject, AIssuer,
    ACommonName, ASerialHex);
end;

function TMockCryptoProvider.CertificateTlsFeatures(const ACert: TBytes;
  out AFeatures: TArray<UInt16>): Boolean;
begin
  Result := FInner.CertificateTlsFeatures(ACert, AFeatures);
end;

function TMockCryptoProvider.CertificateKeyUsagePermits(
  const ACertificateDer: TBytes; AUsage: TCertKeyUsage;
  out APermitted: Boolean): Boolean;
begin
  Result := FInner.CertificateKeyUsagePermits(ACertificateDer, AUsage, APermitted);
end;

function TMockCryptoProvider.CertificateHasRsaPssKey(
  const ACertificateDer: TBytes; out AIsRsaPss: Boolean): Boolean;
begin
  Result := FInner.CertificateHasRsaPssKey(ACertificateDer, AIsRsaPss);
end;

function TMockCryptoProvider.CertificateKeyKind(const ACertificateDer: TBytes;
  out AKind: TCertKeyKind; out AEcNamedGroup: UInt16): Boolean;
begin
  Result := FInner.CertificateKeyKind(ACertificateDer, AKind, AEcNamedGroup);
end;

function TMockCryptoProvider.CreateKeyAgreement(AName: TKeyAgreementAlgorithm): IKeyAgreement;
begin
  Result := FInner.CreateKeyAgreement(AName);
end;

function TMockCryptoProvider.CreateKem(AName: TKemAlgorithm): IKem;
begin
  Result := FInner.CreateKem(AName);
end;

function TMockCryptoProvider.HasHardwareAes: Boolean;
begin
  Result := FInner.HasHardwareAes;
end;

{ TFixedAesProvider }

constructor TFixedAesProvider.Create(const AInner: ICryptoProvider;
  AHasHardwareAes: Boolean);
begin
  inherited Create;
  FInner := AInner;
  FHasHardwareAes := AHasHardwareAes;
end;

function TFixedAesProvider.GetRandom: IRandom;
begin
  Result := FInner.GetRandom;
end;

function TFixedAesProvider.CreateHash(AAlgorithm: THashAlgorithm): IHash;
begin
  Result := FInner.CreateHash(AAlgorithm);
end;

function TFixedAesProvider.CreateHmac(AAlgorithm: THashAlgorithm): IHmac;
begin
  Result := FInner.CreateHmac(AAlgorithm);
end;

function TFixedAesProvider.CreateHkdf(AAlgorithm: THashAlgorithm): IHkdf;
begin
  Result := FInner.CreateHkdf(AAlgorithm);
end;

function TFixedAesProvider.CreateAead(AAlgorithm: TAeadAlgorithm): IAead;
begin
  Result := FInner.CreateAead(AAlgorithm);
end;

function TFixedAesProvider.ImportSigningKey(const AData: TBytes): ISigningKey;
begin
  Result := FInner.ImportSigningKey(AData);
end;

function TFixedAesProvider.ImportSigningKey(const AData: TBytes;
  const APassword: string): ISigningKey;
begin
  Result := FInner.ImportSigningKey(AData, APassword);
end;

function TFixedAesProvider.CreateSignatureSigner(AScheme: TSignatureScheme;
  const AKey: ISigningKey): ISignatureSigner;
begin
  Result := FInner.CreateSignatureSigner(AScheme, AKey);
end;

function TFixedAesProvider.CreateSignatureVerifier(AScheme: TSignatureScheme;
  const APublicKeyDer: TBytes): ISignatureVerifier;
begin
  Result := FInner.CreateSignatureVerifier(AScheme, APublicKeyDer);
end;

function TFixedAesProvider.LoadCertificateChain(
  const AData: TBytes): TArray<TBytes>;
begin
  Result := FInner.LoadCertificateChain(AData);
end;

function TFixedAesProvider.IsWellFormedCertificate(
  const ADer: TBytes): Boolean;
begin
  Result := FInner.IsWellFormedCertificate(ADer);
end;

function TFixedAesProvider.ImportPkcs12(const AData: TBytes;
  const APassword: string): TTlsCredential;
begin
  Result := FInner.ImportPkcs12(AData, APassword);
end;

function TFixedAesProvider.CertificatePublicKeyInfo(
  const ACertificateDer: TBytes): TBytes;
begin
  Result := FInner.CertificatePublicKeyInfo(ACertificateDer);
end;

function TFixedAesProvider.CertificateDnsNames(
  const ACertificateDer: TBytes): TArray<string>;
begin
  Result := FInner.CertificateDnsNames(ACertificateDer);
end;

function TFixedAesProvider.CertificateIpAddresses(
  const ACertificateDer: TBytes): TArray<TBytes>;
begin
  Result := FInner.CertificateIpAddresses(ACertificateDer);
end;

procedure TFixedAesProvider.ValidateCertificatePath(const AChain,
  ATrustAnchors: TArray<TBytes>; const AValidationTimeUtc: TDateTime);
begin
  FInner.ValidateCertificatePath(AChain, ATrustAnchors, AValidationTimeUtc);
end;

function TFixedAesProvider.ValidateOcspStaple(const ALeafCert, AIssuerCert,
  AOcspResponseDer: TBytes; const AValidationTimeUtc: TDateTime;
  out AStatus: TOcspStatus; out AThisUpdate, ANextUpdate: TDateTime): Boolean;
begin
  Result := FInner.ValidateOcspStaple(ALeafCert, AIssuerCert, AOcspResponseDer,
    AValidationTimeUtc, AStatus, AThisUpdate, ANextUpdate);
end;

function TFixedAesProvider.BuildOcspRequest(const ALeafCert, AIssuerCert: TBytes;
  out ARequestDer: TBytes): Boolean;
begin
  Result := FInner.BuildOcspRequest(ALeafCert, AIssuerCert, ARequestDer);
end;

function TFixedAesProvider.TryGetOcspResponderUrl(const ACert: TBytes;
  out AUrl: string): Boolean;
begin
  Result := FInner.TryGetOcspResponderUrl(ACert, AUrl);
end;

function TFixedAesProvider.TryGetCrlDistributionPoints(const ACert: TBytes;
  out AUrls: TArray<string>): Boolean;
begin
  Result := FInner.TryGetCrlDistributionPoints(ACert, AUrls);
end;

function TFixedAesProvider.CheckCrlRevocation(const ALeafCert, AIssuerCert,
  ACrlDer: TBytes; out ARevoked: Boolean): Boolean;
begin
  Result := FInner.CheckCrlRevocation(ALeafCert, AIssuerCert, ACrlDer, ARevoked);
end;

function TFixedAesProvider.CertificatePeerInfo(const ACertificateDer: TBytes;
  out ASubject, AIssuer, ACommonName, ASerialHex: string): Boolean;
begin
  Result := FInner.CertificatePeerInfo(ACertificateDer, ASubject, AIssuer,
    ACommonName, ASerialHex);
end;

function TFixedAesProvider.CertificateTlsFeatures(const ACert: TBytes;
  out AFeatures: TArray<UInt16>): Boolean;
begin
  Result := FInner.CertificateTlsFeatures(ACert, AFeatures);
end;

function TFixedAesProvider.CertificateKeyUsagePermits(
  const ACertificateDer: TBytes; AUsage: TCertKeyUsage;
  out APermitted: Boolean): Boolean;
begin
  Result := FInner.CertificateKeyUsagePermits(ACertificateDer, AUsage, APermitted);
end;

function TFixedAesProvider.CertificateHasRsaPssKey(
  const ACertificateDer: TBytes; out AIsRsaPss: Boolean): Boolean;
begin
  Result := FInner.CertificateHasRsaPssKey(ACertificateDer, AIsRsaPss);
end;

function TFixedAesProvider.CertificateKeyKind(const ACertificateDer: TBytes;
  out AKind: TCertKeyKind; out AEcNamedGroup: UInt16): Boolean;
begin
  Result := FInner.CertificateKeyKind(ACertificateDer, AKind, AEcNamedGroup);
end;

function TFixedAesProvider.CreateKeyAgreement(AName: TKeyAgreementAlgorithm): IKeyAgreement;
begin
  Result := FInner.CreateKeyAgreement(AName);
end;

function TFixedAesProvider.CreateKem(AName: TKemAlgorithm): IKem;
begin
  Result := FInner.CreateKem(AName);
end;

function TFixedAesProvider.HasHardwareAes: Boolean;
begin
  Result := FHasHardwareAes;
end;

end.
