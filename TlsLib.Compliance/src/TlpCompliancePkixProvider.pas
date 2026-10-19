{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpCompliancePkixProvider;

{$I ..\..\TlsLib\src\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpPkixDomainTypes,
  TlpIPkixProvider,
  TlpITrustAnchorStore,
  TlpComplianceTypes,
  TlpComplianceExceptions,
  TlpTlsLibExceptions;

type
  /// <summary>
  /// A path validator that, in strict mode, refuses every chain: the portable validation runs
  /// outside the OS module, so a chain check must come from a source the module serves.
  /// Relaxed mode forwards.
  /// </summary>
  TCompliancePathValidator = class sealed(TInterfacedObject, ICertificatePathValidator)
  strict private
  var
    FInner: ICertificatePathValidator;
    FStrict: Boolean;
  public
    constructor Create(const AInner: ICertificatePathValidator;
      AEnforcement: TComplianceEnforcement);
    procedure ValidateCertificatePath(const AChain: TArray<TBytes>;
      const ATrustAnchors: ITrustAnchorStore; const AIntermediates: TArray<TBytes>;
      const AValidationTimeUtc: TDateTime; AKeyPurpose: TCertKeyPurpose;
      var AEffectiveChain: TArray<TBytes>);
  end;

  /// <summary>
  /// A revocation checker that, in strict mode, answers indeterminate to every query (the
  /// contract never raises): the portable OCSP and CRL checks run outside the OS module, so a
  /// hard posture rejects and a soft one accepts. Relaxed mode forwards.
  /// </summary>
  TComplianceRevocationChecker = class sealed(TInterfacedObject, IRevocationChecker)
  strict private
  var
    FInner: IRevocationChecker;
    FStrict: Boolean;
  public
    constructor Create(const AInner: IRevocationChecker; AEnforcement: TComplianceEnforcement);
    function ValidateOcspStaple(const ALeafCert, AIssuerCert, AOcspResponseDer: TBytes;
      const AValidationTimeUtc: TDateTime; out AStatus: TOcspStatus;
      out AThisUpdate, ANextUpdate: TDateTime): Boolean;
    function BuildOcspRequest(const ALeafCert, AIssuerCert: TBytes;
      out ARequestDer: TBytes): Boolean;
    function TryGetOcspResponderUrls(const ACert: TBytes;
      out AUrls: TArray<string>): Boolean;
    function TryGetCrlDistributionPoints(const ACert: TBytes;
      out AUrls: TArray<string>): Boolean;
    function CheckCrlRevocation(const ALeafCert, AIssuerCert, ACrlDer: TBytes;
      const AValidationTimeUtc: TDateTime; out ARevoked: Boolean;
      out AThisUpdate, ANextUpdate: TDateTime): Boolean;
    function TryFindIssuer(const ALeafCert: TBytes; const ACandidates: TArray<TBytes>;
      out AIssuerCert: TBytes): Boolean;
  end;

  /// <summary>
  /// A PKIX provider that keeps the base's certificate parsing and routes path validation and
  /// revocation through the refusing facets, so no chain or staple is judged outside the module
  /// in strict mode.
  /// </summary>
  TCompliancePkixProvider = class sealed(TInterfacedObject, IPkixProvider)
  strict private
  var
    FCertificates: ICertificateInspector;
    FPathValidation: ICertificatePathValidator;
    FRevocation: IRevocationChecker;
  public
    constructor Create(const ABase: IPkixProvider; AEnforcement: TComplianceEnforcement);
    function Certificates: ICertificateInspector;
    function PathValidation: ICertificatePathValidator;
    function Revocation: IRevocationChecker;
  end;

implementation

resourcestring
  SChainOutsideModule = 'certificate path validation runs outside the OS crypto module';
  SNilInnerValidator = 'the inner path validator must not be nil';
  SNilInnerChecker = 'the inner revocation checker must not be nil';
  SNilBasePkix = 'the base PKIX provider must not be nil';

{ TCompliancePathValidator }

constructor TCompliancePathValidator.Create(const AInner: ICertificatePathValidator;
  AEnforcement: TComplianceEnforcement);
begin
  inherited Create;
  if AInner = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilInnerValidator);
  FInner := AInner;
  FStrict := AEnforcement = TComplianceEnforcement.Strict;
end;

procedure TCompliancePathValidator.ValidateCertificatePath(const AChain: TArray<TBytes>;
  const ATrustAnchors: ITrustAnchorStore; const AIntermediates: TArray<TBytes>;
  const AValidationTimeUtc: TDateTime; AKeyPurpose: TCertKeyPurpose;
  var AEffectiveChain: TArray<TBytes>);
begin
  if FStrict then
    raise EComplianceRefusedTlsLibException.CreateRes(@SChainOutsideModule);
  FInner.ValidateCertificatePath(AChain, ATrustAnchors, AIntermediates, AValidationTimeUtc,
    AKeyPurpose, AEffectiveChain);
end;

{ TComplianceRevocationChecker }

constructor TComplianceRevocationChecker.Create(const AInner: IRevocationChecker;
  AEnforcement: TComplianceEnforcement);
begin
  inherited Create;
  if AInner = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilInnerChecker);
  FInner := AInner;
  FStrict := AEnforcement = TComplianceEnforcement.Strict;
end;

function TComplianceRevocationChecker.ValidateOcspStaple(const ALeafCert, AIssuerCert,
  AOcspResponseDer: TBytes; const AValidationTimeUtc: TDateTime; out AStatus: TOcspStatus;
  out AThisUpdate, ANextUpdate: TDateTime): Boolean;
begin
  if FStrict then
  begin
    AStatus := TOcspStatus.Unknown;
    AThisUpdate := 0;
    ANextUpdate := 0;
    Exit(False);
  end;
  Result := FInner.ValidateOcspStaple(ALeafCert, AIssuerCert, AOcspResponseDer,
    AValidationTimeUtc, AStatus, AThisUpdate, ANextUpdate);
end;

function TComplianceRevocationChecker.BuildOcspRequest(const ALeafCert, AIssuerCert: TBytes;
  out ARequestDer: TBytes): Boolean;
begin
  if FStrict then
  begin
    ARequestDer := nil;
    Exit(False);
  end;
  Result := FInner.BuildOcspRequest(ALeafCert, AIssuerCert, ARequestDer);
end;

function TComplianceRevocationChecker.TryGetOcspResponderUrls(const ACert: TBytes;
  out AUrls: TArray<string>): Boolean;
begin
  if FStrict then
  begin
    AUrls := nil;
    Exit(False);
  end;
  Result := FInner.TryGetOcspResponderUrls(ACert, AUrls);
end;

function TComplianceRevocationChecker.TryGetCrlDistributionPoints(const ACert: TBytes;
  out AUrls: TArray<string>): Boolean;
begin
  if FStrict then
  begin
    AUrls := nil;
    Exit(False);
  end;
  Result := FInner.TryGetCrlDistributionPoints(ACert, AUrls);
end;

function TComplianceRevocationChecker.CheckCrlRevocation(const ALeafCert, AIssuerCert,
  ACrlDer: TBytes; const AValidationTimeUtc: TDateTime; out ARevoked: Boolean;
  out AThisUpdate, ANextUpdate: TDateTime): Boolean;
begin
  if FStrict then
  begin
    ARevoked := False;
    AThisUpdate := 0;
    ANextUpdate := 0;
    Exit(False);
  end;
  Result := FInner.CheckCrlRevocation(ALeafCert, AIssuerCert, ACrlDer, AValidationTimeUtc,
    ARevoked, AThisUpdate, ANextUpdate);
end;

function TComplianceRevocationChecker.TryFindIssuer(const ALeafCert: TBytes;
  const ACandidates: TArray<TBytes>; out AIssuerCert: TBytes): Boolean;
begin
  if FStrict then
  begin
    AIssuerCert := nil;
    Exit(False);
  end;
  Result := FInner.TryFindIssuer(ALeafCert, ACandidates, AIssuerCert);
end;

{ TCompliancePkixProvider }

constructor TCompliancePkixProvider.Create(const ABase: IPkixProvider;
  AEnforcement: TComplianceEnforcement);
var
  LValidator: ICertificatePathValidator;
  LChecker: IRevocationChecker;
begin
  inherited Create;
  if ABase = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilBasePkix);
  LValidator := TCompliancePathValidator.Create(ABase.PathValidation, AEnforcement)
    as ICertificatePathValidator;
  LChecker := TComplianceRevocationChecker.Create(ABase.Revocation, AEnforcement)
    as IRevocationChecker;
  FCertificates := ABase.Certificates;
  FPathValidation := LValidator;
  FRevocation := LChecker;
end;

function TCompliancePkixProvider.Certificates: ICertificateInspector;
begin
  Result := FCertificates;
end;

function TCompliancePkixProvider.PathValidation: ICertificatePathValidator;
begin
  Result := FPathValidation;
end;

function TCompliancePkixProvider.Revocation: IRevocationChecker;
begin
  Result := FRevocation;
end;

end.
