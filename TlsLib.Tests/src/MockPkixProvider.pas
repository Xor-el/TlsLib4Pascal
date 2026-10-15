{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit MockPkixProvider;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  TlpPkixDomainTypes,
  TlpITrustAnchorStore,
  TlpIPkixProvider;

type
  /// <summary>Counts the path builds it is asked for while delegating to a real validator.</summary>
  TCountingPathValidator = class sealed(TInterfacedObject, ICertificatePathValidator)
  strict private
  var
    FInner: ICertificatePathValidator;
    FCount: Integer;
  public
    constructor Create(const AInner: ICertificatePathValidator);
    procedure ValidateCertificatePath(const AChain: TArray<TBytes>;
      const ATrustAnchors: ITrustAnchorStore; const AIntermediates: TArray<TBytes>;
      const AValidationTimeUtc: TDateTime; AKeyPurpose: TCertKeyPurpose;
      var AEffectiveChain: TArray<TBytes>);
    property Count: Integer read FCount;
  end;

  /// <summary>Delegates to a real provider, counting the revocation and path calls, with
  /// scriptable responder URLs and request failure.</summary>
  TMockPkixProvider = class sealed(TInterfacedObject, IPkixProvider, IRevocationChecker)
  strict private
  var
    FInner: IPkixProvider;
    FOcspParseCount: Integer;
    FCrlParseCount: Integer;
    FOcspUrlsOverridden, FCrlUrlsOverridden, FOcspRequestFails: Boolean;
    FBuildRequestCount: Integer;
    FFindIssuerCount: Integer;
    FOcspUrls, FCrlUrls: TArray<string>;
    FPathValidator: TCountingPathValidator;
    FPathValidatorRef: ICertificatePathValidator;
    // IPkixProvider
    function Certificates: ICertificateInspector;
    function PathValidation: ICertificatePathValidator;
    function Revocation: IRevocationChecker;
    // IRevocationChecker
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
  public
    constructor Create(const AInner: IPkixProvider);
    /// <summary>Makes the provider report AUrls as the certificate's OCSP responders, whatever the
    /// certificate carries, so a checker test can script the responder list with the fixtures'
    /// own signed responses (an OCSP response is bound to the certificate, not to the URL).</summary>
    procedure OverrideOcspUrls(const AUrls: TArray<string>);
    /// <summary>As OverrideOcspUrls, for the CRL distribution points.</summary>
    procedure OverrideCrlUrls(const AUrls: TArray<string>);
    /// <summary>Makes BuildOcspRequest report that no request could be built.</summary>
    procedure FailOcspRequest;
    /// <summary>How many path builds PathValidation has been asked for.</summary>
    function PathBuildCount: Integer;
    property BuildRequestCount: Integer read FBuildRequestCount;
    property FindIssuerCount: Integer read FFindIssuerCount;
    property OcspParseCount: Integer read FOcspParseCount;
    property CrlParseCount: Integer read FCrlParseCount;
  end;

implementation

{ TCountingPathValidator }

constructor TCountingPathValidator.Create(const AInner: ICertificatePathValidator);
begin
  inherited Create;
  FInner := AInner;
end;

procedure TCountingPathValidator.ValidateCertificatePath(const AChain: TArray<TBytes>;
  const ATrustAnchors: ITrustAnchorStore; const AIntermediates: TArray<TBytes>;
  const AValidationTimeUtc: TDateTime; AKeyPurpose: TCertKeyPurpose;
  var AEffectiveChain: TArray<TBytes>);
begin
  Inc(FCount);
  FInner.ValidateCertificatePath(AChain, ATrustAnchors, AIntermediates, AValidationTimeUtc,
    AKeyPurpose, AEffectiveChain);
end;

{ TMockPkixProvider }

constructor TMockPkixProvider.Create(const AInner: IPkixProvider);
begin
  inherited Create;
  FInner := AInner;
  FPathValidator := TCountingPathValidator.Create(AInner.PathValidation);
  FPathValidatorRef := FPathValidator as ICertificatePathValidator;
end;

function TMockPkixProvider.Certificates: ICertificateInspector;
begin
  Result := FInner.Certificates;
end;

function TMockPkixProvider.PathValidation: ICertificatePathValidator;
begin
  Result := FPathValidatorRef;
end;

function TMockPkixProvider.PathBuildCount: Integer;
begin
  Result := FPathValidator.Count;
end;

function TMockPkixProvider.Revocation: IRevocationChecker;
begin
  Result := Self;
end;

function TMockPkixProvider.ValidateOcspStaple(const ALeafCert, AIssuerCert,
  AOcspResponseDer: TBytes; const AValidationTimeUtc: TDateTime;
  out AStatus: TOcspStatus; out AThisUpdate, ANextUpdate: TDateTime): Boolean;
begin
  Inc(FOcspParseCount);
  Result := FInner.Revocation.ValidateOcspStaple(ALeafCert, AIssuerCert,
    AOcspResponseDer, AValidationTimeUtc, AStatus, AThisUpdate, ANextUpdate);
end;

function TMockPkixProvider.BuildOcspRequest(const ALeafCert, AIssuerCert: TBytes;
  out ARequestDer: TBytes): Boolean;
begin
  Inc(FBuildRequestCount);
  if FOcspRequestFails then
  begin
    ARequestDer := nil;
    Exit(False);
  end;
  Result := FInner.Revocation.BuildOcspRequest(ALeafCert, AIssuerCert, ARequestDer);
end;

procedure TMockPkixProvider.FailOcspRequest;
begin
  FOcspRequestFails := True;
end;

procedure TMockPkixProvider.OverrideOcspUrls(const AUrls: TArray<string>);
begin
  FOcspUrlsOverridden := True;
  FOcspUrls := AUrls;
end;

procedure TMockPkixProvider.OverrideCrlUrls(const AUrls: TArray<string>);
begin
  FCrlUrlsOverridden := True;
  FCrlUrls := AUrls;
end;

function TMockPkixProvider.TryGetOcspResponderUrls(const ACert: TBytes;
  out AUrls: TArray<string>): Boolean;
begin
  if FOcspUrlsOverridden then
  begin
    AUrls := System.Copy(FOcspUrls);
    Exit(System.Length(AUrls) > 0);
  end;
  Result := FInner.Revocation.TryGetOcspResponderUrls(ACert, AUrls);
end;

function TMockPkixProvider.TryGetCrlDistributionPoints(const ACert: TBytes;
  out AUrls: TArray<string>): Boolean;
begin
  if FCrlUrlsOverridden then
  begin
    AUrls := System.Copy(FCrlUrls);
    Exit(System.Length(AUrls) > 0);
  end;
  Result := FInner.Revocation.TryGetCrlDistributionPoints(ACert, AUrls);
end;

function TMockPkixProvider.CheckCrlRevocation(const ALeafCert, AIssuerCert,
  ACrlDer: TBytes; const AValidationTimeUtc: TDateTime; out ARevoked: Boolean;
  out AThisUpdate, ANextUpdate: TDateTime): Boolean;
begin
  Inc(FCrlParseCount);
  Result := FInner.Revocation.CheckCrlRevocation(ALeafCert, AIssuerCert, ACrlDer,
    AValidationTimeUtc, ARevoked, AThisUpdate, ANextUpdate);
end;

function TMockPkixProvider.TryFindIssuer(const ALeafCert: TBytes;
  const ACandidates: TArray<TBytes>; out AIssuerCert: TBytes): Boolean;
begin
  Inc(FFindIssuerCount);
  Result := FInner.Revocation.TryFindIssuer(ALeafCert, ACandidates, AIssuerCert);
end;

end.
