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
  TlpCryptoDomainTypes,
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
    FNameConstraintsRaise: Boolean;
  public
    constructor Create(const AInner: ICertificatePathValidator);
    procedure ValidateCertificatePath(const AChain: TArray<TBytes>;
      const ATrustAnchors: ITrustAnchorStore; const AIntermediates: TArray<TBytes>;
      const AValidationTimeUtc: TDateTime; AKeyPurpose: TCertKeyPurpose;
      var AEffectiveChain: TArray<TBytes>);
    function NameConstraintsAdmit(const APath: TArray<TBytes>): Boolean;
    property Count: Integer read FCount;
    /// <summary>Makes NameConstraintsAdmit raise instead of answering.</summary>
    property NameConstraintsRaise: Boolean read FNameConstraintsRaise write FNameConstraintsRaise;
  end;

  /// <summary>An inspector that delegates to a real one except that SameName answers a scripted
  /// verdict, for the answer a real certificate pair never produces, and Parse can be made to raise
  /// something other than a library exception.</summary>
  TScriptedNameInspector = class sealed(TInterfacedObject, ICertificateInspector)
  strict private
  var
    FInner: ICertificateInspector;
    FAnswer: TCertAnswer;
    FParseRaises: Boolean;
  public
    constructor Create(const AInner: ICertificateInspector; AAnswer: TCertAnswer);
    property ParseRaises: Boolean read FParseRaises write FParseRaises;
    function Parse(const ADer: TBytes): IInspectedCertificate;
    function LoadChain(const AData: TBytes): TArray<TBytes>;
    function IsWellFormed(const ADer: TBytes): Boolean;
    function PublicKeyInfo(const ACertificateDer: TBytes): TBytes;
    function DnsNames(const ACertificateDer: TBytes): TArray<string>;
    function IpAddresses(const ACertificateDer: TBytes): TArray<TBytes>;
    function PeerInfo(const ACertificateDer: TBytes;
      out ASubject, AIssuer, ACommonName, ASerialHex: string): Boolean;
    function TlsFeatures(const ACert: TBytes; out AFeatures: TArray<UInt16>): Boolean;
    function KeyUsagePermits(const ACertificateDer: TBytes; AUsage: TCertKeyUsage): TCertAnswer;
    function KeyIsRsaPss(const ACertificateDer: TBytes): TCertAnswer;
    function IsCertificateAuthority(const ACertificateDer: TBytes): TCertAnswer;
    function KeyKind(const ACertificateDer: TBytes; out AKind: TSignatureKeyKind;
      out AEcNamedGroup: UInt16): Boolean;
    function SamePublicKey(const ASpkiA, ASpkiB: TBytes): TCertAnswer;
    function SameName(const AName1, AName2: TBytes): TCertAnswer;
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
    FOcspUrlsCount: Integer;
    FCrlUrlsCount: Integer;
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
    /// <summary>The counting validator behind PathValidation, for scripting its failures.</summary>
    property PathValidatorSpy: TCountingPathValidator read FPathValidator;
    property BuildRequestCount: Integer read FBuildRequestCount;
    property FindIssuerCount: Integer read FFindIssuerCount;
    property OcspUrlsCount: Integer read FOcspUrlsCount;
    property CrlUrlsCount: Integer read FCrlUrlsCount;
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

function TCountingPathValidator.NameConstraintsAdmit(const APath: TArray<TBytes>): Boolean;
begin
  if FNameConstraintsRaise then
    raise Exception.Create('name constraints unavailable');
  Result := FInner.NameConstraintsAdmit(APath);
end;

{ TScriptedNameInspector }

constructor TScriptedNameInspector.Create(const AInner: ICertificateInspector;
  AAnswer: TCertAnswer);
begin
  inherited Create;
  FInner := AInner;
  FAnswer := AAnswer;
end;

function TScriptedNameInspector.Parse(const ADer: TBytes): IInspectedCertificate;
begin
  if FParseRaises then
    raise Exception.Create('the inspector failed');
  Result := FInner.Parse(ADer);
end;

function TScriptedNameInspector.LoadChain(const AData: TBytes): TArray<TBytes>;
begin
  Result := FInner.LoadChain(AData);
end;

function TScriptedNameInspector.IsWellFormed(const ADer: TBytes): Boolean;
begin
  Result := FInner.IsWellFormed(ADer);
end;

function TScriptedNameInspector.PublicKeyInfo(const ACertificateDer: TBytes): TBytes;
begin
  Result := FInner.PublicKeyInfo(ACertificateDer);
end;

function TScriptedNameInspector.DnsNames(const ACertificateDer: TBytes): TArray<string>;
begin
  Result := FInner.DnsNames(ACertificateDer);
end;

function TScriptedNameInspector.IpAddresses(const ACertificateDer: TBytes): TArray<TBytes>;
begin
  Result := FInner.IpAddresses(ACertificateDer);
end;

function TScriptedNameInspector.PeerInfo(const ACertificateDer: TBytes;
  out ASubject, AIssuer, ACommonName, ASerialHex: string): Boolean;
begin
  Result := FInner.PeerInfo(ACertificateDer, ASubject, AIssuer, ACommonName, ASerialHex);
end;

function TScriptedNameInspector.TlsFeatures(const ACert: TBytes;
  out AFeatures: TArray<UInt16>): Boolean;
begin
  Result := FInner.TlsFeatures(ACert, AFeatures);
end;

function TScriptedNameInspector.KeyUsagePermits(const ACertificateDer: TBytes;
  AUsage: TCertKeyUsage): TCertAnswer;
begin
  Result := FInner.KeyUsagePermits(ACertificateDer, AUsage);
end;

function TScriptedNameInspector.KeyIsRsaPss(const ACertificateDer: TBytes): TCertAnswer;
begin
  Result := FInner.KeyIsRsaPss(ACertificateDer);
end;

function TScriptedNameInspector.IsCertificateAuthority(const ACertificateDer: TBytes): TCertAnswer;
begin
  Result := FInner.IsCertificateAuthority(ACertificateDer);
end;

function TScriptedNameInspector.KeyKind(const ACertificateDer: TBytes;
  out AKind: TSignatureKeyKind; out AEcNamedGroup: UInt16): Boolean;
begin
  Result := FInner.KeyKind(ACertificateDer, AKind, AEcNamedGroup);
end;

function TScriptedNameInspector.SamePublicKey(const ASpkiA, ASpkiB: TBytes): TCertAnswer;
begin
  Result := FInner.SamePublicKey(ASpkiA, ASpkiB);
end;

function TScriptedNameInspector.SameName(const AName1, AName2: TBytes): TCertAnswer;
begin
  Result := FAnswer;
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
  Inc(FOcspUrlsCount);
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
  Inc(FCrlUrlsCount);
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
