{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit SpyRevocationProvider;

{ A pass-through IPkixProvider that delegates every call to a real provider while counting the two
  revocation-parse entry points (ValidateOcspStaple / CheckCrlRevocation). It lets a test prove that
  the live checker's size cap short-circuits BEFORE any parse - an outcome assertion alone cannot,
  since a garbage body is rejected by the parser too. }

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  TlpCryptoDomainTypes,
  TlpPkixDomainTypes,
  TlpIPkixProvider;

type
  /// <summary>Counts ValidateOcspStaple/CheckCrlRevocation while delegating the whole IPkixProvider
  /// (and IRevocationChecker) surface to an injected real provider. Used to assert the checker never
  /// reaches the parser for an oversize body.</summary>
  TSpyPkixProvider = class sealed(TInterfacedObject, IPkixProvider, IRevocationChecker)
  strict private
  var
    FInner: IPkixProvider;
    FOcspParseCount: Integer;
    FCrlParseCount: Integer;
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
    function TryGetOcspResponderUrl(const ACert: TBytes; out AUrl: string): Boolean;
    function TryGetCrlDistributionPoints(const ACert: TBytes;
      out AUrls: TArray<string>): Boolean;
    function CheckCrlRevocation(const ALeafCert, AIssuerCert, ACrlDer: TBytes;
      const AValidationTimeUtc: TDateTime; out ARevoked: Boolean;
      out AThisUpdate, ANextUpdate: TDateTime): Boolean;
    function TryFindIssuer(const ALeafCert: TBytes; const ACandidates: TArray<TBytes>;
      out AIssuerCert: TBytes): Boolean;
  public
    constructor Create(const AInner: IPkixProvider);
    property OcspParseCount: Integer read FOcspParseCount;
    property CrlParseCount: Integer read FCrlParseCount;
  end;

implementation

{ TSpyPkixProvider }

constructor TSpyPkixProvider.Create(const AInner: IPkixProvider);
begin
  inherited Create;
  FInner := AInner;
end;

function TSpyPkixProvider.Certificates: ICertificateInspector;
begin
  Result := FInner.Certificates;
end;

function TSpyPkixProvider.PathValidation: ICertificatePathValidator;
begin
  Result := FInner.PathValidation;
end;

function TSpyPkixProvider.Revocation: IRevocationChecker;
begin
  Result := Self;
end;

function TSpyPkixProvider.ValidateOcspStaple(const ALeafCert, AIssuerCert,
  AOcspResponseDer: TBytes; const AValidationTimeUtc: TDateTime;
  out AStatus: TOcspStatus; out AThisUpdate, ANextUpdate: TDateTime): Boolean;
begin
  Inc(FOcspParseCount);
  Result := FInner.Revocation.ValidateOcspStaple(ALeafCert, AIssuerCert,
    AOcspResponseDer, AValidationTimeUtc, AStatus, AThisUpdate, ANextUpdate);
end;

function TSpyPkixProvider.BuildOcspRequest(const ALeafCert, AIssuerCert: TBytes;
  out ARequestDer: TBytes): Boolean;
begin
  Result := FInner.Revocation.BuildOcspRequest(ALeafCert, AIssuerCert, ARequestDer);
end;

function TSpyPkixProvider.TryGetOcspResponderUrl(const ACert: TBytes;
  out AUrl: string): Boolean;
begin
  Result := FInner.Revocation.TryGetOcspResponderUrl(ACert, AUrl);
end;

function TSpyPkixProvider.TryGetCrlDistributionPoints(const ACert: TBytes;
  out AUrls: TArray<string>): Boolean;
begin
  Result := FInner.Revocation.TryGetCrlDistributionPoints(ACert, AUrls);
end;

function TSpyPkixProvider.CheckCrlRevocation(const ALeafCert, AIssuerCert,
  ACrlDer: TBytes; const AValidationTimeUtc: TDateTime; out ARevoked: Boolean;
  out AThisUpdate, ANextUpdate: TDateTime): Boolean;
begin
  Inc(FCrlParseCount);
  Result := FInner.Revocation.CheckCrlRevocation(ALeafCert, AIssuerCert, ACrlDer,
    AValidationTimeUtc, ARevoked, AThisUpdate, ANextUpdate);
end;

function TSpyPkixProvider.TryFindIssuer(const ALeafCert: TBytes;
  const ACandidates: TArray<TBytes>; out AIssuerCert: TBytes): Boolean;
begin
  Result := FInner.Revocation.TryFindIssuer(ALeafCert, ACandidates, AIssuerCert);
end;

end.
