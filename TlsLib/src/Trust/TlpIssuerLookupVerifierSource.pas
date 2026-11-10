{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpIssuerLookupVerifierSource;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpArrayUtilities,
  TlpTlsAlert,
  TlpTlsLibExceptions,
  TlpServerName,
  TlpTrustTypes,
  TlpTrustPolicy,
  TlpITrustAnchorStore,
  TlpICertificateTrust,
  TlpICertificateVerifierSource,
  TlpIIssuerLookup,
  TlpIssuerResolution;

type
  /// <summary>
  /// Wraps a server-verifier source so each verification resolves the issuers of the presented chain
  /// from an issuer lookup first: the inner source builds its verifier over the context's trust store
  /// with the looked-up anchors layered on and the looked-up intermediates added. The engine factory
  /// applies it at engine creation; it is never stored in a config.
  /// </summary>
  TIssuerLookupServerVerifierSource = class sealed(TInterfacedObject,
    IServerCertificateVerifierSource)
  strict private
    FInner: IServerCertificateVerifierSource;
    FLookup: IIssuerLookup;
    FRule: TBundleAnchorRule;
  public
    constructor Create(const AInner: IServerCertificateVerifierSource;
      const ALookup: IIssuerLookup; ARule: TBundleAnchorRule);
    function CreateServerVerifier(const AContext: TServerTrustContext)
      : IServerCertificateVerifier;
  end;

  /// <summary>The client-certificate counterpart of <see cref="TIssuerLookupServerVerifierSource" />.</summary>
  TIssuerLookupClientVerifierSource = class sealed(TInterfacedObject,
    IClientCertificateVerifierSource)
  strict private
    FInner: IClientCertificateVerifierSource;
    FLookup: IIssuerLookup;
    FRule: TBundleAnchorRule;
  public
    constructor Create(const AInner: IClientCertificateVerifierSource;
      const ALookup: IIssuerLookup; ARule: TBundleAnchorRule);
    function CreateClientVerifier(const AContext: TClientTrustContext)
      : IClientCertificateVerifier;
  end;

implementation

resourcestring
  SNilSource = 'an issuer-lookup decorator needs the verifier source it wraps';
  SNilLookup = 'an issuer-lookup decorator needs an issuer lookup';

type
  TIssuerLookupServerVerifier = class sealed(TInterfacedObject, IServerCertificateVerifier)
  strict private
    FInner: IServerCertificateVerifierSource;
    FLookup: IIssuerLookup;
    FRule: TBundleAnchorRule;
    FContext: TServerTrustContext;
  public
    constructor Create(const AInner: IServerCertificateVerifierSource;
      const ALookup: IIssuerLookup; ARule: TBundleAnchorRule;
      const AContext: TServerTrustContext);
    function VerifyServerCertificate(const AChain: TArray<TBytes>;
      const AServerName: TServerName; const AOcspStaple: TBytes;
      out AVerified: TVerifiedChain; out AAlert: TTlsAlertDescription): Boolean;
  end;

  TIssuerLookupClientVerifier = class sealed(TInterfacedObject, IClientCertificateVerifier)
  strict private
    FInner: IClientCertificateVerifierSource;
    FLookup: IIssuerLookup;
    FRule: TBundleAnchorRule;
    FContext: TClientTrustContext;
  public
    constructor Create(const AInner: IClientCertificateVerifierSource;
      const ALookup: IIssuerLookup; ARule: TBundleAnchorRule;
      const AContext: TClientTrustContext);
    function VerifyClientCertificate(const AChain: TArray<TBytes>;
      out AVerified: TVerifiedChain; out AAlert: TTlsAlertDescription): Boolean;
  end;

{ TIssuerLookupServerVerifierSource }

constructor TIssuerLookupServerVerifierSource.Create(
  const AInner: IServerCertificateVerifierSource; const ALookup: IIssuerLookup;
  ARule: TBundleAnchorRule);
begin
  inherited Create;
  if AInner = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilSource);
  if ALookup = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilLookup);
  FInner := AInner;
  FLookup := ALookup;
  FRule := ARule;
end;

function TIssuerLookupServerVerifierSource.CreateServerVerifier(
  const AContext: TServerTrustContext): IServerCertificateVerifier;
begin
  Result := TIssuerLookupServerVerifier.Create(FInner, FLookup, FRule, AContext)
    as IServerCertificateVerifier;
end;

{ TIssuerLookupClientVerifierSource }

constructor TIssuerLookupClientVerifierSource.Create(
  const AInner: IClientCertificateVerifierSource; const ALookup: IIssuerLookup;
  ARule: TBundleAnchorRule);
begin
  inherited Create;
  if AInner = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilSource);
  if ALookup = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilLookup);
  FInner := AInner;
  FLookup := ALookup;
  FRule := ARule;
end;

function TIssuerLookupClientVerifierSource.CreateClientVerifier(
  const AContext: TClientTrustContext): IClientCertificateVerifier;
begin
  Result := TIssuerLookupClientVerifier.Create(FInner, FLookup, FRule, AContext)
    as IClientCertificateVerifier;
end;

{ TIssuerLookupServerVerifier }

constructor TIssuerLookupServerVerifier.Create(const AInner: IServerCertificateVerifierSource;
  const ALookup: IIssuerLookup; ARule: TBundleAnchorRule; const AContext: TServerTrustContext);
begin
  inherited Create;
  FInner := AInner;
  FLookup := ALookup;
  FRule := ARule;
  FContext := AContext;
end;

function TIssuerLookupServerVerifier.VerifyServerCertificate(const AChain: TArray<TBytes>;
  const AServerName: TServerName; const AOcspStaple: TBytes; out AVerified: TVerifiedChain;
  out AAlert: TTlsAlertDescription): Boolean;
var
  LContext: TServerTrustContext;
  LStore: ITrustAnchorStore;
  LFound: TArray<TBytes>;
begin
  AVerified := Default(TVerifiedChain);
  AAlert := TTlsAlertDescription.BadCertificate;
  // the chain caps hold before the lookup is asked anything
  if not FContext.ChainLimits.AdmitsChain(AChain) then
    Exit(False);
  TIssuerResolution.Resolve(FContext.Pkix.Certificates, FLookup, FRule, FContext.StrengthPolicy,
    FContext.TrustStore, AChain, FContext.Intermediates, LStore, LFound);
  LContext := FContext;
  LContext.TrustStore := LStore;
  LContext.Intermediates := TArrayUtilities.Concat<TBytes>(FContext.Intermediates, LFound);
  Result := FInner.CreateServerVerifier(LContext).VerifyServerCertificate(AChain,
    AServerName, AOcspStaple, AVerified, AAlert);
end;

{ TIssuerLookupClientVerifier }

constructor TIssuerLookupClientVerifier.Create(const AInner: IClientCertificateVerifierSource;
  const ALookup: IIssuerLookup; ARule: TBundleAnchorRule; const AContext: TClientTrustContext);
begin
  inherited Create;
  FInner := AInner;
  FLookup := ALookup;
  FRule := ARule;
  FContext := AContext;
end;

function TIssuerLookupClientVerifier.VerifyClientCertificate(const AChain: TArray<TBytes>;
  out AVerified: TVerifiedChain; out AAlert: TTlsAlertDescription): Boolean;
var
  LContext: TClientTrustContext;
  LStore: ITrustAnchorStore;
  LFound: TArray<TBytes>;
begin
  AVerified := Default(TVerifiedChain);
  AAlert := TTlsAlertDescription.BadCertificate;
  if not FContext.ChainLimits.AdmitsChain(AChain) then
    Exit(False);
  TIssuerResolution.Resolve(FContext.Pkix.Certificates, FLookup, FRule, FContext.StrengthPolicy,
    FContext.TrustStore, AChain, FContext.Intermediates, LStore, LFound);
  LContext := FContext;
  LContext.TrustStore := LStore;
  LContext.Intermediates := TArrayUtilities.Concat<TBytes>(FContext.Intermediates, LFound);
  Result := FInner.CreateClientVerifier(LContext).VerifyClientCertificate(AChain, AVerified,
    AAlert);
end;

end.
