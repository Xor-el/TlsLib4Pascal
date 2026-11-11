{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit MockCertificateVerifiers;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  TlpTlsAlert,
  TlpTlsLibExceptions,
  TlpServerName,
  TlpArrayUtilities,
  TlpTrustTypes,
  TlpTrustPolicy,
  TlpITrustAnchorStore,
  TlpIIssuerLookup,
  TlpICertificateTrust,
  TlpICertificateVerifierSource;

type
  /// <summary>A verifier with a scripted verdict that counts its calls.</summary>
  TFixedVerdictVerifier = class sealed(TInterfacedObject, IServerCertificateVerifier,
    IClientCertificateVerifier)
  strict private
    FAccept: Boolean;
    FNonEmptyOnly: Boolean;
    FReportPath: Boolean;
    FAlert: TTlsAlertDescription;
    FPath: TArray<TBytes>;
    FOutcome: TVerificationOutcome;
    FCalls: Int32;
  public
    /// <summary>Accepts every chain, echoing it as the validated path; ANonEmptyChainOnly
    /// rejects an empty chain.</summary>
    constructor CreateAccepting(ANonEmptyChainOnly: Boolean);
    /// <summary>Rejects every chain with AAlert.</summary>
    constructor CreateRejecting(AAlert: TTlsAlertDescription);
    /// <summary>Accepts every chain, reporting APath and AOutcome as the validated path.</summary>
    constructor CreateReporting(const APath: TArray<TBytes>; AOutcome: TVerificationOutcome);
    function VerifyServerCertificate(const AChain: TArray<TBytes>;
      const AServerName: TServerName; const AOcspStaple: TBytes;
      out AVerified: TVerifiedChain; out AAlert: TTlsAlertDescription): Boolean;
    function VerifyClientCertificate(const AChain: TArray<TBytes>;
      out AVerified: TVerifiedChain; out AAlert: TTlsAlertDescription): Boolean;
    property Calls: Int32 read FCalls;
  end;

  /// <summary>Counts each verification and records its host, then defers to AInner.</summary>
  TRecordingServerVerifier = class sealed(TInterfacedObject, IServerCertificateVerifier)
  strict private
    FInner: IServerCertificateVerifier;
    FCalls: Int32;
    FNames: TArray<string>;
  public
    constructor Create(const AInner: IServerCertificateVerifier);
    function VerifyServerCertificate(const AChain: TArray<TBytes>;
      const AServerName: TServerName; const AOcspStaple: TBytes;
      out AVerified: TVerifiedChain; out AAlert: TTlsAlertDescription): Boolean;
    property Calls: Int32 read FCalls;
    property Names: TArray<string> read FNames;
  end;

  /// <summary>A verifier that raises instead of answering.</summary>
  TRaisingServerVerifier = class sealed(TInterfacedObject, IServerCertificateVerifier)
  public
    function VerifyServerCertificate(const AChain: TArray<TBytes>;
      const AServerName: TServerName; const AOcspStaple: TBytes;
      out AVerified: TVerifiedChain; out AAlert: TTlsAlertDescription): Boolean;
  end;

  /// <summary>A client-verifier source that hands out an accept-all verifier.</summary>
  TAcceptingClientVerifierSource = class sealed(TInterfacedObject,
    IClientCertificateVerifierSource)
  public
    function CreateClientVerifier(const AContext: TClientTrustContext)
      : IClientCertificateVerifier;
  end;

  /// <summary>A host verifier source that is not the library's OS source, and builds no
  /// verifier; a connection that asks it for a verifier fails. Never for production use.</summary>
  TFakeHostVerifierSource = class sealed(TInterfacedObject,
    IServerCertificateVerifierSource, IClientCertificateVerifierSource)
  public
    function CreateServerVerifier(const AContext: TServerTrustContext)
      : IServerCertificateVerifier;
    function CreateClientVerifier(const AContext: TClientTrustContext)
      : IClientCertificateVerifier;
  end;

  /// <summary>A verifier source that accepts every chain and keeps the trust store and intermediates
  /// of the context it was last asked to build a verifier from.</summary>
  TCapturingVerifierSource = class sealed(TInterfacedObject, IServerCertificateVerifierSource,
    IClientCertificateVerifierSource)
  strict private
    FStore: ITrustAnchorStore;
    FIntermediates: TArray<TBytes>;
    FCreated: Int32;
  public
    function CreateServerVerifier(const AContext: TServerTrustContext)
      : IServerCertificateVerifier;
    function CreateClientVerifier(const AContext: TClientTrustContext)
      : IClientCertificateVerifier;
    property Store: ITrustAnchorStore read FStore;
    property Intermediates: TArray<TBytes> read FIntermediates;
    /// <summary>How many verifiers the source has been asked to build.</summary>
    property Created: Int32 read FCreated;
  end;

  /// <summary>A verifier source whose verifiers accept a chain exactly when its last certificate is
  /// an anchor of the trust store the context carries, so only that store can reject.</summary>
  TAnchorMembershipVerifierSource = class sealed(TInterfacedObject,
    IServerCertificateVerifierSource)
  public
    function CreateServerVerifier(const AContext: TServerTrustContext)
      : IServerCertificateVerifier;
  end;

  /// <summary>An issuer lookup that answers from a script and records every name it is asked. A
  /// name is answered only when it equals a scripted name byte for byte.</summary>
  TRecordingIssuerLookup = class sealed(TInterfacedObject, IIssuerLookup)
  strict private
    FIdentity: string;
    FNames: TArray<TBytes>;
    FAnswers: TArray<TLookedUpIssuers>;
    FAsked: TArray<TBytes>;
    FRaises: Boolean;
  public
    constructor Create(const AIdentity: string);
    /// <summary>Scripts the answer for ASubjectName.</summary>
    procedure Offer(const ASubjectName: TBytes; const AAnchors, AIntermediates: TArray<TBytes>);
    /// <summary>Drops every scripted answer; the record of asked names stays.</summary>
    procedure Forget;
    function Identity: string;
    function IssuersNamed(const ASubjectName: TBytes): TLookedUpIssuers;
    /// <summary>How many times ASubjectName has been asked.</summary>
    function TimesAsked(const ASubjectName: TBytes): Int32;
    /// <summary>The names asked so far, in order.</summary>
    property Asked: TArray<TBytes> read FAsked;
    /// <summary>Makes every ask raise instead of answering.</summary>
    property RaisesOnAsk: Boolean read FRaises write FRaises;
  end;

implementation

resourcestring
  SFakeVerifierAsked = 'the fake system verifier source builds no verifier';

type
  TAnchorMembershipVerifier = class sealed(TInterfacedObject, IServerCertificateVerifier)
  strict private
    FStore: ITrustAnchorStore;
  public
    constructor Create(const AStore: ITrustAnchorStore);
    function VerifyServerCertificate(const AChain: TArray<TBytes>;
      const AServerName: TServerName; const AOcspStaple: TBytes;
      out AVerified: TVerifiedChain; out AAlert: TTlsAlertDescription): Boolean;
  end;

{ TFixedVerdictVerifier }

constructor TFixedVerdictVerifier.CreateAccepting(ANonEmptyChainOnly: Boolean);
begin
  inherited Create;
  FAccept := True;
  FNonEmptyOnly := ANonEmptyChainOnly;
  FAlert := TTlsAlertDescription.BadCertificate;
end;

constructor TFixedVerdictVerifier.CreateRejecting(AAlert: TTlsAlertDescription);
begin
  inherited Create;
  FAlert := AAlert;
end;

constructor TFixedVerdictVerifier.CreateReporting(const APath: TArray<TBytes>;
  AOutcome: TVerificationOutcome);
begin
  inherited Create;
  FAccept := True;
  FReportPath := True;
  FAlert := TTlsAlertDescription.BadCertificate;
  FPath := APath;
  FOutcome := AOutcome;
end;

function TFixedVerdictVerifier.VerifyServerCertificate(const AChain: TArray<TBytes>;
  const AServerName: TServerName; const AOcspStaple: TBytes;
  out AVerified: TVerifiedChain; out AAlert: TTlsAlertDescription): Boolean;
begin
  Inc(FCalls);
  AVerified := Default(TVerifiedChain);
  AAlert := FAlert;
  Result := FAccept and ((not FNonEmptyOnly) or (System.Length(AChain) > 0));
  if not Result then
    Exit;
  if FReportPath then
  begin
    AVerified.Path := FPath;
    AVerified.Outcome := FOutcome;
  end
  else
    AVerified.Path := AChain;
end;

function TFixedVerdictVerifier.VerifyClientCertificate(const AChain: TArray<TBytes>;
  out AVerified: TVerifiedChain; out AAlert: TTlsAlertDescription): Boolean;
begin
  Result := VerifyServerCertificate(AChain, Default(TServerName), nil, AVerified, AAlert);
end;

{ TRecordingServerVerifier }

constructor TRecordingServerVerifier.Create(const AInner: IServerCertificateVerifier);
begin
  inherited Create;
  FInner := AInner;
end;

function TRecordingServerVerifier.VerifyServerCertificate(const AChain: TArray<TBytes>;
  const AServerName: TServerName; const AOcspStaple: TBytes;
  out AVerified: TVerifiedChain; out AAlert: TTlsAlertDescription): Boolean;
begin
  Inc(FCalls);
  SetLength(FNames, System.Length(FNames) + 1);
  FNames[System.High(FNames)] := AServerName.ToString;
  Result := FInner.VerifyServerCertificate(AChain, AServerName, AOcspStaple, AVerified, AAlert);
end;

{ TRaisingServerVerifier }

function TRaisingServerVerifier.VerifyServerCertificate(const AChain: TArray<TBytes>;
  const AServerName: TServerName; const AOcspStaple: TBytes;
  out AVerified: TVerifiedChain; out AAlert: TTlsAlertDescription): Boolean;
begin
  raise Exception.Create('the verifier failed');
end;

{ TAcceptingClientVerifierSource }

function TAcceptingClientVerifierSource.CreateClientVerifier(
  const AContext: TClientTrustContext): IClientCertificateVerifier;
begin
  Result := TFixedVerdictVerifier.CreateAccepting(False) as IClientCertificateVerifier;
end;

{ TFakeHostVerifierSource }

function TFakeHostVerifierSource.CreateServerVerifier(const AContext: TServerTrustContext)
  : IServerCertificateVerifier;
begin
  raise EInvalidOperationTlsLibException.CreateRes(@SFakeVerifierAsked);
end;

function TFakeHostVerifierSource.CreateClientVerifier(const AContext: TClientTrustContext)
  : IClientCertificateVerifier;
begin
  raise EInvalidOperationTlsLibException.CreateRes(@SFakeVerifierAsked);
end;

{ TCapturingVerifierSource }

function TCapturingVerifierSource.CreateServerVerifier(const AContext: TServerTrustContext)
  : IServerCertificateVerifier;
begin
  Inc(FCreated);
  FStore := AContext.TrustStore;
  FIntermediates := AContext.Intermediates;
  Result := TFixedVerdictVerifier.CreateAccepting(False) as IServerCertificateVerifier;
end;

function TCapturingVerifierSource.CreateClientVerifier(const AContext: TClientTrustContext)
  : IClientCertificateVerifier;
begin
  Inc(FCreated);
  FStore := AContext.TrustStore;
  FIntermediates := AContext.Intermediates;
  Result := TFixedVerdictVerifier.CreateAccepting(False) as IClientCertificateVerifier;
end;

{ TAnchorMembershipVerifier }

constructor TAnchorMembershipVerifier.Create(const AStore: ITrustAnchorStore);
begin
  inherited Create;
  FStore := AStore;
end;

function TAnchorMembershipVerifier.VerifyServerCertificate(const AChain: TArray<TBytes>;
  const AServerName: TServerName; const AOcspStaple: TBytes; out AVerified: TVerifiedChain;
  out AAlert: TTlsAlertDescription): Boolean;
begin
  AVerified := Default(TVerifiedChain);
  AAlert := TTlsAlertDescription.UnknownCa;
  Result := (FStore <> nil) and (System.Length(AChain) > 0) and
    FStore.IsAnchor(AChain[System.High(AChain)]);
end;

{ TAnchorMembershipVerifierSource }

function TAnchorMembershipVerifierSource.CreateServerVerifier(const AContext: TServerTrustContext)
  : IServerCertificateVerifier;
begin
  Result := TAnchorMembershipVerifier.Create(AContext.TrustStore) as IServerCertificateVerifier;
end;

{ TRecordingIssuerLookup }

constructor TRecordingIssuerLookup.Create(const AIdentity: string);
begin
  inherited Create;
  FIdentity := AIdentity;
end;

procedure TRecordingIssuerLookup.Offer(const ASubjectName: TBytes;
  const AAnchors, AIntermediates: TArray<TBytes>);
var
  LAnswer: TLookedUpIssuers;
begin
  LAnswer.Anchors := AAnchors;
  LAnswer.Intermediates := AIntermediates;
  TArrayUtilities.Append<TBytes>(FNames, ASubjectName);
  TArrayUtilities.Append<TLookedUpIssuers>(FAnswers, LAnswer);
end;

procedure TRecordingIssuerLookup.Forget;
begin
  FNames := nil;
  FAnswers := nil;
end;

function TRecordingIssuerLookup.Identity: string;
begin
  Result := FIdentity;
end;

function TRecordingIssuerLookup.IssuersNamed(const ASubjectName: TBytes): TLookedUpIssuers;
var
  LI: Int32;
begin
  TArrayUtilities.Append<TBytes>(FAsked, ASubjectName);
  if FRaises then
    raise Exception.Create('the issuer lookup failed');
  Result := Default(TLookedUpIssuers);
  for LI := 0 to System.High(FNames) do
    if TArrayUtilities.AreEqual(FNames[LI], ASubjectName) then
      Exit(FAnswers[LI]);
end;

function TRecordingIssuerLookup.TimesAsked(const ASubjectName: TBytes): Int32;
var
  LI: Int32;
begin
  Result := 0;
  for LI := 0 to System.High(FAsked) do
    if TArrayUtilities.AreEqual(FAsked[LI], ASubjectName) then
      Inc(Result);
end;

end.
