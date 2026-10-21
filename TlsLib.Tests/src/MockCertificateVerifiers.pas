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
  TlpTrustTypes,
  TlpTrustPolicy,
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

implementation

resourcestring
  SFakeVerifierAsked = 'the fake system verifier source builds no verifier';

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

end.
