{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpLiveRevocation;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpTlsAlert,
  TlpCryptoAlgorithms,
  TlpICryptoProvider,
  TlpIClock,
  TlpIHttpFetcher,
  TlpTrustPolicy,
  TlpDateTimeUtilities;

type
  /// <summary>The live revocation outcome for a leaf: a current Good response, a definitive
  /// Revoked, or an indeterminate result (no responder, unreachable, malformed, unknown, or
  /// outside the response validity window).</summary>
  TLiveRevocationOutcome = (Good, Revoked, Indeterminate);

  /// <summary>Which live revocation source(s) to consult, in order.</summary>
  TLiveRevocationMethod = (Ocsp, Crl, OcspThenCrl);

  /// <summary>
  /// The driver-edge live revocation check that turns the async certificate-verdict seam
  /// into working network revocation: given an accepted peer chain it fetches
  /// OCSP (RFC 6960) and/or CRL (RFC 5280) status through the injected IHttpFetcher and
  /// returns a fail-closed verdict. It performs no IO itself - the fetcher owns every socket
  /// - so it stays sans-IO and is fully testable with a fake fetcher.
  ///
  /// Fail-closed matrix (augment-only: it can only additionally reject a chain the built-in
  /// pipeline already accepted, never resurrect one):
  ///   * a definitive, issuer-authenticated Revoked (OCSP or CRL) ALWAYS rejects;
  ///   * a current Good accepts;
  ///   * indeterminate (no responder URL, unreachable, malformed, unknown, stale, or a chain
  ///     with no issuer to authenticate against) is treated per the posture - Soft/Off accept
  ///     (soft-fail), Hard rejects. The default when unspecified is the stricter Hard.
  /// </summary>
  TLiveRevocationChecker = class sealed(TObject)
  strict private
  const
    OcspRequestContentType = 'application/ocsp-request';
  var
    FProvider: ICryptoProvider;
    FClock: ITlsClock;
    FFetcher: IHttpFetcher;
    FPosture: TRevocationPosture;
    FMethod: TLiveRevocationMethod;
    FTimeoutMs: Cardinal;
    function EvaluateOcsp(const ALeaf, AIssuer: TBytes;
      const AResponderUrl: string): TLiveRevocationOutcome;
    function EvaluateCrl(const ALeaf, AIssuer: TBytes;
      const ACrlUrl: string): TLiveRevocationOutcome;
  public
    /// <summary>Builds a checker over an injected provider and fetcher. APosture governs how
    /// an indeterminate result is treated (Hard rejects, Soft/Off accept). ATimeoutMs bounds
    /// each fetch (0 leaves it to the fetcher).</summary>
    constructor Create(const AProvider: ICryptoProvider; const AClock: ITlsClock;
      const AFetcher: IHttpFetcher; APosture: TRevocationPosture;
      AMethod: TLiveRevocationMethod; ATimeoutMs: Cardinal);
    /// <summary>The tri-state live outcome for the chain (leaf = AChain[0], issuer =
    /// AChain[1]). A chain without an issuer entry is Indeterminate (nothing authenticates a
    /// revocation).</summary>
    function Evaluate(const AChain: TArray<TBytes>): TLiveRevocationOutcome;
    /// <summary>The fail-closed accept/reject verdict for the chain: Revoked rejects always,
    /// Good accepts, Indeterminate follows the posture.</summary>
    function CheckChain(const AChain: TArray<TBytes>): Boolean;
    /// <summary>Signature-compatible with the Tier-2 stream verdict resolver (the host name is
    /// not used for revocation): assign it to TTlsStream.SetCertificateVerdictResolver to run
    /// live revocation as the out-of-band verdict for a parked handshake. On reject, ARejectAlert
    /// is certificate_revoked for a definitive Revoked and bad_certificate_status_response for a
    /// hard-fail indeterminate.</summary>
    function ResolveVerdict(const AChain: TArray<TBytes>;
      const AHostName: string;
      out ARejectAlert: TTlsAlertDescription): Boolean;
  end;

implementation

{ TLiveRevocationChecker }

constructor TLiveRevocationChecker.Create(const AProvider: ICryptoProvider;
  const AClock: ITlsClock; const AFetcher: IHttpFetcher; APosture: TRevocationPosture;
  AMethod: TLiveRevocationMethod; ATimeoutMs: Cardinal);
begin
  inherited Create;
  FProvider := AProvider;
  FClock := AClock;
  FFetcher := AFetcher;
  FPosture := APosture;
  FMethod := AMethod;
  FTimeoutMs := ATimeoutMs;
end;

function TLiveRevocationChecker.EvaluateOcsp(const ALeaf, AIssuer: TBytes;
  const AResponderUrl: string): TLiveRevocationOutcome;
var
  LRequest, LResponse: TBytes;
  LStatus: TOcspStatus;
  LThisUpdate, LNextUpdate: TDateTime;
  LNowMs: Int64;
begin
  Result := TLiveRevocationOutcome.Indeterminate;
  if (AResponderUrl = '') or (FFetcher = nil) then
    Exit;
  if not FProvider.Revocation.BuildOcspRequest(ALeaf, AIssuer, LRequest) then
    Exit;
  // unreachable / non-2xx / empty body -> indeterminate (never a silent pass)
  if not FFetcher.Post(AResponderUrl, OcspRequestContentType, LRequest, FTimeoutMs,
    LResponse) then
    Exit;
  // reuse the in-band parser: it authenticates the response (issuer- or delegated-signed)
  // and binds the CertID to this leaf; a malformed/unauthorized response is indeterminate.
  // the responder-validity date comes from the injected clock, like the window below
  if not FProvider.Revocation.ValidateOcspStaple(ALeaf, AIssuer, LResponse,
    TDateTimeUtilities.UnixMsToDateTime(Int64(FClock.NowUnixMillis)), LStatus,
    LThisUpdate, LNextUpdate) then
    Exit;
  case LStatus of
    TOcspStatus.Revoked:
      Result := TLiveRevocationOutcome.Revoked;
    TOcspStatus.Good:
      begin
        // honor the response validity window; a Good outside it is indeterminate
        LNowMs := Int64(FClock.NowUnixMillis);
        if (LNowMs >= TDateTimeUtilities.DateTimeToUnixMs(LThisUpdate)) and
          ((LNextUpdate = 0) or
          (LNowMs < TDateTimeUtilities.DateTimeToUnixMs(LNextUpdate))) then
          Result := TLiveRevocationOutcome.Good;
      end;
  end;
end;

function TLiveRevocationChecker.EvaluateCrl(const ALeaf, AIssuer: TBytes;
  const ACrlUrl: string): TLiveRevocationOutcome;
var
  LCrl: TBytes;
  LRevoked: Boolean;
begin
  Result := TLiveRevocationOutcome.Indeterminate;
  if (ACrlUrl = '') or (FFetcher = nil) then
    Exit;
  if not FFetcher.Get(ACrlUrl, FTimeoutMs, LCrl) then
    Exit;
  // an unparseable or issuer-unverifiable CRL is indeterminate, never trusted
  if not FProvider.Revocation.CheckCrlRevocation(ALeaf, AIssuer, LCrl, LRevoked) then
    Exit;
  if LRevoked then
    Result := TLiveRevocationOutcome.Revoked
  else
    Result := TLiveRevocationOutcome.Good;
end;

function TLiveRevocationChecker.Evaluate(
  const AChain: TArray<TBytes>): TLiveRevocationOutcome;
var
  LLeaf, LIssuer: TBytes;
  LUrl: string;
  LUrls: TArray<string>;
  LI: Int32;
begin
  Result := TLiveRevocationOutcome.Indeterminate;
  // Off suppresses the live fetch entirely (its network + privacy cost): no OCSP POST
  // and no CRL GET. The outcome is Indeterminate, which CheckChain accepts under Off (soft); a
  // stapled Revoked is still honored upstream by the built-in pipeline before the park.
  if FPosture = TRevocationPosture.Off then
    Exit;
  // a revocation check needs the issuer (next chain entry) to authenticate the response
  if System.Length(AChain) < 2 then
    Exit;
  LLeaf := AChain[0];
  LIssuer := AChain[1];

  if FMethod in [TLiveRevocationMethod.Ocsp, TLiveRevocationMethod.OcspThenCrl] then
    if FProvider.Revocation.TryGetOcspResponderUrl(LLeaf, LUrl) then
    begin
      Result := EvaluateOcsp(LLeaf, LIssuer, LUrl);
      if Result <> TLiveRevocationOutcome.Indeterminate then
        Exit; // a definitive Good or Revoked settles it
    end;

  if FMethod in [TLiveRevocationMethod.Crl, TLiveRevocationMethod.OcspThenCrl] then
    if FProvider.Revocation.TryGetCrlDistributionPoints(LLeaf, LUrls) then
      for LI := 0 to System.High(LUrls) do
      begin
        Result := EvaluateCrl(LLeaf, LIssuer, LUrls[LI]);
        if Result <> TLiveRevocationOutcome.Indeterminate then
          Exit;
      end;

  Result := TLiveRevocationOutcome.Indeterminate;
end;

function TLiveRevocationChecker.CheckChain(const AChain: TArray<TBytes>): Boolean;
begin
  case Evaluate(AChain) of
    TLiveRevocationOutcome.Revoked:
      Result := False; // a definitive revocation always rejects
    TLiveRevocationOutcome.Good:
      Result := True;
  else
    // indeterminate: soft-fail accepts (Soft/Off), hard-fail rejects (Hard)
    Result := FPosture <> TRevocationPosture.Hard;
  end;
end;

function TLiveRevocationChecker.ResolveVerdict(const AChain: TArray<TBytes>;
  const AHostName: string;
  out ARejectAlert: TTlsAlertDescription): Boolean;
begin
  // a definitive Revoked aborts with certificate_revoked always; an indeterminate hard-fail
  // aborts with bad_certificate_status_response (the same alert a hard stapled-OCSP fail sends)
  ARejectAlert := TTlsAlertDescription.BadCertificate;
  case Evaluate(AChain) of
    TLiveRevocationOutcome.Revoked:
      begin
        ARejectAlert := TTlsAlertDescription.CertificateRevoked;
        Result := False;
      end;
    TLiveRevocationOutcome.Good:
      Result := True;
  else
    // indeterminate: soft-fail accepts (Soft/Off), hard-fail rejects
    Result := FPosture <> TRevocationPosture.Hard;
    if not Result then
      ARejectAlert := TTlsAlertDescription.BadCertificateStatusResponse;
  end;
end;

end.
