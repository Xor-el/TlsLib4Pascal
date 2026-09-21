{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpOSLiveRevocation;

{$I ..\..\TlsLib\src\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpTlsAlert,
  TlpTrustPolicy,
  TlpSystemTrustBase,
  TlpLiveRevocation;

type
  /// <summary>
  /// The host-owned OS-native live-revocation resolver: it re-runs the platform trust engine with
  /// network fetch enabled - off the sans-IO engine thread, in the async-verdict park - and turns
  /// the platform's tri-state revocation outcome into an accept/reject verdict for the
  /// TCertificateVerdictResolver seam. The shared verdict logic (posture handling + an optional
  /// portable fallback on an indeterminate OS outcome) lives here; a platform subclass supplies
  /// EvaluateLive. Off posture does no fetch and accepts (the inline pipeline already settled trust
  /// and any definitive cached revocation). All per-call state is on the stack, so one instance is
  /// reusable across connections and threads; the only shared mutable is the host's fallback fetcher.
  /// </summary>
  TOSLiveRevocationResolver = class abstract(TObject)
  strict protected
    FPosture: TRevocationPosture;
    FExpectedPeer: TPeerRole;
    FFallback: TCertificateVerdictResolver;
    /// <summary>Runs the platform trust engine live (network on) at the configured posture,
    /// classifying the outcome: True with AOutcome in {Good, Revoked, Indeterminate}; False with
    /// ARejectAlert set on a definitive non-revocation trust failure the live path surfaced.</summary>
    function EvaluateLive(const AChain: TArray<TBytes>; const AHostName: string;
      const AStaple: TBytes; out AOutcome: TLiveRevocationOutcome;
      out ARejectAlert: TTlsAlertDescription): Boolean; virtual; abstract;
  public
    /// <summary>AExpectedPeer is the certificate role this resolver was built to evaluate (a
    /// server-config resolver binds server-auth EKU; a client-config resolver binds client-auth):
    /// a park for the other role is refused as a misconfiguration rather than evaluated.</summary>
    constructor Create(APosture: TRevocationPosture; AExpectedPeer: TPeerRole;
      const AFallback: TCertificateVerdictResolver);
    /// <summary>The TCertificateVerdictResolver seam entry: assign it to
    /// SetCertificateVerdictResolver or the adapter hook matching this resolver's role -
    /// VerdictResolver for a resolver built from a client config, ServerVerdictResolver for one
    /// built from a server config (a role mismatch is refused with internal_error).</summary>
    function ResolveVerdict(const ACtx: TCertificateVerdictContext;
      out ARejectAlert: TTlsAlertDescription): Boolean;
  end;

implementation

{ TOSLiveRevocationResolver }

constructor TOSLiveRevocationResolver.Create(APosture: TRevocationPosture;
  AExpectedPeer: TPeerRole; const AFallback: TCertificateVerdictResolver);
begin
  inherited Create;
  FPosture := APosture;
  FExpectedPeer := AExpectedPeer;
  FFallback := AFallback;
end;

function TOSLiveRevocationResolver.ResolveVerdict(
  const ACtx: TCertificateVerdictContext;
  out ARejectAlert: TTlsAlertDescription): Boolean;
var
  LOutcome: TLiveRevocationOutcome;
begin
  ARejectAlert := TTlsAlertDescription.BadCertificate;
  // this resolver's trust engine is bound to one certificate role (server-auth vs client-auth
  // EKU); a park for the other role cannot be evaluated here. Refuse it as a local
  // misconfiguration (internal_error, RFC 8446 6.2) rather than let it surface as a misleading
  // trust failure that would look like a rejected peer
  if ACtx.PeerRole <> FExpectedPeer then
  begin
    ARejectAlert := TTlsAlertDescription.InternalError;
    Exit(False);
  end;
  // Off suppresses the live fetch (its network + privacy cost); the inline pipeline already
  // settled trust and any definitive cached revocation, so accept
  if FPosture = TRevocationPosture.Off then
    Exit(True);
  // a definitive non-revocation trust failure from the live re-evaluation rejects outright. The
  // live re-check is revocation-only (identity was settled inline), so an IP literal is never
  // handed to the OS name logic - it would only ever spuriously fail to match. Re-run over the
  // validated path (when the pipeline produced one) so the OS engine sees the path the inline pass
  // completed, not an incomplete presented chain it cannot re-assemble with AIA disabled
  if not EvaluateLive(ACtx.RevocationPath, TDelegatePostChecks.OsHostName(ACtx.HostName),
    ACtx.OcspStaple, LOutcome, ARejectAlert) then
    Exit(False);
  case LOutcome of
    TLiveRevocationOutcome.Revoked:
      begin
        ARejectAlert := TTlsAlertDescription.CertificateRevoked;
        Result := False;
      end;
    TLiveRevocationOutcome.Good:
      Result := True;
  else
    // indeterminate: the OS could not fetch or decide. Defer to the portable fallback if one is
    // wired (OCSP/CRL over the host's IHttpFetcher), else apply the posture (Soft/Off accept,
    // Hard reject with bad_certificate_status_response).
    if System.Assigned(FFallback) then
      Result := FFallback(ACtx, ARejectAlert)
    else if FPosture = TRevocationPosture.Hard then
    begin
      ARejectAlert := TTlsAlertDescription.BadCertificateStatusResponse;
      Result := False;
    end
    else
      Result := True;
  end;
end;

end.
