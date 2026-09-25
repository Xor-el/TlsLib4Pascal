{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpTrustPolicy;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpTlsAlert,
  TlpIPkixProvider,
  TlpIClock,
  TlpTrustTypes,
  TlpICertificateTrust,
  TlpCertificateLimits,
  TlpCertificateStrengthPolicy;

type
  /// <summary>
  /// The revocation-checking posture for the stapled OCSP response (RFC 6960),
  /// consumed in-band from the handshake - no network. The posture governs only how an
  /// unknown/indeterminate outcome is treated; a definitive, authenticated Revoked is
  /// always rejected under every posture. Soft (the default) accepts a missing or
  /// indeterminate staple; Hard rejects anything short of a
  /// current Good staple (bad_certificate_status_response); Off does not require a stapled
  /// OCSP response (a missing or indeterminate staple is accepted), but still rejects a
  /// definitive Revoked. Must-staple (RFC 7633) is enforced at the TLS layer independently of
  /// this setting, but only for an initial-handshake server certificate the client requested a
  /// staple for (never a client certificate, never on a resumption).
  /// </summary>
  TRevocationPosture = (Soft, Hard, Off);

  /// <summary>The result of a revocation check for one certificate: a definitive Good or Revoked,
  /// or Indeterminate when no authoritative status was obtained (missing/expired/unreachable).</summary>
  TLiveRevocationOutcome = (Good, Revoked, Indeterminate);

  /// <summary>
  /// The one revocation-decision table every verifier and resolver applies: a definitive Revoked
  /// rejects under every posture (certificate_revoked); a Good accepts; an Indeterminate accepts
  /// unless the posture is Hard and the decision is not deferred to a live check, in which case it
  /// rejects (bad_certificate_status_response). Deferral to a live check is expressed by evaluating
  /// at an effective posture of Soft, so the handshake reaches the park where the live result is
  /// decided at the configured posture.
  /// </summary>
  /// <summary>How current a Good OCSP response is: Fresh (within its nextUpdate window),
  /// Unbounded (no nextUpdate but recent enough to accept inline, never to settle revocation -
  /// RFC 6960 4.2.2.1 says newer information is then always available), or Stale.</summary>
  TOcspFreshness = (Fresh, Unbounded, Stale);

  TRevocationDecision = class sealed(TObject)
  public
    /// <summary>A Good response without nextUpdate is accepted inline only if its thisUpdate is
    /// within this age; beyond it the response is Stale.</summary>
    const OcspUnboundedMaxAgeMs = Int64(7) * 24 * 60 * 60 * 1000;
    /// <summary>Classifies a Good OCSP response by its window. All times are Unix milliseconds;
    /// ANextUpdateMs = 0 means the response carried no nextUpdate.</summary>
    class function OcspFreshness(ANowMs, AThisUpdateMs,
      ANextUpdateMs: Int64): TOcspFreshness; static;
    /// <summary>The posture an inline evaluation runs at: Hard becomes Soft while the indeterminate
    /// case is deferred to a live check; otherwise the configured posture.</summary>
    class function EffectivePosture(APosture: TRevocationPosture;
      ADeferToLive: Boolean): TRevocationPosture; static;
    /// <summary>True to accept; False with AAlert (certificate_revoked for Revoked,
    /// bad_certificate_status_response for an undeferred Indeterminate under Hard). AAlert is
    /// untouched on True.</summary>
    class function Decide(AOutcome: TLiveRevocationOutcome; APosture: TRevocationPosture;
      ADeferToLive: Boolean; out AAlert: TTlsAlertDescription): Boolean; static;
    /// <summary>True when a Hard posture can only be satisfied by a live-revocation verdict: an
    /// indeterminate outcome (no staple) is decided inline by posture unless deferred to a live
    /// check, so an undeferred Hard rejects every staple-less peer.</summary>
    class function HardNeedsLiveRevocation(APosture: TRevocationPosture;
      ADeferToLive: Boolean): Boolean; static;
  end;

  /// <summary>
  /// An augment-only peer-certificate check the caller supplies: it runs after the
  /// built-in pipeline (PKIX, revocation, endpoint identity, pinning) has already
  /// passed and can only additionally reject (return False) - it can never turn a
  /// rejected chain into an accepted one. AChain is the peer chain (leaf first, DER);
  /// AHostName is the expected host (empty on the server side). This is how a host
  /// framework's own verify hook is bridged without loosening our trust decision.
  /// </summary>
  TTlsCertificateVerifyCallback = function(const AChain: TArray<TBytes>;
    const AHostName: string): Boolean of object;

  /// <summary>
  /// The escape hatches that deliberately weaken or extend trust, grouped so they read
  /// as one loud, opt-in surface. InsecureSkipVerify makes an otherwise-untrusted chain
  /// pass (it bypasses PKIX, revocation, endpoint identity, and pinning) and must never
  /// ship in production - it exists for tests and pinned/self-signed development peers.
  /// VerifyCallback is the augment-only hook (it can only additionally reject). When both
  /// are set the callback still runs, so a caller can skip the built-in pipeline yet keep
  /// a bespoke reject rule.
  /// </summary>
  TDangerousTrust = record
    InsecureSkipVerify: Boolean;
    VerifyCallback: TTlsCertificateVerifyCallback;
    // zero the unmanaged method pointer so no construction path leaves it garbage
    class operator Initialize({$IFDEF FPC}var{$ELSE}out{$ENDIF}
      AOptions: TDangerousTrust);
  end;

  /// <summary>Whose certificate a parked verdict concerns. Server: we are the client and the chain
  /// is the server's, matched against HostName. Client: we are the server and the chain is an mTLS
  /// client's, with no host identity to match. A resolver that evaluates a role-specific trust
  /// engine (an OS-native live check binds the server-auth or client-auth EKU) must branch on this
  /// rather than assume a role - the same process may run both a client and an mTLS server. Unknown
  /// is the zero value so a hand-built context that forgets to set the role fails a role-specific
  /// resolver's check closed rather than defaulting to a wrong role.</summary>
  TPeerRole = (Unknown, Server, Client);

  /// <summary>
  /// The asynchronous certificate-verdict setting. When Deferral is not None, the engine runs
  /// its built-in trust pipeline synchronously and, only if that pipeline accepts
  /// the peer chain, parks the handshake so a host or a live-revocation resolver can decide
  /// out-of-band and resume with SetCertificateVerdict. This is augment-only: the verdict can
  /// only additionally reject, never resurrect a chain the pipeline already rejected. The park
  /// is fail-closed - no verdict or a rejection aborts the handshake. DeadlineMs is the time
  /// budget a resolver built from this config is given (the Windows live resolver bounds its URL
  /// retrieval by it; Apple exposes no per-evaluation timeout, so there it is informational);
  /// neither the engine nor the stream drivers enforce it - a resolver that cannot decide within
  /// its budget returns False. None (the default) keeps the verdict inline.
  /// </summary>
  TAsyncCertificateVerdict = record
    Deferral: TVerdictDeferral;
    DeadlineMs: Cardinal;
  end;

  /// <summary>
  /// What an out-of-band verdict resolver receives for a parked peer certificate: whose chain it
  /// is (PeerRole); the chain as the peer presented it (Chain, leaf first, DER); the leaf-first path
  /// the built-in pipeline validated (ValidatedPath, with the leaf's issuer at index 1 and the
  /// anchor where nameable); the expected host (empty on the server side); and the handshake OCSP
  /// staple (empty when none) so a live check can skip a fetch the server already answered in-band.
  /// A revocation check should authenticate against RevocationPath (ValidatedPath when the pipeline
  /// produced one, else the presented Chain), so the responder is bound to the issuer PKIX already
  /// authenticated rather than a re-guess. A client certificate may also carry a staple (RFC 8446
  /// 4.4.2.1 lets a server request status_request of a client), so the staple is not a role signal -
  /// branch on PeerRole. A caller that hand-builds this record MUST set PeerRole (a role-specific
  /// resolver refuses the unset Unknown value); ValidatedPath may be left empty, and RevocationPath
  /// then falls back to Chain.
  /// </summary>
  TCertificateVerdictContext = record
    PeerRole: TPeerRole;
    Chain: TArray<TBytes>;
    ValidatedPath: TArray<TBytes>;
    HostName: string;
    OcspStaple: TBytes;
    /// <summary>The path a revocation check should authenticate against: the validated path when
    /// the pipeline produced one, else the presented chain (never the reverse, so a hand-built
    /// context that set only Chain keeps its meaning).</summary>
    function RevocationPath: TArray<TBytes>;
  end;

  /// <summary>
  /// Decides a parked peer-certificate verdict out-of-band (RFC 8446 deferred-verdict seam).
  /// Return True to continue the handshake, False to abort it; on False, ARejectAlert selects
  /// the abort alert (default bad_certificate; a definitive live-revocation reject sets
  /// certificate_revoked). The resolver owns any deadline: a check that cannot decide in time
  /// returns False (fail-closed). Reached only when a verdict-deferral mode is set.
  /// </summary>
  TCertificateVerdictResolver = function(const ACtx: TCertificateVerdictContext;
    out ARejectAlert: TTlsAlertDescription): Boolean of object;

  /// <summary>
  /// The trust parameters the engine gathers once from the frozen config and hands a
  /// verifier source to build the server-certificate verifier for a connection. The clock
  /// and posture are carried here so a source injects them when it constructs its verifier
  /// (the built-in and the OS-native delegate alike). SPKI pinning is applied by a decorator
  /// over the source output, so no pins appear here. The factory builds one verifier per
  /// occasion (an initial-handshake verifier and, for reverify-on-resume, a second
  /// Occasion=Resumption verifier), so must-staple binds only where a Certificate is
  /// actually on the wire.
  /// </summary>
  TServerTrustContext = record
    Pkix: IPkixProvider;
    Clock: ITlsClock;
    TrustStore: ITrustAnchorStore;
    CheckHostName: Boolean;
    ChainLimits: TCertificateChainLimits;
    RevocationPosture: TRevocationPosture;
    Dangerous: TDangerousTrust;
    Deferral: TVerdictDeferral;
    Intermediates: TArray<TBytes>;
    StrengthPolicy: TCertificateStrengthPolicy;
    AdvertisedSignatureSchemes: TArray<UInt16>;
    /// <summary>Whether the client offered status_request on this connection: must-staple is
    /// enforced only when it did (RFC 7633 4.3.3 binds the requirement to the client's ask).</summary>
    StatusRequestOffered: Boolean;
    Occasion: TVerificationOccasion;
  end;

  /// <summary>
  /// The trust parameters the engine hands a source to build the client-certificate verifier
  /// for an mTLS connection. TrustStore is the configured client-CA anchor set; there is no
  /// host identity to match (a client certificate is never checked against a name) and no
  /// stapled OCSP (a client certificate is not stapled). An OS-native delegate treats TrustStore
  /// as an exclusive trust root, so a client is authenticated only against these anchors, never
  /// the OS/public-web-PKI roots.
  /// </summary>
  TClientTrustContext = record
    Pkix: IPkixProvider;
    Clock: ITlsClock;
    TrustStore: ITrustAnchorStore;
    ChainLimits: TCertificateChainLimits;
    RevocationPosture: TRevocationPosture;
    Dangerous: TDangerousTrust;
    Deferral: TVerdictDeferral;
    Intermediates: TArray<TBytes>;
    StrengthPolicy: TCertificateStrengthPolicy;
    AdvertisedSignatureSchemes: TArray<UInt16>;
  end;

implementation

class operator TDangerousTrust.Initialize({$IFDEF FPC}var{$ELSE}out{$ENDIF}
  AOptions: TDangerousTrust);
begin
  AOptions.InsecureSkipVerify := False;
  AOptions.VerifyCallback := nil;
end;

function TCertificateVerdictContext.RevocationPath: TArray<TBytes>;
begin
  // prefer the pipeline-validated path (issuer authenticated at index 1); fall back to the
  // presented chain so a hand-built context that set only Chain still resolves
  if System.Length(ValidatedPath) > 0 then
    Result := ValidatedPath
  else
    Result := Chain;
end;

{ TRevocationDecision }

class function TRevocationDecision.OcspFreshness(ANowMs, AThisUpdateMs,
  ANextUpdateMs: Int64): TOcspFreshness;
begin
  if ANowMs < AThisUpdateMs then
    Result := TOcspFreshness.Stale // not yet valid
  else if ANextUpdateMs <> 0 then
  begin
    if ANowMs < ANextUpdateMs then
      Result := TOcspFreshness.Fresh
    else
      Result := TOcspFreshness.Stale;
  end
  else if (ANowMs - AThisUpdateMs) <= OcspUnboundedMaxAgeMs then
    Result := TOcspFreshness.Unbounded
  else
    Result := TOcspFreshness.Stale;
end;

class function TRevocationDecision.EffectivePosture(APosture: TRevocationPosture;
  ADeferToLive: Boolean): TRevocationPosture;
begin
  if ADeferToLive and (APosture = TRevocationPosture.Hard) then
    Result := TRevocationPosture.Soft
  else
    Result := APosture;
end;

class function TRevocationDecision.Decide(AOutcome: TLiveRevocationOutcome;
  APosture: TRevocationPosture; ADeferToLive: Boolean;
  out AAlert: TTlsAlertDescription): Boolean;
begin
  case AOutcome of
    TLiveRevocationOutcome.Revoked:
      begin
        AAlert := TTlsAlertDescription.CertificateRevoked;
        Result := False;
      end;
    TLiveRevocationOutcome.Good:
      Result := True;
  else
    // Indeterminate: reject only under an effective Hard posture (a Hard check not deferred to a
    // live one); Soft/Off, or a deferred Hard, accept and let the live check (if any) decide
    Result := EffectivePosture(APosture, ADeferToLive) <> TRevocationPosture.Hard;
    if not Result then
      AAlert := TTlsAlertDescription.BadCertificateStatusResponse;
  end;
end;

class function TRevocationDecision.HardNeedsLiveRevocation(APosture: TRevocationPosture;
  ADeferToLive: Boolean): Boolean;
begin
  Result := (APosture = TRevocationPosture.Hard) and (not ADeferToLive);
end;

end.
