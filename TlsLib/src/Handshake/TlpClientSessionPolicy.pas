{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpClientSessionPolicy;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpDataEncoding,
  TlpTlsAlert,
  TlpExtensionVector,
  TlpHandshakeMessages,
  TlpICertificateTrust,
  TlpTrustTypes,
  TlpServerName,
  TlpTlsCredential,
  TlpISession;

type
  /// <summary>
  /// The version-neutral session-resumption decisions the client handshakes share: the
  /// session-ticket lifetime cap, the cache key, whether a cached ticket is still offerable,
  /// the offered-extension census, and the opt-in re-verification of a resumed server. Each
  /// is pure of connection state - it reads the session / configuration inputs and returns a
  /// value or aborts with the RFC-mandated alert - so the 1.2 and 1.3 client machines (and the
  /// two servers' ticket-emit paths) share one implementation.
  /// </summary>
  TClientSessionPolicy = class sealed(TObject)
  public
    /// <summary>Clamps a session-ticket lifetime to the seven-day ceiling: a server MUST NOT
    /// advertise or honour a value above it, and a client MUST NOT use one for longer, regardless
    /// of what was advertised (RFC 9846 4.7.1).</summary>
    class function ClampTicketLifetime(ALifetime: UInt32): UInt32; static;
    /// <summary>Whether the seven-day total lifetime of a resumption chain, counted from the full
    /// handshake that authenticated it (RFC 9846 4.7.1 recommends limiting it), has passed at
    /// ANowMs; the seventh day itself still counts, and a clock behind the authentication time
    /// counts as not yet lapsed.</summary>
    class function AuthenticationLapsed(AAuthenticatedAtMs, ANowMs: UInt64): Boolean; static;
    /// <summary>The lifetime in seconds a ticket may advertise: the configured one (clamped to
    /// seven days) cut to what remains of the chain's total lifetime, rounded up so it is zero
    /// only at the chain's last millisecond or once the authentication has lapsed; a caller mints
    /// no ticket for 0.</summary>
    class function RenewedTicketLifetime(ALifetime: UInt32;
      AAuthenticatedAtMs, ANowMs: UInt64): UInt32; static;
    /// <summary>The session-cache key for a server: the explicit identity when set, else the
    /// SNI host, with the configuration scope folded in so a cache shared with another
    /// configuration does not resume across the two (the #31 separator cannot occur in an
    /// identity).</summary>
    class function CacheIdentity(const AServerIdentity, AServerName: string;
      const AScope: TBytes): string; static;
    /// <summary>Whether a cached TLS 1.3 session is still offerable as a PSK: a zero lifetime
    /// means discard immediately, and a ticket past its (capped) lifetime, or whose chain's
    /// authentication has lapsed, is not offered (RFC 9846 4.7.1).</summary>
    class function IsOfferableTls13(const ASession: IResumableSession;
      ANowMs: UInt64): Boolean; static;
    /// <summary>Whether a cached TLS 1.2 session is still offerable: a ticket past its hinted
    /// (capped) lifetime, or whose chain's authentication has lapsed, is dropped (RFC 5077 3.3); a
    /// hint of 0 is unspecified, so it is held to the seven-day client ceiling instead of being
    /// discarded as in 1.3.</summary>
    class function IsOfferableTls12(const ASession: IResumableSession;
      ANowMs: UInt64): Boolean; static;
    /// <summary>The extension types a framed ClientHello offered: strips the 4-byte handshake
    /// header, decodes the hello, and returns the parsed extension type list. A resumed
    /// handshake replays these so a HelloRetryRequest / ServerHello extension is only accepted
    /// when it was actually offered.</summary>
    class function OfferedExtensionTypes(
      const AFramedClientHello: TBytes): TArray<UInt16>; static;
    /// <summary>Whether a cached session may be offered: always under ReuseOriginal or for a
    /// session a PSK authenticated (it has no chain); under Reverify only when its stored chain
    /// passes current trust (a resume carries no fresh Certificate or staple). Prefers the
    /// resumption-occasion verifier, falls back to the primary; False when neither is configured,
    /// the chain is empty or the verifier rejects it. APath carries the validated path on a
    /// pass. A verifier that raises fails the connection.</summary>
    class function SessionTrustedForOffer(AMode: TResumeVerification;
      const ASession: IResumableSession; const APrimary,
      AResume: IServerCertificateVerifier; const AName: TServerName;
      out APath: TArray<TBytes>): Boolean; static;
  end;

implementation

{ TClientSessionPolicy }

class function TClientSessionPolicy.ClampTicketLifetime(
  ALifetime: UInt32): UInt32;
begin
  Result := ALifetime;
  if Result > MaxTicketLifetimeSeconds then
    Result := MaxTicketLifetimeSeconds;
end;

class function TClientSessionPolicy.AuthenticationLapsed(AAuthenticatedAtMs,
  ANowMs: UInt64): Boolean;
begin
  Result := (ANowMs > AAuthenticatedAtMs) and
    ((ANowMs - AAuthenticatedAtMs) > UInt64(MaxTicketLifetimeSeconds) * 1000);
end;

class function TClientSessionPolicy.RenewedTicketLifetime(ALifetime: UInt32;
  AAuthenticatedAtMs, ANowMs: UInt64): UInt32;
var
  LElapsedMs, LRemainingMs: UInt64;
begin
  Result := ClampTicketLifetime(ALifetime);
  if AuthenticationLapsed(AAuthenticatedAtMs, ANowMs) then
    Exit(0);
  LElapsedMs := 0;
  if ANowMs > AAuthenticatedAtMs then
    LElapsedMs := ANowMs - AAuthenticatedAtMs;
  LRemainingMs := UInt64(MaxTicketLifetimeSeconds) * 1000 - LElapsedMs;
  if UInt64(Result) * 1000 > LRemainingMs then
    Result := UInt32((LRemainingMs + 999) div 1000);
end;

class function TClientSessionPolicy.CacheIdentity(const AServerIdentity,
  AServerName: string; const AScope: TBytes): string;
begin
  if AServerIdentity <> '' then
    Result := AServerIdentity
  else
    Result := AServerName;
  // fold the configuration scope into the key so a cache shared with another configuration does not
  // resume across the two (the separator is a control char that cannot occur in a server identity)
  if System.Length(AScope) > 0 then
    Result := Result + #31 + TDataEncoding.HexEncode(AScope);
end;

class function TClientSessionPolicy.IsOfferableTls13(
  const ASession: IResumableSession; ANowMs: UInt64): Boolean;
var
  LCappedLifetime: UInt32;
begin
  // a ticket past its lifetime is not offered (RFC 9846 4.7.1): the client drops the
  // expired PSK and does a full handshake rather than offer one the server will reject.
  // A zero lifetime means discard immediately, and the seven-day ceiling is enforced here
  // too so a ticket cached out-of-band cannot outlive the RFC bound.
  LCappedLifetime := ClampTicketLifetime(ASession.TicketLifetime);
  Result := (ASession.TicketLifetime > 0) and ((ANowMs - ASession.IssuedAtMillis) <=
    (UInt64(LCappedLifetime) * 1000)) and
    not AuthenticationLapsed(ASession.AuthenticatedAtMillis, ANowMs);
end;

class function TClientSessionPolicy.IsOfferableTls12(
  const ASession: IResumableSession; ANowMs: UInt64): Boolean;
var
  LCappedLifetime: UInt32;
begin
  // a 1.2 ticket past its hinted lifetime is dropped (RFC 5077 3.3); a hint of 0 is
  // unspecified, so it gets the seven-day client ceiling (RFC 9846 4.7.1) like any other session
  LCappedLifetime := ClampTicketLifetime(ASession.TicketLifetime);
  if LCappedLifetime = 0 then
    LCappedLifetime := MaxTicketLifetimeSeconds;
  Result := ((ANowMs - ASession.IssuedAtMillis) <= (UInt64(LCappedLifetime) * 1000)) and
    not AuthenticationLapsed(ASession.AuthenticatedAtMillis, ANowMs);
end;

class function TClientSessionPolicy.OfferedExtensionTypes(
  const AFramedClientHello: TBytes): TArray<UInt16>;
var
  LHello: TTlsClientHello;
  LVector: TExtensionVector;
begin
  // strip the 4-byte handshake header (type + uint24 length) to reach the body
  LHello := THandshakeMessages.DecodeClientHello(System.Copy(AFramedClientHello, 4,
    System.Length(AFramedClientHello) - 4));
  LVector := TExtensionVector.Parse(LHello.Extensions);
  Result := LVector.Types;
end;

class function TClientSessionPolicy.SessionTrustedForOffer(AMode: TResumeVerification;
  const ASession: IResumableSession; const APrimary,
  AResume: IServerCertificateVerifier; const AName: TServerName;
  out APath: TArray<TBytes>): Boolean;
var
  LVerifier: IServerCertificateVerifier;
  LAlert: TTlsAlertDescription;
  LVerified: TVerifiedChain;
begin
  Result := True;
  if (AMode <> TResumeVerification.Reverify) or (System.Length(ASession.PskIdentity) > 0) then
    Exit;
  // the resumption verifier applies no must-staple to a chain that carries no Certificate
  LVerifier := AResume;
  if LVerifier = nil then
    LVerifier := APrimary;
  // an unverifiable session is declined, and the full handshake's own verification decides
  LAlert := TTlsAlertDescription.BadCertificate;
  Result := (LVerifier <> nil) and (System.Length(ASession.PeerCertificates) > 0) and
    LVerifier.VerifyServerCertificate(ASession.PeerCertificates, AName, nil, LVerified, LAlert);
  if Result then
    APath := LVerified.ValidatedPath;
end;

end.
