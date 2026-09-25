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
  TlpTlsLibExceptions,
  TlpExtensionVector,
  TlpHandshakeMessages,
  TlpICertificateTrust,
  TlpTrustTypes,
  TlpServerName,
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
    /// advertise or honour a value above it, and a client MUST NOT cache one longer, regardless
    /// of what was advertised (RFC 8446 4.6.1).</summary>
    class function ClampTicketLifetime(ALifetime: UInt32): UInt32; static;
    /// <summary>The session-cache key for a server: the explicit identity when set, else the
    /// SNI host, with the configuration scope folded in so a cache shared with another
    /// configuration does not resume across the two (the #31 separator cannot occur in an
    /// identity).</summary>
    class function CacheIdentity(const AServerIdentity, AServerName: string;
      const AScope: TBytes): string; static;
    /// <summary>Whether a cached TLS 1.3 session is still offerable as a PSK: a zero lifetime
    /// means discard immediately, and a ticket past its (capped) lifetime is not offered
    /// (RFC 8446 4.6.1).</summary>
    class function IsOfferableTls13(const ASession: IResumableSession;
      ANowMs: UInt64): Boolean; static;
    /// <summary>Whether a cached TLS 1.2 session is still offerable: a ticket past its hinted
    /// (capped) lifetime is dropped (RFC 5077 3.3), but a hint of 0 is unspecified and still
    /// offered - the intentional divergence from the 1.3 rule.</summary>
    class function IsOfferableTls12(const ASession: IResumableSession;
      ANowMs: UInt64): Boolean; static;
    /// <summary>The extension types a framed ClientHello offered: strips the 4-byte handshake
    /// header, decodes the hello, and returns the parsed extension type list. A resumed
    /// handshake replays these so a HelloRetryRequest / ServerHello extension is only accepted
    /// when it was actually offered.</summary>
    class function OfferedExtensionTypes(
      const AFramedClientHello: TBytes): TArray<UInt16>; static;
    /// <summary>Re-verifies the stored chain of a server being resumed against current trust
    /// (opt-in ReverifyOnResume): a resumed handshake carries no fresh Certificate/OCSP staple.
    /// Prefers the resumption-occasion verifier, falls back to the primary; raises
    /// internal_error when neither is configured, and bad_certificate (or the verifier's alert)
    /// when the chain is empty or fails. On success APath carries the validated path.</summary>
    class procedure ReverifyResumedServer(const APrimary,
      AResume: IServerCertificateVerifier; const AChain: TArray<TBytes>;
      const AName: TServerName; out APath: TArray<TBytes>); static;
  end;

implementation

resourcestring
  SNoCertificateVerifier = 'no certificate verifier configured (fail-closed)';
  SUntrustedCertificate = 'the server certificate chain was not trusted';

{ TClientSessionPolicy }

class function TClientSessionPolicy.ClampTicketLifetime(
  ALifetime: UInt32): UInt32;
begin
  Result := ALifetime;
  if Result > MaxTicketLifetimeSeconds then
    Result := MaxTicketLifetimeSeconds;
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
  // a ticket past its lifetime is not offered (RFC 8446 4.6.1): the client drops the
  // expired PSK and does a full handshake rather than offer one the server will reject.
  // A zero lifetime means discard immediately, and the seven-day ceiling is enforced here
  // too so a ticket cached out-of-band cannot outlive the RFC bound.
  LCappedLifetime := ClampTicketLifetime(ASession.TicketLifetime);
  Result := (ASession.TicketLifetime > 0) and ((ANowMs - ASession.IssuedAtMillis) <=
    (UInt64(LCappedLifetime) * 1000));
end;

class function TClientSessionPolicy.IsOfferableTls12(
  const ASession: IResumableSession; ANowMs: UInt64): Boolean;
var
  LCappedLifetime: UInt32;
begin
  // a 1.2 ticket past its hinted lifetime is dropped (RFC 5077 3.3); a hint of 0 is
  // unspecified and still offered; the seven-day ceiling bounds an out-of-band session
  LCappedLifetime := ClampTicketLifetime(ASession.TicketLifetime);
  Result := (ASession.TicketLifetime = 0) or ((ANowMs - ASession.IssuedAtMillis) <=
    (UInt64(LCappedLifetime) * 1000));
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

class procedure TClientSessionPolicy.ReverifyResumedServer(const APrimary,
  AResume: IServerCertificateVerifier; const AChain: TArray<TBytes>;
  const AName: TServerName; out APath: TArray<TBytes>);
var
  LVerifier: IServerCertificateVerifier;
  LAlert: TTlsAlertDescription;
  LVerified: TVerifiedChain;
begin
  // prefer the resumption-occasion verifier (no must-staple on a chain with no Certificate);
  // fall back to the primary for a direct caller that wired only one
  LVerifier := AResume;
  if LVerifier = nil then
    LVerifier := APrimary;
  if LVerifier = nil then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.InternalError, @SNoCertificateVerifier);
  // a resumed handshake carries no fresh OCSP staple; re-check the stored chain against current
  // trust. An empty stored chain cannot be re-verified, so it fails closed
  LAlert := TTlsAlertDescription.BadCertificate;
  if (System.Length(AChain) = 0) or
    not LVerifier.VerifyServerCertificate(AChain, AName, nil, LVerified, LAlert) then
    raise EFatalAlertTlsLibException.CreateRes(LAlert, @SUntrustedCertificate);
  APath := LVerified.Path;
end;

end.
