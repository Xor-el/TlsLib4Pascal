{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpTrustTypes;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils;

type
  /// <summary>
  /// How a peer-certificate verdict is deferred out-of-band. None (the default) decides the
  /// verdict entirely inline. HostDecision parks the handshake after the built-in pipeline
  /// accepts the chain and raises a CertificateReceived event so a host decides out-of-band
  /// (e.g. an operator prompt); it is augment-only and does not change how an indeterminate
  /// stapled revocation outcome is decided (the posture still decides that inline).
  /// LiveRevocation additionally defers an indeterminate stapled outcome to the resolver at
  /// the park, so a live OCSP/CRL fetch renders the posture's verdict - the only way a Hard
  /// posture is reachable for a peer that carries no staple (e.g. a client certificate). Under
  /// LiveRevocation the park is skipped when the verifier already settled revocation inline (a
  /// current, authenticated Good staple), so the resolver sees only peers whose revocation is still
  /// undecided; a host that must observe every accepted peer (an audit hook, extra policy) uses
  /// HostDecision, which always parks.
  /// </summary>
  TVerdictDeferral = (None, HostDecision, LiveRevocation);

  /// <summary>Whether a certificate is being verified on the initial handshake (a Certificate
  /// flight is on the wire) or on a resumption (no Certificate; the stored chain is
  /// re-checked). Must-staple is enforced only on the initial handshake.</summary>
  TVerificationOccasion = (InitialHandshake, Resumption);

  /// <summary>How the built-in pipeline reached acceptance, as it bears on a live-revocation park.
  /// Trusted (the default) is the safe case: if a live-revocation park is configured, run it.
  /// RevocationSettledInline means the verifier reached a definitive, authenticated revocation
  /// verdict inline (e.g. a current Good staple carrying nextUpdate), so a configured
  /// live-revocation park would be redundant and the caller may skip it. A Good staple without
  /// nextUpdate is accepted inline but never settles - the park still runs (RFC 6960 4.2.2.1).
  /// Only a verifier that can settle revocation inline sets
  /// RevocationSettledInline; a delegate whose live check happens at the park always returns Trusted,
  /// so the park still runs. This never affects a host-decision park, which is a separate policy.</summary>
  TVerificationOutcome = (Trusted, RevocationSettledInline);

  /// <summary>The proof a certificate verifier returns on acceptance: the leaf-first path it
  /// validated (Path, with the leaf's issuer at index 1 where the validator can name it; the leaf
  /// alone under InsecureSkipVerify) and how acceptance was reached (Outcome). A verifier fills this
  /// only when it returns True; on rejection the caller reads the alert, not this record. A
  /// key-pinning check matches against Path, never the presented chain (RFC 7469 6).</summary>
  TVerifiedChain = record
    Path: TArray<TBytes>;
    Outcome: TVerificationOutcome;
    // zero the unmanaged Outcome to the safe default so a verifier that writes only Path (this is a
    // public seam) can never leave the park-skip driven by a garbage enum on an out parameter
    class operator Initialize({$IFDEF FPC}var{$ELSE}out{$ENDIF}
      AVerified: TVerifiedChain);
  end;

implementation

class operator TVerifiedChain.Initialize({$IFDEF FPC}var{$ELSE}out{$ENDIF}
  AVerified: TVerifiedChain);
begin
  AVerified.Outcome := TVerificationOutcome.Trusted;
end;

end.
