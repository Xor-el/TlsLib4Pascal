{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpICertificateTrust;

{$I ..\..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpServerName,
  TlpTlsAlert;

type
  /// <summary>How the built-in pipeline reached acceptance, as it bears on a live-revocation park.
  /// Trusted (the default) is the safe case: if a live-revocation park is configured, run it.
  /// RevocationSettledInline means the verifier reached a definitive, authenticated revocation
  /// verdict inline (e.g. a current Good staple), so a configured live-revocation park would be
  /// redundant and the caller may skip it. Only a verifier that can settle revocation inline sets
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

  /// <summary>
  /// The set of trusted root certificates (DER), kept behind an interface so the
  /// PKIX backend's certificate types never reach the public surface.
  /// </summary>
  ITrustAnchorStore = interface(IInterface)
    ['{6F1D2A54-9C83-4E70-B1A6-3D7E0C5B94F2}']
    /// <summary>The trusted root CA certificates, DER-encoded.</summary>
    function RootCertificates: TArray<TBytes>;
  end;

  /// <summary>
  /// Decides whether a server's certificate chain is trusted for the name the
  /// client is connecting to (a client-side check). Fail-closed: the handshake
  /// proceeds only on an explicit positive verdict. On rejection it returns the
  /// fatal alert the caller must send (unknown_ca / certificate_expired /
  /// bad_certificate / unsupported_certificate).
  /// </summary>
  IServerCertificateVerifier = interface(IInterface)
    ['{2A9E6C14-5D73-4B80-A1F8-6C3E0D5B92A7}']
    /// <summary>True if AChain (leaf first, DER) is a trusted server certificate for
    /// AServerName; else False with AAlert set to the reason. AOcspStaple is the
    /// stapled OCSP response delivered in the handshake (empty when none), fed to the
    /// revocation step. On True, AVerified carries the validated path and how acceptance was
    /// reached (see TVerifiedChain); on False AVerified is empty and the caller reads AAlert.</summary>
    function VerifyServerCertificate(const AChain: TArray<TBytes>;
      const AServerName: TServerName; const AOcspStaple: TBytes;
      out AVerified: TVerifiedChain;
      out AAlert: TTlsAlertDescription): Boolean;
  end;

  /// <summary>
  /// Decides whether a client's certificate chain is trusted (a server-side mTLS
  /// check). There is no host identity or OCSP staple for a client certificate.
  /// Fail-closed, returning the fatal alert to send on rejection.
  /// </summary>
  IClientCertificateVerifier = interface(IInterface)
    ['{7B4C1E93-2F60-4A18-9D3B-5E8A0C2F41D6}']
    /// <summary>True if AChain (leaf first, DER) is a trusted client certificate;
    /// else False with AAlert set to the reason. On True, AVerified carries the validated path and
    /// how acceptance was reached (see TVerifiedChain); on False AVerified is empty.</summary>
    function VerifyClientCertificate(const AChain: TArray<TBytes>;
      out AVerified: TVerifiedChain;
      out AAlert: TTlsAlertDescription): Boolean;
  end;

implementation

class operator TVerifiedChain.Initialize({$IFDEF FPC}var{$ELSE}out{$ENDIF}
  AVerified: TVerifiedChain);
begin
  AVerified.Outcome := TVerificationOutcome.Trusted;
end;

end.
