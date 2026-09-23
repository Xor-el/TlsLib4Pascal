{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpPeerAuthentication;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpTlsAlert,
  TlpTlsVersion,
  TlpTlsLibExceptions,
  TlpArrayUtilities,
  TlpCryptoDomainTypes,
  TlpNegotiationTypes,
  TlpICryptoProvider,
  TlpIPkixProvider,
  TlpTrustTypes,
  TlpCertificateVerify;

type
  /// <summary>
  /// The version- and role-neutral peer-signature checks a handshake performs over a received
  /// signed structure (a TLS 1.3 CertificateVerify or a TLS 1.2 ServerKeyExchange / client
  /// CertificateVerify): validate the negotiated scheme against what the local side accepts and
  /// the leaf's signing policy, then verify the signature over caller-supplied content. Kept as
  /// two calls so a caller can interpose version-specific checks between them (the TLS 1.2 client
  /// binds the ServerKeyExchange curve before verifying); each machine builds the signed content
  /// itself (the content and its context string differ per role and message).
  /// </summary>
  TPeerAuthentication = class sealed(TObject)
  public
    /// <summary>Validates the peer's chosen signature scheme before a signature is verified: it
    /// must be one APermittedSchemes advertised (RFC 8446 4.4.3 / RFC 5246 7.4.8 - a scheme
    /// outside the accepted set is a wrong signature type), a scheme this build knows, and one
    /// valid to carry a handshake signature for AVersion (rsa_pkcs1_* is certificate-only in TLS
    /// 1.3). It then enforces ALeaf's signing policy for the scheme (digitalSignature keyUsage,
    /// key-family match, curve bound to the scheme under TLS 1.3). Raises illegal_parameter (or
    /// bad_certificate on keyUsage) on any failure and returns the resolved scheme.</summary>
    class function RequirePeerScheme(const APermittedSchemes: TArray<UInt16>;
      ASchemeCode: UInt16; AVersion: TTlsVersion;
      const ALeaf: IInspectedCertificate): TSignatureScheme; static;
    /// <summary>Verifies ASignature over AContent under AScheme with ALeaf's public key. The leaf
    /// is released (set nil) once the verifier has the key, so the ASN.1 graph is not pinned past
    /// its use. A failed verification is fatal decrypt_error. AScheme and ALeaf must already have
    /// passed RequirePeerScheme.</summary>
    class procedure VerifyPeerSignature(const ACryptoProvider: ICryptoProvider;
      var ALeaf: IInspectedCertificate; const AScheme: TSignatureScheme;
      const AContent, ASignature: TBytes); static;
    /// <summary>Whether an accepted peer chain should park for an out-of-band host verdict rather
    /// than continue inline: only when async verdicts are enabled, and not when the park is purely
    /// a live-revocation deferral that the verifier already settled inline. Applied identically by
    /// both roles and versions once the built-in pipeline has accepted the chain.</summary>
    class function ShouldPark(AAsyncVerdict, ALiveRevocationDeferral: Boolean;
      AOutcome: TVerificationOutcome): Boolean; static;
  end;

implementation

resourcestring
  SUnacceptedPeerScheme =
    'the peer signed with a scheme outside the accepted set';
  SLegacyPkcs1InHandshakeSignature =
    'rsa_pkcs1_* is certificate-only and must not carry a TLS 1.3 handshake signature';
  SPeerHandshakeSignatureInvalid =
    'the peer handshake signature did not verify';

{ TPeerAuthentication }

class function TPeerAuthentication.RequirePeerScheme(
  const APermittedSchemes: TArray<UInt16>; ASchemeCode: UInt16;
  AVersion: TTlsVersion; const ALeaf: IInspectedCertificate): TSignatureScheme;
begin
  if not (TArrayUtilities.Contains<UInt16>(APermittedSchemes, ASchemeCode)) then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.IllegalParameter, @SUnacceptedPeerScheme);
  if not TSignatureScheme.TryFromCode(ASchemeCode, Result) then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.IllegalParameter, @SUnacceptedPeerScheme);
  // rsa_pkcs1_* may be offered in TLS 1.3 for backward compatibility but must not sign a
  // handshake message there (RFC 8446 4.2.3); every scheme may sign a TLS 1.2 handshake
  if not Result.IsValidForHandshake(AVersion) then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.IllegalParameter, @SLegacyPkcs1InHandshakeSignature);
  // the leaf must permit digitalSignature and, for an rsa_pss_rsae_* scheme, not be an
  // id-RSASSA-PSS key; TLS 1.3 additionally binds an ecdsa_* scheme to the leaf's curve
  TCertificateVerify.EnforceSigningLeafPolicy(ALeaf, Result, AVersion.Equals(TTlsVersion.Tls13));
end;

class procedure TPeerAuthentication.VerifyPeerSignature(
  const ACryptoProvider: ICryptoProvider; var ALeaf: IInspectedCertificate;
  const AScheme: TSignatureScheme; const AContent, ASignature: TBytes);
var
  LPublicKeyInfo: TBytes;
  LVerifier: ISignatureVerifier;
begin
  LPublicKeyInfo := ALeaf.PublicKeyInfo;
  LVerifier := ACryptoProvider.Signing.CreateSignatureVerifier(AScheme, LPublicKeyInfo);
  LVerifier.Update(AContent, 0, System.Length(AContent));
  // the parsed leaf is no longer needed; release it rather than pin the ASN.1 graph
  ALeaf := nil;
  if not LVerifier.Verify(ASignature) then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.DecryptError, @SPeerHandshakeSignatureInvalid);
end;

class function TPeerAuthentication.ShouldPark(AAsyncVerdict,
  ALiveRevocationDeferral: Boolean; AOutcome: TVerificationOutcome): Boolean;
begin
  Result := AAsyncVerdict and not (ALiveRevocationDeferral and
    (AOutcome = TVerificationOutcome.RevocationSettledInline));
end;

end.
