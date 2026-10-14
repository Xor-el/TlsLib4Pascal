{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpCertificateVerify;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpTlsAlert,
  TlpTlsLibExceptions,
  TlpCryptoDomainTypes,
  TlpPkixDomainTypes,
  TlpNegotiationTypes,
  TlpICertificateTrust,
  TlpTrustTypes,
  TlpIPkixProvider;

type
  /// <summary>Which side's CertificateVerify context string the signed content carries: the
  /// server's or the client's (RFC 9846 4.5.2).</summary>
  TCertificateVerifySide = (Server, Client);

  /// <summary>
  /// Builds the CertificateVerify to-be-signed content (RFC 9846 4.5.2): 64 octets
  /// of 0x20, the role context string, a 0x00 separator, then the transcript hash
  /// through the Certificate message. Both the signer (server) and the verifier
  /// (client) construct the identical bytes.
  /// </summary>
  TCertificateVerify = class sealed(TObject)
  strict private
  const
    ServerContext = 'TLS 1.3, server CertificateVerify';
    ClientContext = 'TLS 1.3, client CertificateVerify';
  strict private
    class function EcdsaSchemeNamedGroup(const AScheme: TSignatureScheme): UInt16; static;
  public
    /// <summary>The signed content for ASide's CertificateVerify over ATranscriptHash.</summary>
    class function SignatureContent(ASide: TCertificateVerifySide;
      const ATranscriptHash: TBytes): TBytes; static;
    /// <summary>Enforces the peer leaf's signing policy before verifying a handshake
    /// signature (a CertificateVerify, or a 1.2 ServerKeyExchange): the leaf must permit
    /// digitalSignature if it carries keyUsage (RFC 5280 4.2.1.3), the scheme's key family
    /// must match the leaf key's family (an EC leaf cannot sign rsa_pss_rsae_*, etc.). When
    /// ABindEcdsaCurve is set (TLS 1.3), an ecdsa_* scheme additionally requires the leaf
    /// EC key to be on the scheme's named curve (RFC 9846 4.3.3) - TLS 1.2 leaves the curve
    /// to the supported_groups list, so it passes False. Applies symmetrically to a client
    /// verifying the server leaf and a server verifying the client leaf.</summary>
    class procedure EnforceSigningLeafPolicy(const ALeaf: IInspectedCertificate;
      const AScheme: TSignatureScheme; ABindEcdsaCurve: Boolean); static;
    /// <summary>Parses a peer leaf, rejecting one that is not a well-formed X.509
    /// certificate with a decode_error alert, and one whose key is id-RSASSA-PSS with an
    /// unsupported_certificate alert, before it reaches signature verification or
    /// the trust pipeline, and returns the parsed handle so the caller reuses the single
    /// decode. Applies to a received server or client leaf. It runs ahead of the per-entry
    /// extension checks, so a PSS leaf with an unsupported extension gets unsupported_certificate.</summary>
    class function ParseWellFormedLeaf(const AInspector: ICertificateInspector;
      const ALeafCertificate: TBytes): IInspectedCertificate; static;
    /// <summary>The single fail-closed gate for a received client certificate chain, shared by
    /// both server versions: a nil verifier is a server misconfiguration and raises internal_error
    /// (there is no basis to trust the chain); otherwise it returns the verifier's verdict with
    /// AAlert set on rejection. On acceptance AVerified carries the PKIX-validated path (leaf first,
    /// with the recovered issuer and anchor where nameable) and how acceptance was reached, so a
    /// caller parks or reports the validated path rather than the raw presented chain.</summary>
    class function VerifyClientChain(const AVerifier: IClientCertificateVerifier;
      const AChain: TArray<TBytes>; out AVerified: TVerifiedChain;
      out AAlert: TTlsAlertDescription): Boolean; static;
  end;

implementation

resourcestring
  SLeafKeyUsageForbidsSigning =
    'the peer certificate keyUsage does not permit digitalSignature';
  SPssLeafKeyUnsupported =
    'an id-RSASSA-PSS leaf key is not supported: no rsa_pss_pss_* scheme is offered';
  SEcdsaSchemeCurveMismatch =
    'the ecdsa_* signature scheme requires a leaf key on the scheme''s named curve';
  SSchemeKeyFamilyMismatch =
    'the signature scheme does not match the leaf key algorithm family';
  SUnparseableLeafCertificate =
    'the peer leaf is not a well-formed X.509 certificate';
  SNoClientCertificateVerifier =
    'no client certificate verifier configured (fail-closed)';

{ TCertificateVerify }

class function TCertificateVerify.VerifyClientChain(
  const AVerifier: IClientCertificateVerifier; const AChain: TArray<TBytes>;
  out AVerified: TVerifiedChain; out AAlert: TTlsAlertDescription): Boolean;
begin
  AAlert := TTlsAlertDescription.InternalError;
  AVerified := Default(TVerifiedChain);
  if AVerifier = nil then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.InternalError, @SNoClientCertificateVerifier);
  Result := AVerifier.VerifyClientCertificate(AChain, AVerified, AAlert);
end;

class function TCertificateVerify.ParseWellFormedLeaf(
  const AInspector: ICertificateInspector;
  const ALeafCertificate: TBytes): IInspectedCertificate;
var
  LSubject, LIssuer, LCommonName, LSerialHex: string;
begin
  // the catch-all except covers uncaught backend exception types from the ASN.1 decode
  try
    Result := AInspector.Parse(ALeafCertificate);
  except
    raise EDecodeErrorTlsLibException.CreateRes(@SUnparseableLeafCertificate);
  end;
  // PeerInfo probes the whole certificate and never raises: False means a field is not a
  // well-formed X.509 structure, so reject it before any downstream cert use.
  if not Result.PeerInfo(LSubject, LIssuer, LCommonName, LSerialHex) then
    raise EDecodeErrorTlsLibException.CreateRes(@SUnparseableLeafCertificate);
  // an id-RSASSA-PSS key fits only rsa_pss_pss_*, which is never offered (RFC 9846 4.3.3)
  if Result.KeyIsRsaPss = TCertAnswer.Yes then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.UnsupportedCertificate, @SPssLeafKeyUnsupported);
end;

class function TCertificateVerify.SignatureContent(ASide: TCertificateVerifySide;
  const ATranscriptHash: TBytes): TBytes;
var
  LContext: TBytes;
  LPos: Int32;
begin
  if ASide = TCertificateVerifySide.Server then
    LContext := TEncoding.ASCII.GetBytes(ServerContext)
  else
    LContext := TEncoding.ASCII.GetBytes(ClientContext);

  SetLength(Result, 64 + System.Length(LContext) + 1 +
    System.Length(ATranscriptHash));
  FillChar(Result[0], 64, $20);
  LPos := 64;
  if System.Length(LContext) > 0 then
    Move(LContext[0], Result[LPos], System.Length(LContext));
  Inc(LPos, System.Length(LContext));
  Result[LPos] := $00;
  Inc(LPos);
  if System.Length(ATranscriptHash) > 0 then
    Move(ATranscriptHash[0], Result[LPos], System.Length(ATranscriptHash));
end;

class function TCertificateVerify.EcdsaSchemeNamedGroup(
  const AScheme: TSignatureScheme): UInt16;
begin
  // the IANA supported_groups code the ecdsa_* scheme's curve maps to; 0 when not ecdsa
  case AScheme of
    TSignatureScheme.ECDSA_SECP256R1_SHA256: Result := TNamedGroupCatalog.Secp256r1;
    TSignatureScheme.ECDSA_SECP384R1_SHA384: Result := TNamedGroupCatalog.Secp384r1;
    TSignatureScheme.ECDSA_SECP521R1_SHA512: Result := TNamedGroupCatalog.Secp521r1;
  else
    Result := 0;
  end;
end;

class procedure TCertificateVerify.EnforceSigningLeafPolicy(
  const ALeaf: IInspectedCertificate; const AScheme: TSignatureScheme;
  ABindEcdsaCurve: Boolean);
var
  LKind: TSignatureKeyKind;
  LKindKnown: Boolean;
  LCertGroup, LSchemeGroup: UInt16;
begin
  // the caller passes the leaf already parsed by ParseWellFormedLeaf, answering every
  // signing-policy query from that one decode. A keyUsage that cannot be decoded fails like a
  // clear bit (stricter local policy; RFC 5280 4.2 mandates it only for critical extensions);
  // the other queries pass an Undetermined answer (fail-open per check)
  if ALeaf.KeyUsagePermits(TCertKeyUsage.DigitalSignature) <> TCertAnswer.Yes then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.BadCertificate, @SLeafKeyUsageForbidsSigning);
  // the signature scheme's key family must match the leaf key's family: an EC leaf under
  // rsa_pss_rsae_*, or an RSA leaf under ecdsa_*, is a wrong-signature-type (RFC 9846 4.3.3).
  // A leaf key the provider cannot classify passes (fail-open); the provider seam is the backstop.
  LKindKnown := ALeaf.KeyKind(LKind, LCertGroup);
  if LKindKnown and (LKind <> AScheme.KeyKind) then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.IllegalParameter, @SSchemeKeyFamilyMismatch);
  // TLS 1.3 binds the ECDSA curve to the signature scheme: an ecdsa_secp384r1_sha384
  // signature made by a P-256 leaf key is a wrong-signature-type (RFC 9846 4.3.3)
  if ABindEcdsaCurve then
  begin
    LSchemeGroup := EcdsaSchemeNamedGroup(AScheme);
    if (LSchemeGroup <> 0) and LKindKnown and
      (LKind = TSignatureKeyKind.Ecdsa) and (LCertGroup <> LSchemeGroup) then
      raise EFatalAlertTlsLibException.CreateRes(
        TTlsAlertDescription.IllegalParameter, @SEcdsaSchemeCurveMismatch);
  end;
end;

end.
