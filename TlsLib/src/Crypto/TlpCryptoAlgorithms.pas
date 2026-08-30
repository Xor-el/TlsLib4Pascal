{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpCryptoAlgorithms;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpTlsVersion,
  TlpTlsLibExceptions;

type
  /// <summary>
  /// The hash / digest algorithms the library selects between. The constant names
  /// carry separators so they round-trip to the provider backend by name (e.g.
  /// SHA_256 -> "SHA-256"); they are internal identifiers, never on the wire.
  /// </summary>
  THashAlgorithm = (SHA_256, SHA_384, SHA_512);

  /// <summary>The AEAD ciphers the library selects between (internal identifiers).</summary>
  TAeadAlgorithm = (AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305);

  /// <summary>An AEAD's usage-limit family: AES-GCM must proactively rekey by a
  /// record-count bound, ChaCha20-Poly1305 is bounded only by the record sequence.</summary>
  TAeadUsageCategory = (AesGcm, ChaCha20);

  /// <summary>The Diffie-Hellman key-agreement primitives (X25519 and NIST prime curves).</summary>
  TKeyAgreementAlgorithm = (X25519, SECP256R1, SECP384R1, SECP521R1);

  /// <summary>The key-encapsulation primitives.</summary>
  TKemAlgorithm = (ML_KEM_768);

  /// <summary>
  /// The revocation verdict an OCSP response reports for a certificate (RFC 6960
  /// sec. 2.2): Good, Revoked, or Unknown. Crosses the provider seam so the OCSP
  /// ASN.1 handling stays inside the provider.
  /// </summary>
  TOcspStatus = (Good, Revoked, Unknown);

  /// <summary>
  /// The X.509 keyUsage bits (RFC 5280 4.2.1.3) a TLS handshake consults: whether a
  /// leaf may sign (DigitalSignature), receive a transported key (KeyEncipherment),
  /// or perform static key agreement (KeyAgreement). Crosses the provider seam so the
  /// certificate ASN.1 handling stays inside the provider.
  /// </summary>
  TCertKeyUsage = (DigitalSignature, KeyEncipherment, KeyAgreement);

  /// <summary>
  /// The public-key algorithm of a certificate's leaf key, classified across the provider
  /// seam so the certificate ASN.1 handling stays inside the provider: an RSA key
  /// (rsaEncryption or id-RSASSA-PSS), an ECDSA key on a named curve, or an EdDSA key.
  /// Only recognized kinds are listed - a key the provider cannot classify is reported by
  /// the seam returning False (not by a catch-all member that would imply a real category).
  /// Used to match a certificate against a TLS 1.2 suite's auth method and to bind an ECDSA
  /// signature scheme's curve to the leaf key's curve (RFC 8446 4.2.3).
  /// </summary>
  TCertKeyKind = (Rsa, Ecdsa, Ed25519, Ed448);

  /// <summary>Fail-closed answer to a Boolean certificate query: Undetermined when the
  /// certificate or the queried field is malformed, otherwise No / Yes.</summary>
  TCertAnswer = (Undetermined, No, Yes);

  /// <summary>
  /// How a named group performs its key exchange: Ecdhe is a classical ephemeral
  /// ECDH curve, Kem a standalone key-encapsulation mechanism, Hybrid a
  /// combinator of the two. Only Ecdhe groups are eligible for a TLS 1.2
  /// handshake; Kem and Hybrid groups are TLS 1.3 only.
  /// </summary>
  TNamedGroupKind = (Ecdhe, Kem, Hybrid);

  /// <summary>
  /// The TLS 1.3 signature schemes (RFC 8446 4.2.3). Unlike the primitives above,
  /// a scheme is a wire value carried in the signature_algorithms extension, so it
  /// has a 2-byte codepoint (see the record helper).
  /// </summary>
  TSignatureScheme = (
    ECDSA_SECP256R1_SHA256,
    ECDSA_SECP384R1_SHA384,
    ECDSA_SECP521R1_SHA512,
    ED25519,
    ED448,
    RSA_PSS_RSAE_SHA256,
    RSA_PSS_RSAE_SHA384,
    RSA_PSS_RSAE_SHA512,
    RSA_PKCS1_SHA256,
    RSA_PKCS1_SHA384,
    RSA_PKCS1_SHA512);

  /// <summary>Wire-codepoint codec for the signature scheme (RFC 8446 4.2.3).</summary>
  TSignatureSchemeHelper = record helper for TSignatureScheme
  public
    /// <summary>The scheme's 2-byte SignatureScheme codepoint.</summary>
    function ToCode: UInt16;
    /// <summary>Maps a codepoint to a known scheme; False if unrecognized.</summary>
    class function TryFromCode(ACode: UInt16;
      out AScheme: TSignatureScheme): Boolean; static;
    /// <summary>True for the rsa_pss_rsae_* schemes, which require an rsaEncryption
    /// leaf key rather than an id-RSASSA-PSS one (RFC 8446 4.2.3).</summary>
    function IsRsaPssRsae: Boolean;
    /// <summary>True for the legacy rsa_pkcs1_* schemes. RFC 8446 4.2.3 defines these
    /// solely for signatures in certificates: they are valid for a TLS 1.2 handshake
    /// signature but MUST NOT sign or verify a TLS 1.3 CertificateVerify.</summary>
    function IsRsaPkcs1: Boolean;
    /// <summary>Whether this scheme may carry a handshake signature at the given TLS
    /// version. All schemes are valid in TLS 1.2; the legacy rsa_pkcs1_* schemes are
    /// certificate-only in TLS 1.3 (RFC 8446 4.2.3).</summary>
    function IsValidForHandshake(const AVersion: TTlsVersion): Boolean;
  end;

implementation

resourcestring
  SNoSchemeCode = 'signature scheme enum value %d has no wire codepoint';

{ TSignatureSchemeHelper }

function TSignatureSchemeHelper.ToCode: UInt16;
begin
  case Self of
    TSignatureScheme.ECDSA_SECP256R1_SHA256:
      Result := $0403;
    TSignatureScheme.ECDSA_SECP384R1_SHA384:
      Result := $0503;
    TSignatureScheme.ECDSA_SECP521R1_SHA512:
      Result := $0603;
    TSignatureScheme.ED25519:
      Result := $0807;
    TSignatureScheme.ED448:
      Result := $0808;
    TSignatureScheme.RSA_PSS_RSAE_SHA256:
      Result := $0804;
    TSignatureScheme.RSA_PSS_RSAE_SHA384:
      Result := $0805;
    TSignatureScheme.RSA_PSS_RSAE_SHA512:
      Result := $0806;
    TSignatureScheme.RSA_PKCS1_SHA256:
      Result := $0401;
    TSignatureScheme.RSA_PKCS1_SHA384:
      Result := $0501;
    TSignatureScheme.RSA_PKCS1_SHA512:
      Result := $0601;
  else
    raise ENotSupportedTlsLibException.CreateResFmt(@SNoSchemeCode, [Ord(Self)]);
  end;
end;

class function TSignatureSchemeHelper.TryFromCode(ACode: UInt16;
  out AScheme: TSignatureScheme): Boolean;
begin
  Result := True;
  case ACode of
    $0403:
      AScheme := TSignatureScheme.ECDSA_SECP256R1_SHA256;
    $0503:
      AScheme := TSignatureScheme.ECDSA_SECP384R1_SHA384;
    $0603:
      AScheme := TSignatureScheme.ECDSA_SECP521R1_SHA512;
    $0807:
      AScheme := TSignatureScheme.ED25519;
    $0808:
      AScheme := TSignatureScheme.ED448;
    $0804:
      AScheme := TSignatureScheme.RSA_PSS_RSAE_SHA256;
    $0805:
      AScheme := TSignatureScheme.RSA_PSS_RSAE_SHA384;
    $0806:
      AScheme := TSignatureScheme.RSA_PSS_RSAE_SHA512;
    $0401:
      AScheme := TSignatureScheme.RSA_PKCS1_SHA256;
    $0501:
      AScheme := TSignatureScheme.RSA_PKCS1_SHA384;
    $0601:
      AScheme := TSignatureScheme.RSA_PKCS1_SHA512;
  else
    Result := False;
  end;
end;

function TSignatureSchemeHelper.IsRsaPssRsae: Boolean;
begin
  Result := Self in [TSignatureScheme.RSA_PSS_RSAE_SHA256,
    TSignatureScheme.RSA_PSS_RSAE_SHA384, TSignatureScheme.RSA_PSS_RSAE_SHA512];
end;

function TSignatureSchemeHelper.IsRsaPkcs1: Boolean;
begin
  Result := Self in [TSignatureScheme.RSA_PKCS1_SHA256,
    TSignatureScheme.RSA_PKCS1_SHA384, TSignatureScheme.RSA_PKCS1_SHA512];
end;

function TSignatureSchemeHelper.IsValidForHandshake(
  const AVersion: TTlsVersion): Boolean;
begin
  // the legacy rsa_pkcs1_* schemes are certificate-only in TLS 1.3 (RFC 8446 4.2.3);
  // every scheme may carry a TLS 1.2 handshake signature
  Result := (not AVersion.Equals(TTlsVersion.Tls13)) or (not IsRsaPkcs1);
end;

end.
