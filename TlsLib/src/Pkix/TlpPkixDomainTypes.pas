{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpPkixDomainTypes;

{$I ..\Include\TlsLib.inc}

interface

uses
  TlpCryptoDomainTypes;

type
  /// <summary>
  /// The revocation verdict an OCSP response reports for a certificate (RFC 6960
  /// sec. 2.2): Good, Revoked, or Unknown. Crosses the PKIX seam so the OCSP
  /// ASN.1 handling stays inside the provider.
  /// </summary>
  TOcspStatus = (Good, Revoked, Unknown);

  /// <summary>
  /// The X.509 keyUsage bits (RFC 5280 4.2.1.3) a TLS handshake consults: whether a
  /// leaf may sign (DigitalSignature), receive a transported key (KeyEncipherment),
  /// or perform static key agreement (KeyAgreement). Crosses the PKIX seam so the
  /// certificate ASN.1 handling stays inside the provider.
  /// </summary>
  TCertKeyUsage = (DigitalSignature, KeyEncipherment, KeyAgreement);

  /// <summary>
  /// The TLS role a certificate is being validated for, selecting the extendedKeyUsage
  /// (RFC 5280 4.2.1.12) the path must carry: id-kp-serverAuth for a server certificate,
  /// id-kp-clientAuth for a client certificate. Enforced "if present" over the leaf and
  /// every intermediate (never the trust anchor): a certificate that carries an EKU
  /// extension must include the required purpose, while a certificate with no EKU is
  /// unrestricted.
  /// </summary>
  TCertKeyPurpose = (ServerAuth, ClientAuth);

  /// <summary>Fail-closed answer to a Boolean certificate query: Undetermined when the
  /// certificate or the queried field is malformed, otherwise No / Yes.</summary>
  TCertAnswer = (Undetermined, No, Yes);

  /// <summary>The public-key algorithm family a certificate signature uses.</summary>
  TCertSignatureFamily = (RsaPkcs1, RsaPss, Ecdsa, Ed25519, Ed448);

  /// <summary>The hash a certificate signature uses. Md5/Sha1 are representable so the
  /// RFC 8446 4.4.2 MD5 MUST (and the SHA-1 rejection) can be expressed; Implicit is EdDSA,
  /// whose OID names no hash because the algorithm fixes it (unlike the RSA/ECDSA OIDs).</summary>
  TCertSignatureHash = (Md5, Sha1, Sha224, Sha256, Sha384, Sha512, Sha3, Implicit);

  /// <summary>The strength-relevant facts about a certificate's subject public key: the key
  /// family, its size (RSA modulus bits; EC field size in bits; 0 for EdDSA), and the IANA
  /// named-group code of a recognized curve (0 = other or explicit parameters).</summary>
  TCertKeyFacts = record
    Kind: TCertKeyKind;
    Bits: Int32;
    EcNamedGroup: UInt16;
  end;

  /// <summary>The algorithm a certificate was signed with: family, hash, and (for RSA-PSS)
  /// whether the parameters are canonical (MGF1 hash equals the signature hash and the salt
  /// length equals the digest length).</summary>
  TCertSignatureFacts = record
    Family: TCertSignatureFamily;
    Hash: TCertSignatureHash;
    PssCanonical: Boolean;
  end;

implementation

end.
