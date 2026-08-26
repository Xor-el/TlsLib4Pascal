{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpICryptoProvider;

{$I ..\..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpCryptoAlgorithms,
  TlpISigningKey,
  TlpTlsCredential,
  TlpISecretBuffer;

type
  /// <summary>An AEAD's usage-limit family: AES-GCM must proactively rekey by a
  /// record-count bound, ChaCha20-Poly1305 is bounded only by the record sequence.</summary>
  TAeadUsageCategory = (AesGcm, ChaCha20);

{ ===== Primitive interfaces ===== }

  /// <summary>
  /// The CSPRNG. Failure is a hard fail - a randomness failure raises, never a
  /// weak or zero fallback.
  /// </summary>
  IRandom = interface(IInterface)
    ['{08659DB4-A63B-4FDB-AA8C-0810BB8D8BDC}']
    /// <summary>Fills the whole of ABuffer with random bytes.</summary>
    procedure NextBytes(var ABuffer: TBytes);
    /// <summary>Returns ALength fresh random bytes.</summary>
    function GenerateBytes(ALength: Int32): TBytes;
  end;

  /// <summary>
  /// A hash / digest. <see cref="Clone" /> supports the deferred/branching
  /// transcript hash.
  /// </summary>
  IHash = interface(IInterface)
    ['{FAF552F4-DEBA-4AA1-A3EE-C58E291FDAAB}']
    function AlgorithmName: string;
    /// <summary>Digest output size in bytes.</summary>
    function HashSize: Int32;
    /// <summary>Internal block size in bytes.</summary>
    function BlockSize: Int32;
    procedure Update(const AData: TBytes; AOffset, ALength: Int32);
    /// <summary>Finalizes and returns the digest; resets for reuse.</summary>
    function DoFinal: TBytes;
    procedure Reset;
    /// <summary>An independent copy at the current state.</summary>
    function Clone: IHash;
  end;

  /// <summary>Keyed MAC (HMAC).</summary>
  IHmac = interface(IInterface)
    ['{E1A30A8D-B6A1-4F79-B12C-46B68BFB3C3B}']
    function AlgorithmName: string;
    /// <summary>MAC output size in bytes.</summary>
    function MacSize: Int32;
    procedure Init(const AKey: ISecretBuffer);
    procedure Update(const AData: TBytes; AOffset, ALength: Int32);
    function DoFinal: TBytes;
    procedure Reset;
  end;

  /// <summary>
  /// Raw HKDF (RFC 5869): <see cref="Extract" /> derives a pseudo-random key,
  /// <see cref="Expand" /> stretches it. The TLS HKDF-Expand-Label wrapper is a
  /// higher layer. An instance is stateful and is not shared across threads.
  /// </summary>
  IHkdf = interface(IInterface)
    ['{CE8C6F1F-9C1E-46F2-95EC-8F8FA500A5DD}']
    /// <summary>PRK = HMAC-Hash(salt, IKM); an empty salt is treated as HashLen zeros.</summary>
    function Extract(const ASalt: TBytes; const AIkm: ISecretBuffer): ISecretBuffer;
    /// <summary>OKM = HKDF-Expand(PRK, info, ALength).</summary>
    function Expand(const APrk: ISecretBuffer; const AInfo: TBytes;
      ALength: Int32): ISecretBuffer;
  end;

  /// <summary>
  /// An AEAD cipher. The key is set once via <see cref="Init" />; the nonce and
  /// associated data are per message. <see cref="Open" /> raises on an
  /// authentication failure.
  /// </summary>
  IAead = interface(IInterface)
    ['{0A207715-F01E-4C2D-AD4D-AEC6C0EC32D9}']
    function AlgorithmName: string;
    /// <summary>The usage-limit family the record layer derives its rekey bound from.</summary>
    function UsageCategory: TAeadUsageCategory;
    /// <summary>Required key length in bytes.</summary>
    function KeySize: Int32;
    /// <summary>Required nonce length in bytes.</summary>
    function NonceSize: Int32;
    /// <summary>Authentication tag length in bytes.</summary>
    function TagSize: Int32;
    /// <summary>Bytes added by sealing (the tag length).</summary>
    function Overhead: Int32;
    procedure Init(const AKey: ISecretBuffer);
    /// <summary>Encrypts and authenticates; returns ciphertext followed by the tag.</summary>
    function Seal(const ANonce, AAad, APlaintext: TBytes): TBytes;
    /// <summary>Authenticates and decrypts ciphertext||tag; raises on auth failure.</summary>
    function Open(const ANonce, AAad, ACiphertext: TBytes): TBytes;
  end;

  /// <summary>
  /// A Diffie-Hellman key agreement primitive (X25519 or a NIST prime curve).
  /// The named-group layer wraps this into a KEM shape; the raw math lives in the
  /// provider so a different backend can supply it.
  /// </summary>
  IKeyAgreement = interface(IInterface)
    ['{FFE70BE6-D33F-4CD4-B6B4-AA381B8863DE}']
    function Name: string;
    /// <summary>A fresh key pair: the private key and the public value to send.</summary>
    procedure GenerateKeyPair(out APrivateKey: ISecretBuffer; out APublicKey: TBytes);
    /// <summary>The shared secret from our private key and a peer's public value.</summary>
    function Agree(const APrivateKey: ISecretBuffer; const APeerPublicKey: TBytes): ISecretBuffer;
    /// <summary>Whether a peer's public value is well-formed and safe to use.</summary>
    function ValidatePublicKey(const APublicKey: TBytes): Boolean;
  end;

  /// <summary>
  /// A key-encapsulation primitive (ML-KEM). The raw math lives in the provider
  /// so a different backend can supply it; the named-group layer wraps it.
  /// </summary>
  IKem = interface(IInterface)
    ['{F362C3EF-E378-4C84-A7AB-45777EC1A8CA}']
    function Name: string;
    /// <summary>A fresh key pair: the private (decapsulation) key and the public
    /// (encapsulation) key to send.</summary>
    procedure GenerateKeyPair(out APrivateKey: ISecretBuffer; out APublicKey: TBytes);
    /// <summary>Against a peer's public key, the ciphertext to send and the
    /// shared secret.</summary>
    procedure Encapsulate(const APeerPublicKey: TBytes; out ACiphertext: TBytes;
      out ASharedSecret: ISecretBuffer);
    /// <summary>From the private key and a ciphertext, the shared secret.</summary>
    procedure Decapsulate(const APrivateKey: ISecretBuffer; const ACiphertext: TBytes;
      out ASharedSecret: ISecretBuffer);
    /// <summary>Whether a peer's public key is well-formed.</summary>
    function ValidatePublicKey(const APublicKey: TBytes): Boolean;
  end;

  /// <summary>
  /// Vends the raw crypto primitives by descriptor and reports machine-checkable
  /// capabilities. It does not select or fall back between algorithms - that is
  /// the negotiation policy's job; it only reports capability and returns correct
  /// results.
  /// </summary>
  ICryptoPrimitives = interface(IInterface)
    ['{55A260D5-E22D-4876-894B-5FB957433E38}']
    function GetRandom: IRandom;
    function CreateHash(AAlgorithm: THashAlgorithm): IHash;
    function CreateHmac(AAlgorithm: THashAlgorithm): IHmac;
    function CreateHkdf(AAlgorithm: THashAlgorithm): IHkdf;
    function CreateAead(AAlgorithm: TAeadAlgorithm): IAead;
    function CreateKeyAgreement(AAlgorithm: TKeyAgreementAlgorithm): IKeyAgreement;
    function CreateKem(AAlgorithm: TKemAlgorithm): IKem;
    /// <summary>Whether hardware accelerated AES is present on this host.</summary>
    function HasHardwareAes: Boolean;
  end;

{ ===== Signing interfaces ===== }

  /// <summary>
  /// Produces a signature over fed data with a loaded private key, for a TLS 1.3
  /// signature scheme (RSA-PSS / ECDSA / EdDSA). Feed the to-be-signed bytes via
  /// <see cref="Update" />, then <see cref="Sign" />.
  /// </summary>
  ISignatureSigner = interface(IInterface)
    ['{9B1CAFD9-7162-4B3A-8615-6DD9AC6C0A7E}']
    function AlgorithmName: string;
    procedure Update(const AData: TBytes; AOffset, ALength: Int32);
    function Sign: TBytes;
  end;

  /// <summary>
  /// Verifies a signature over fed data against a loaded public key. Verification
  /// is fail-closed: any malformed input returns False, never raises.
  /// </summary>
  ISignatureVerifier = interface(IInterface)
    ['{AE23AEDF-7BCD-42A3-A5A9-2D49868D4FDC}']
    function AlgorithmName: string;
    procedure Update(const AData: TBytes; AOffset, ALength: Int32);
    function Verify(const ASignature: TBytes): Boolean;
  end;

  /// <summary>
  /// The signing-credential seam: imports private keys and PKCS#12 identities
  /// into opaque backend handles and mints signers/verifiers over them. An
  /// <see cref="ISigningKey" /> handle is meaningful only to the same backend's
  /// <see cref="CreateSignatureSigner" />, so import and signer-minting are one
  /// coherence domain.
  /// </summary>
  ISigningCrypto = interface(IInterface)
    ['{367BAFEA-1828-4B5A-BA87-82CEDB994DD0}']
    /// <summary>
    /// Imports a signing private key in any supported encoding - PKCS#8, PKCS#1
    /// (RSAPrivateKey) or SEC1 (ECPrivateKey), in DER or PEM - into an opaque handle
    /// that holds it as canonical PKCS#8 and reports the schemes it can sign with.
    /// Malformed input raises EArgumentTlsLibException; an unsupported key algorithm
    /// raises ENotSupportedTlsLibException.
    /// </summary>
    function ImportSigningKey(const AData: TBytes): ISigningKey; overload;
    /// <summary>
    /// As <see cref="ImportSigningKey" />, decrypting an encrypted PKCS#8 key (DER
    /// EncryptedPrivateKeyInfo or an encrypted PEM key) with APassword.
    /// </summary>
    function ImportSigningKey(const AData: TBytes;
      const APassword: string): ISigningKey; overload;
    /// <summary>
    /// Imports a PKCS#12 (.pfx/.p12) blob decrypted with APassword into a complete
    /// credential: the leaf and any intermediates as the chain (leaf first, DER) and an
    /// ISigningKey composed from the enclosed private key. The store must hold exactly one
    /// private-key entry - a multi-identity store is ambiguous and rejected. Fails closed:
    /// a wrong password, bad MAC, malformed store, or an ambiguous/absent key raises
    /// EArgumentTlsLibException and no partial credential is returned; an unsupported key
    /// algorithm raises ENotSupportedTlsLibException.
    /// </summary>
    function ImportPkcs12(const AData: TBytes;
      const APassword: string): TTlsCredential;
    /// <summary>A signer for AScheme over the imported signing key AKey.</summary>
    function CreateSignatureSigner(AScheme: TSignatureScheme;
      const AKey: ISigningKey): ISignatureSigner;
    /// <summary>A verifier for AScheme over the SubjectPublicKeyInfo in APublicKeyDer.</summary>
    function CreateSignatureVerifier(AScheme: TSignatureScheme;
      const APublicKeyDer: TBytes): ISignatureVerifier;
  end;

{ ===== Certificate operations ===== }

  /// <summary>
  /// A single certificate parsed once into an opaque handle, answering the
  /// per-certificate queries from that one decode. It lets a caller that inspects the
  /// same leaf several times in a handshake pay the ASN.1 decode a single time. The
  /// handle is obtained from <see cref="ICertificateInspector.Parse" /> and is not
  /// shared across threads.
  /// </summary>
  IInspectedCertificate = interface(IInterface)
    ['{5A0E2B77-3C41-4E28-9B6E-7E9F0C6D1A44}']
    function PublicKeyInfo: TBytes;
    function DnsNames: TArray<string>;
    function IpAddresses: TArray<TBytes>;
    function KeyUsagePermits(AUsage: TCertKeyUsage; out APermitted: Boolean): Boolean;
    function HasRsaPssKey(out AIsRsaPss: Boolean): Boolean;
    function KeyKind(out AKind: TCertKeyKind; out AEcNamedGroup: UInt16): Boolean;
  end;

  /// <summary>
  /// Pure, per-certificate, side-effect-free X.509 inspection. The Boolean-returning
  /// queries are fail-closed: they never raise on malformed input, returning False (or
  /// an empty result) so the caller decides the alert. Parse, LoadChain, and the
  /// extractor methods (PublicKeyInfo, DnsNames, IpAddresses) raise on malformed input.
  /// </summary>
  ICertificateInspector = interface(IInterface)
    ['{243AB9CD-2900-4A04-B952-FEC3CD105B05}']
    /// <summary>
    /// Decodes ADer once into a handle that answers the per-certificate queries from
    /// that single decode. Raises when ADer does not decode to a certificate (empty or
    /// malformed); otherwise returns a handle over a well-formed certificate. Unlike the
    /// fail-closed DER-taking queries it raises rather than returning False, so use it
    /// where the certificate is already known well-formed.
    /// </summary>
    function Parse(const ADer: TBytes): IInspectedCertificate;
    /// <summary>
    /// Decodes certificates from AData - a PEM block (a single certificate or a whole
    /// leaf-first chain/bundle) or a single DER certificate - into their ordered raw
    /// DER encodings. Serves both credential chains and trust anchors. Raises
    /// EArgumentTlsLibException if nothing parses.
    /// </summary>
    function LoadChain(const AData: TBytes): TArray<TBytes>;
    /// <summary>
    /// True if ADer decodes as a structurally well-formed X.509 certificate. A
    /// parse-only gate (no trust, expiry or signature check) used to screen raw
    /// OS-harvested trust anchors before they reach path validation.
    /// </summary>
    function IsWellFormed(const ADer: TBytes): Boolean;
    /// <summary>The DER SubjectPublicKeyInfo of the X.509 certificate in ACertificateDer.</summary>
    function PublicKeyInfo(const ACertificateDer: TBytes): TBytes;
    /// <summary>The dNSName SubjectAltName entries of the X.509 certificate in ACertificateDer.</summary>
    function DnsNames(const ACertificateDer: TBytes): TArray<string>;
    /// <summary>The iPAddress SAN entries (raw 4- or 16-byte octets) in ACertificateDer.</summary>
    function IpAddresses(const ACertificateDer: TBytes): TArray<TBytes>;
    /// <summary>
    /// Extracts a certificate's human-readable identity: the subject and issuer
    /// distinguished names, the subject common name, and the serial number in hex. Returns
    /// False (all empty) on a malformed certificate; never raises.
    /// </summary>
    function PeerInfo(const ACertificateDer: TBytes;
      out ASubject, AIssuer, ACommonName, ASerialHex: string): Boolean;
    /// <summary>
    /// Reads the RFC 7633 TLS Feature extension (id-pe-tlsfeature, OID
    /// 1.3.6.1.5.5.7.1.24) of the certificate and returns its feature codepoints.
    /// An absent extension yields True with an empty list. A present value that is
    /// not a well-formed ASN.1 SEQUENCE OF INTEGER yields False, so the caller can
    /// abort with bad_certificate.
    /// </summary>
    function TlsFeatures(const ACert: TBytes;
      out AFeatures: TArray<UInt16>): Boolean;
    /// <summary>
    /// Whether the certificate's keyUsage extension (RFC 5280 4.2.1.3) permits AUsage.
    /// APermitted is True when the extension is absent (no restriction) or asserts the
    /// bit; False only when the extension is present and the bit is clear. Returns
    /// False (could not determine) on a malformed certificate, leaving APermitted True.
    /// </summary>
    function KeyUsagePermits(const ACertificateDer: TBytes;
      AUsage: TCertKeyUsage; out APermitted: Boolean): Boolean;
    /// <summary>
    /// Whether the certificate's SubjectPublicKeyInfo algorithm is id-RSASSA-PSS
    /// (OID 1.2.840.113549.1.1.10), the restricted RSA-PSS key type that the
    /// rsa_pss_rsae_* schemes must not be used with (RFC 8446 4.2.3). Returns False
    /// (could not determine) on a malformed certificate, leaving AIsRsaPss False.
    /// </summary>
    function HasRsaPssKey(const ACertificateDer: TBytes;
      out AIsRsaPss: Boolean): Boolean;
    /// <summary>
    /// Classifies the certificate leaf key: AKind is the public-key algorithm, and for an
    /// ECDSA key AEcNamedGroup is the named-group code of its curve (secp256r1 = 0x0017,
    /// secp384r1 = 0x0018, secp521r1 = 0x0019), 0 otherwise. Returns False (could not
    /// determine) on a malformed or unrecognized certificate, leaving AKind = Other.
    /// </summary>
    function KeyKind(const ACertificateDer: TBytes;
      out AKind: TCertKeyKind; out AEcNamedGroup: UInt16): Boolean;
  end;

  /// <summary>
  /// The trust decision: RFC 5280 path validation. The highest-stakes call in the
  /// library - it raises a fatal-alert exception on failure rather than returning a
  /// boolean.
  /// </summary>
  ICertificatePathValidator = interface(IInterface)
    ['{2457CB06-FD52-43D1-BAF4-ADF7D932FCD5}']
    /// <summary>
    /// Validates the DER chain (leaf first) to one of the DER trust anchors (RFC
    /// 5280 path validation; revocation is out of band). Returns normally when the
    /// chain is trusted; on failure it raises a fatal-alert exception carrying the
    /// reason (certificate_expired / unknown_ca / bad_certificate). Every validity
    /// check (chain notBefore/notAfter and the PKIX path date) is evaluated at
    /// AValidationTimeUtc, so the caller's injected clock drives the whole time-based
    /// trust decision from one source. AIntermediates are extra untrusted DER
    /// certificates seeded into path building for a peer that sends an incomplete
    /// chain (e.g. a leaf-only server); empty validates the chain exactly as received.
    /// They never anchor a path and never bypass validation. The chain is first validated
    /// exactly as presented; the intermediates are consulted only if that strict pass fails.
    /// AEffectiveChain returns the validated leaf-first chain - the assembled path when one was
    /// built, otherwise AChain - so the caller's staple and pin checks see the real issuer. It is
    /// a var parameter so a caller may pre-seed it with AChain as a fallback; an implementation
    /// that returns normally must set it.
    /// </summary>
    procedure ValidateCertificatePath(const AChain, ATrustAnchors,
      AIntermediates: TArray<TBytes>; const AValidationTimeUtc: TDateTime;
      var AEffectiveChain: TArray<TBytes>);
  end;

  /// <summary>
  /// Revocation checks (OCSP / CRL). Indeterminate-tolerant: a Boolean result means
  /// "could I determine", never raises a backend exception, so an unreachable or
  /// malformed responder degrades to indeterminate rather than a hard failure.
  /// </summary>
  IRevocationChecker = interface(IInterface)
    ['{B8D6113D-83F1-413C-921C-5D4CE9DCCEEF}']
    /// <summary>
    /// Verifies a stapled OCSP response (RFC 6960) about the leaf certificate,
    /// in-band only - no network. Confirms the response is signed by the leaf's
    /// issuer or an authorized delegated responder (id-kp-OCSPSigning, RFC 6960
    /// sec. 4.2.2.2) and that its CertID matches the leaf (serial + issuer name/key
    /// hash), then returns the reported status and the response's
    /// thisUpdate/nextUpdate window. A malformed, unauthorized, or non-matching
    /// response returns False (indeterminate); it never raises a backend exception.
    /// ANextUpdate is 0 when the responder omitted nextUpdate (no upper bound). The
    /// delegated-responder certificate validity is evaluated at AValidationTimeUtc,
    /// so the caller's injected clock drives it (the caller enforces the
    /// thisUpdate/nextUpdate freshness window against the same source).
    /// </summary>
    function ValidateOcspStaple(const ALeafCert, AIssuerCert,
      AOcspResponseDer: TBytes; const AValidationTimeUtc: TDateTime;
      out AStatus: TOcspStatus;
      out AThisUpdate, ANextUpdate: TDateTime): Boolean;
    /// <summary>
    /// Builds an unsigned DER OCSP request (RFC 6960 4.1.1) for the leaf, its CertID formed
    /// from the issuer name/key hash and the leaf serial - the request a live OCSP check
    /// POSTs to the responder. Returns False (no request) on a malformed input; never raises.
    /// The engine core never calls this; it is used only by the driver-edge live-revocation
    /// resolver.
    /// </summary>
    function BuildOcspRequest(const ALeafCert, AIssuerCert: TBytes;
      out ARequestDer: TBytes): Boolean;
    /// <summary>
    /// Reads the certificate's Authority Information Access extension (RFC 5280 4.2.2.1) and
    /// returns the first id-ad-ocsp responder URL (an http/https accessLocation). Returns
    /// False (no URL) when the extension is absent or carries no OCSP URI; never raises.
    /// </summary>
    function TryGetOcspResponderUrl(const ACert: TBytes;
      out AUrl: string): Boolean;
    /// <summary>
    /// Reads the certificate's CRL Distribution Points extension (RFC 5280 4.2.1.13) and
    /// returns the full-name http/https URLs. Returns False (empty) when absent or carrying
    /// no URI distribution point; never raises.
    /// </summary>
    function TryGetCrlDistributionPoints(const ACert: TBytes;
      out AUrls: TArray<string>): Boolean;
    /// <summary>
    /// Checks the leaf against a fetched DER CRL (RFC 5280): confirms the CRL is signed by
    /// the issuer, then reports whether the leaf serial appears in the revoked list.
    /// Returns True when the CRL parsed and verified (ARevoked then meaningful); False on a
    /// malformed or unverifiable CRL (indeterminate). Never raises.
    /// </summary>
    function CheckCrlRevocation(const ALeafCert, AIssuerCert, ACrlDer: TBytes;
      out ARevoked: Boolean): Boolean;
  end;

{ ===== Composition root ===== }

  /// <summary>
  /// The coherent composition root - one backend family, so its
  /// <see cref="ISigningKey" /> handles, SPKI encodings, and path-validation
  /// semantics all agree. Each accessor returns a stable, thread-safe, never-nil
  /// facet reference (the same reference every call); consumers hold this
  /// aggregator and reach a facet through its accessor.
  /// </summary>
  ICryptoProvider = interface(IInterface)
    ['{8945BF7C-FB99-42DC-B3BD-69C6E3FFB3C0}']
    function Primitives: ICryptoPrimitives;
    function Signing: ISigningCrypto;
    function Certificates: ICertificateInspector;
    function PathValidation: ICertificatePathValidator;
    function Revocation: IRevocationChecker;
  end;

  /// <summary>
  /// Fluent builder for a composed <see cref="ICryptoProvider" />: each With*
  /// overrides one facet (or the entropy source), and <see cref="Build" />
  /// composes the provider. An unset facet defaults; composing coherent facets
  /// (and supplying only thread-safe overrides) is the caller's responsibility.
  /// </summary>
  ICryptoProviderBuilder = interface(IInterface)
    ['{443FE34F-D1CA-4247-ADA3-D2F9D1274193}']
    /// <summary>Entropy source threaded into the default Primitives and Signing (not a
    /// supplied Primitives override).</summary>
    function WithRandom(const ARandom: IRandom): ICryptoProviderBuilder;
    function WithPrimitives(const APrimitives: ICryptoPrimitives): ICryptoProviderBuilder;
    function WithSigning(const ASigning: ISigningCrypto): ICryptoProviderBuilder;
    function WithInspector(const AInspector: ICertificateInspector): ICryptoProviderBuilder;
    function WithPathValidation(const APathValidation: ICertificatePathValidator): ICryptoProviderBuilder;
    function WithRevocation(const ARevocation: IRevocationChecker): ICryptoProviderBuilder;
    /// <summary>Composes the provider from the accumulated overrides.</summary>
    function Build: ICryptoProvider;
  end;

implementation

end.
