{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpIPkixProvider;

{$I ..\..\..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpCryptoDomainTypes,
  TlpPkixDomainTypes;

type

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
    /// <summary>
    /// Whether the certificate's keyUsage extension (RFC 5280 4.2.1.3) permits AUsage.
    /// Yes when the extension is absent (no restriction) or asserts the bit; No only when
    /// the extension is present and the bit is clear; Undetermined on a malformed certificate.
    /// </summary>
    function KeyUsagePermits(AUsage: TCertKeyUsage): TCertAnswer;
    /// <summary>
    /// Whether the certificate's SubjectPublicKeyInfo algorithm is id-RSASSA-PSS
    /// (OID 1.2.840.113549.1.1.10), the restricted RSA-PSS key type that the
    /// rsa_pss_rsae_* schemes must not be used with (RFC 8446 4.2.3). Yes when it is,
    /// No when it is not, Undetermined on a malformed certificate.
    /// </summary>
    function KeyIsRsaPss: TCertAnswer;
    function KeyKind(out AKind: TCertKeyKind; out AEcNamedGroup: UInt16): Boolean;
    /// <summary>
    /// The subject public key's strength facts (family, size, curve). Returns False (facts
    /// undeterminable - unknown key OID, explicit EC parameters, malformed) so the caller
    /// fails closed.
    /// </summary>
    function KeyFacts(out AFacts: TCertKeyFacts): Boolean;
    /// <summary>
    /// The algorithm the certificate was signed with (family, hash, canonical-PSS flag).
    /// Returns False (undeterminable - unknown signature OID, malformed parameters) so the
    /// caller fails closed.
    /// </summary>
    function SignatureFacts(out AFacts: TCertSignatureFacts): Boolean;
    /// <summary>
    /// Extracts the certificate's human-readable identity from the already-decoded handle:
    /// the subject and issuer distinguished names, the subject common name, and the serial
    /// number in hex. Returns False (all empty) on a malformed field; never raises.
    /// </summary>
    function PeerInfo(out ASubject, AIssuer, ACommonName, ASerialHex: string): Boolean;
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
    /// Yes when the extension is absent (no restriction) or asserts the bit; No only when
    /// the extension is present and the bit is clear; Undetermined on a malformed certificate.
    /// </summary>
    function KeyUsagePermits(const ACertificateDer: TBytes;
      AUsage: TCertKeyUsage): TCertAnswer;
    /// <summary>
    /// Whether the certificate's SubjectPublicKeyInfo algorithm is id-RSASSA-PSS
    /// (OID 1.2.840.113549.1.1.10), the restricted RSA-PSS key type that the
    /// rsa_pss_rsae_* schemes must not be used with (RFC 8446 4.2.3). Yes when it is,
    /// No when it is not, Undetermined on a malformed certificate.
    /// </summary>
    function KeyIsRsaPss(const ACertificateDer: TBytes): TCertAnswer;
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
    /// that returns normally must set it. AKeyPurpose selects the extendedKeyUsage the
    /// path must carry (server vs client role); a certificate on the path (leaf or
    /// intermediate, never the anchor) that carries an EKU extension lacking the purpose
    /// is rejected with unsupported_certificate, while one with no EKU is unrestricted.
    /// </summary>
    procedure ValidateCertificatePath(const AChain, ATrustAnchors,
      AIntermediates: TArray<TBytes>; const AValidationTimeUtc: TDateTime;
      AKeyPurpose: TCertKeyPurpose; var AEffectiveChain: TArray<TBytes>);
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
    /// Checks the leaf against a fetched DER CRL (RFC 5280): confirms the CRL is signed by the
    /// issuer, enforces its thisUpdate/nextUpdate freshness window at AValidationTimeUtc (so the
    /// caller's injected clock drives it, not the wall clock), then reports whether the leaf
    /// serial appears in the revoked list. Returns True when the CRL parsed, verified and is
    /// current (ARevoked then meaningful); False on a malformed, unverifiable or out-of-window
    /// CRL (indeterminate). AThisUpdate/ANextUpdate report the window (ANextUpdate 0 when absent).
    /// Never raises.
    /// </summary>
    function CheckCrlRevocation(const ALeafCert, AIssuerCert, ACrlDer: TBytes;
      const AValidationTimeUtc: TDateTime; out ARevoked: Boolean;
      out AThisUpdate, ANextUpdate: TDateTime): Boolean;
    /// <summary>
    /// Finds, among ACandidates, the certificate that issued ALeaf - for a live revocation check on a
    /// peer that presented a leaf-only chain (a mutual-TLS client whose issuer is a configured anchor,
    /// not sent on the wire; RFC 8446 4.4.2). A candidate qualifies only when its subject name matches
    /// the leaf's issuer name AND its public key verifies the leaf's signature, so a same-name/wrong-key
    /// candidate is rejected (it would otherwise mis-key the OCSP CertID). Candidates must come from
    /// local configuration (anchors / configured intermediates), never the peer. Returns False (no
    /// issuer) when none qualifies or on malformed input; never raises.
    /// </summary>
    function TryFindIssuer(const ALeafCert: TBytes; const ACandidates: TArray<TBytes>;
      out AIssuerCert: TBytes): Boolean;
  end;

{ ===== Composition root ===== }

  /// <summary>
  /// The PKIX composition root: X.509 certificate inspection, RFC 5280 path
  /// validation, and revocation - the policy layer that sits above the crypto
  /// primitives, injected alongside <see cref="ICryptoProvider" />. Each accessor
  /// returns a stable, thread-safe, never-nil facet reference (the same reference
  /// every call); consumers hold this aggregator and reach a facet through its accessor.
  /// </summary>
  IPkixProvider = interface(IInterface)
    ['{7E1D9A34-6C82-4B57-A0F9-3D8E2C5B1F60}']
    function Certificates: ICertificateInspector;
    function PathValidation: ICertificatePathValidator;
    function Revocation: IRevocationChecker;
  end;

  /// <summary>
  /// Fluent builder for a composed <see cref="IPkixProvider" />: each With* overrides
  /// one facet, and <see cref="Build" /> composes the provider. An unset facet defaults;
  /// composing coherent facets (and supplying only thread-safe overrides) is the caller's
  /// responsibility. Mirrors <see cref="ICryptoProviderBuilder" />.
  /// </summary>
  IPkixProviderBuilder = interface(IInterface)
    ['{3C8A5F19-2E74-4D06-9B58-1F7A6C0E4D23}']
    function WithInspector(const AInspector: ICertificateInspector): IPkixProviderBuilder;
    function WithPathValidation(const APathValidation: ICertificatePathValidator): IPkixProviderBuilder;
    function WithRevocation(const ARevocation: IRevocationChecker): IPkixProviderBuilder;
    /// <summary>Composes the provider from the accumulated overrides.</summary>
    function Build: IPkixProvider;
  end;

implementation

end.
