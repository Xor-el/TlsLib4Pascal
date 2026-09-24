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

{$I ..\..\..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpCryptoDomainTypes,
  TlpISigningKey,
  TlpIKeyExchangePrivateKey,
  TlpTlsCredential,
  TlpISecretBuffer;

type

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
    /// <summary>PRK = HMAC-Hash(salt, IKM); a nil or zero-length salt is treated as HashLen
    /// zeros. The salt is secret material (a derived-secret in the TLS 1.3 schedule), so it is
    /// passed as a wiped buffer rather than a bare byte array the caller must scrub.</summary>
    function Extract(const ASalt, AIkm: ISecretBuffer): ISecretBuffer;
    /// <summary>OKM = HKDF-Expand(PRK, info, ALength). ALength is 0..255*HashLen; outside
    /// that range raises EArgumentTlsLibException.</summary>
    function Expand(const APrk: ISecretBuffer; const AInfo: TBytes;
      ALength: Int32): ISecretBuffer;
  end;

  /// <summary>
  /// The TLS 1.2 PRF (RFC 5246 5): P_hash over the provider's HMAC, the hash bound at
  /// creation. PRF(secret, label, seed) = P_hash(secret, label + seed). A first-class
  /// primitive so a provider serves it over its own HMAC rather than the key schedule
  /// hand-rolling the construction.
  /// </summary>
  ITls12Prf = interface(IInterface)
    ['{3F9A2C71-5E84-4B60-9D17-8A2C4E7B10F5}']
    function Compute(const ASecret: ISecretBuffer; const ALabel: string;
      const ASeed: TBytes; ALength: Int32): ISecretBuffer;
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
    /// <summary>A fresh key pair: the private key (an Ephemeral handle) and the public value
    /// to send.</summary>
    procedure GenerateKeyPair(out APrivateKey: IKeyExchangePrivateKey;
      out APublicKey: TBytes);
    /// <summary>The shared secret from our private key and a peer's public value. The key's
    /// own Usage (fixed at mint) tells the backend whether it is a fresh single-use scalar or a
    /// long-lived one, so a backend that can select a reuse-hardened scalar-blinding posture
    /// does so for a Static key.</summary>
    function Agree(const APrivateKey: IKeyExchangePrivateKey;
      const APeerPublicKey: TBytes): ISecretBuffer;
    /// <summary>Whether a peer's public value is well-formed and safe to use.</summary>
    function ValidatePublicKey(const APublicKey: TBytes): Boolean;
    /// <summary>A private key adopted from a raw scalar (the curve's fixed-width serialization),
    /// plus its derived public value. AUsage declares whether it will be reused (Static) or is
    /// single-use (Ephemeral) - the one place a Static posture is set. The returned key is in
    /// this backend's own representation, ready for <see cref="Agree" />.</summary>
    function ImportPrivateKey(const ARawPrivateKey: ISecretBuffer;
      AUsage: TKeyAgreementUsage; out APublicKey: TBytes): IKeyExchangePrivateKey;
  end;

  /// <summary>
  /// A key-encapsulation primitive (ML-KEM). The raw math lives in the provider
  /// so a different backend can supply it; the named-group layer wraps it.
  /// </summary>
  IKem = interface(IInterface)
    ['{F362C3EF-E378-4C84-A7AB-45777EC1A8CA}']
    function Name: string;
    /// <summary>A fresh key pair: the private (decapsulation) key handle and the public
    /// (encapsulation) key to send.</summary>
    procedure GenerateKeyPair(out APrivateKey: IKeyExchangePrivateKey;
      out APublicKey: TBytes);
    /// <summary>Against a peer's public key, the ciphertext to send and the
    /// shared secret.</summary>
    procedure Encapsulate(const APeerPublicKey: TBytes; out ACiphertext: TBytes;
      out ASharedSecret: ISecretBuffer);
    /// <summary>From the private key and a ciphertext, the shared secret.</summary>
    procedure Decapsulate(const APrivateKey: IKeyExchangePrivateKey;
      const ACiphertext: TBytes; out ASharedSecret: ISecretBuffer);
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
    function CreateTls12Prf(AAlgorithm: THashAlgorithm): ITls12Prf;
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
    /// EncryptedPrivateKeyInfo or an encrypted PEM key) with APassword. The passphrase is a
    /// wiped buffer of host code units: nil means no passphrase, a zero-length buffer means an
    /// empty passphrase.
    /// </summary>
    function ImportSigningKey(const AData: TBytes;
      const APassword: ISecretBuffer): ISigningKey; overload;
    /// <summary>
    /// Imports a PKCS#12 (.pfx/.p12) blob decrypted with APassword into a complete
    /// credential: the leaf and any intermediates as the chain (leaf first, DER) and an
    /// ISigningKey composed from the enclosed private key. The store must hold exactly one
    /// private-key entry - a multi-identity store is ambiguous and rejected. Fails closed:
    /// a wrong password, bad MAC, malformed store, or an ambiguous/absent key raises
    /// EArgumentTlsLibException and no partial credential is returned; an unsupported key
    /// algorithm raises ENotSupportedTlsLibException. The passphrase is a wiped buffer of host
    /// code units: nil means no passphrase, a zero-length buffer means an empty passphrase.
    /// </summary>
    function ImportPkcs12(const AData: TBytes;
      const APassword: ISecretBuffer): TTlsCredential;
    /// <summary>A signer for AScheme over the imported signing key AKey. Raises
    /// EArgumentTlsLibException when AScheme is not among the key's CapableSchemes or the key
    /// cannot produce it; never lets a raw backend exception cross the seam.</summary>
    function CreateSignatureSigner(AScheme: TSignatureScheme;
      const AKey: ISigningKey): ISignatureSigner;
    /// <summary>A verifier for AScheme over the SubjectPublicKeyInfo in APublicKeyDer. Raises
    /// EArgumentTlsLibException on a malformed SPKI or when the scheme's key family does not
    /// match the key (e.g. an EC key under rsa_pss_rsae_*); never lets a raw backend exception
    /// cross the seam.</summary>
    function CreateSignatureVerifier(AScheme: TSignatureScheme;
      const APublicKeyDer: TBytes): ISignatureVerifier;
  end;

{ ===== HPKE (RFC 9180) ===== }

  /// <summary>
  /// A sender-side HPKE encryption context (RFC 9180 sec. 5.2). It is
  /// sequence-aware: each <see cref="Seal" /> advances the internal AEAD sequence
  /// number, so the same instance produces the seq=0 message and then the seq=1
  /// message. Encrypted Client Hello reuses one sealer across a HelloRetryRequest for
  /// exactly this, so callers hold the live instance rather than re-creating it.
  /// </summary>
  IHpkeSealer = interface(IInterface)
    ['{2B4E6A18-9D07-4C31-A5F2-7E1C3B8D6042}']
    /// <summary>Encrypts APlaintext under AAad at the current sequence number and
    /// advances it.</summary>
    function Seal(const AAad, APlaintext: TBytes): TBytes;
  end;

  /// <summary>
  /// A recipient-side HPKE decryption context (RFC 9180 sec. 5.2). Sequence-aware:
  /// a successful <see cref="Open" /> advances the sequence number, a failed one
  /// (authentication failure) does not, so a rejected ciphertext never
  /// desynchronises the receiver. Encrypted Client Hello holds the live instance
  /// across a HelloRetryRequest to open the second ClientHello at seq=1.
  /// </summary>
  IHpkeOpener = interface(IInterface)
    ['{7C0A9F53-1E62-4B48-8D3A-5F2B7C9E1A46}']
    /// <summary>Authenticates and decrypts ACiphertext under AAad at the current
    /// sequence number; raises EHpkeOpenTlsLibException on authentication failure
    /// without advancing, and advances only on success.</summary>
    function Open(const AAad, ACiphertext: TBytes): TBytes;
  end;

  /// <summary>
  /// A provider-instantiated HPKE suite (RFC 9180 base mode): the (KEM, KDF, AEAD) codepoint
  /// triple bound to the provider's implementation of it. Obtained from
  /// <see cref="IHpkeCrypto.Suite" />, which returns nil for a suite the provider cannot instantiate,
  /// so an IHpkeSuite always denotes a usable suite - one you can seal or open with, needing no
  /// separate support check.
  /// </summary>
  IHpkeSuite = interface(IInterface)
    ['{9E2A5C71-4B08-4D63-8F1A-2C6E9B0D7A34}']
    /// <summary>The KEM codepoint of this suite.</summary>
    function Kem: UInt16;
    /// <summary>The KDF codepoint of this suite.</summary>
    function Kdf: UInt16;
    /// <summary>The AEAD codepoint of this suite.</summary>
    function Aead: UInt16;
    /// <summary>
    /// The AEAD authentication tag length, in bytes - the overhead a Seal adds over its
    /// plaintext. ECH needs it to size the sealed payload (and its zero-filled placeholder in
    /// the AAD) before sealing.
    /// </summary>
    function AeadTagLength: Int32;
    /// <summary>
    /// Sets up a base-mode sender against the recipient public key ARecipientPublicKey (the
    /// KEM's serialized public key). Returns the KEM encapsulation to transmit in AEnc and a
    /// sequence-aware sealer in ASealer. AInfo binds the application context (RFC 9180 sec. 5.1).
    /// Raises if the public key is malformed.
    /// </summary>
    procedure SetupSealer(const ARecipientPublicKey, AInfo: TBytes;
      out AEnc: TBytes; out ASealer: IHpkeSealer);
  end;

  /// <summary>
  /// A recipient HPKE key prepared once for reuse across many decapsulations (RFC 9180): the
  /// private key is decoded and its public key derived at import, so a server that trial-decrypts
  /// every ClientHello does not repeat that work per attempt. The key material stays inside the
  /// provider - only the KEM, the derived public key, and the open operation are exposed.
  /// </summary>
  IHpkeRecipientKey = interface(IInterface)
    ['{1F3B7D24-6E90-4A58-8C05-9B2E4D6A1C73}']
    /// <summary>The KEM this key belongs to.</summary>
    function Kem: UInt16;
    /// <summary>The serialized KEM public key derived from the private key at import.</summary>
    function PublicKey: TBytes;
    /// <summary>
    /// Sets up a base-mode recipient for the encapsulation AEnc under context AInfo, returning a
    /// sequence-aware opener. ASuite's KEM must be this key's KEM. Raises on a suite/KEM mismatch;
    /// a wrong key surfaces later as an authentication failure from <see cref="IHpkeOpener.Open" />.
    /// </summary>
    function SetupOpener(const ASuite: IHpkeSuite;
      const AEnc, AInfo: TBytes): IHpkeOpener;
  end;

  /// <summary>
  /// The HPKE facet (RFC 9180 base mode). It vends suite instantiation, key generation and
  /// key import for Encrypted Client Hello, in neutral currency only: TBytes, ISecretBuffer,
  /// the UInt16 HPKE codepoints, and the <see cref="IHpkeSuite" /> / <see cref="IHpkeRecipientKey" />
  /// handles. No backend type crosses this seam.
  /// </summary>
  IHpkeCrypto = interface(IInterface)
    ['{4D8F1C60-3A72-4E59-9B14-6C0D2E7A3B58}']
    /// <summary>
    /// The provider's instance of the suite (AKem, AKdf, AAead), or nil when it cannot
    /// instantiate it: nil unless the KEM, KDF and AEAD ids are all known AND this provider's
    /// primitives can actually build every one of them (the KEM curve and its KDF hash, the
    /// suite KDF hash, and the AEAD). The ECH config filter skips a nil suite rather than
    /// raising, so an offer this provider cannot satisfy is a clean reject, not internal_error;
    /// a non-nil suite is ready to seal or open with.
    /// </summary>
    function Suite(AKem, AKdf, AAead: UInt16): IHpkeSuite;
    /// <summary>
    /// Imports a recipient private key (the raw KEM scalar for AKem) into a reusable handle,
    /// deriving its public key once. Raises ENotSupportedTlsLibException for an unknown KEM or
    /// EArgumentTlsLibException for a malformed scalar.
    /// </summary>
    function ImportRecipientKey(AKem: UInt16;
      const APrivateKey: ISecretBuffer): IHpkeRecipientKey;
    /// <summary>
    /// Generates a fresh HPKE key pair for the KEM AKem: the serialized public key in
    /// APublicKey and the raw private scalar in APrivateKey (wiped on release). Raises
    /// ENotSupportedTlsLibException for an unsupported KEM.
    /// </summary>
    procedure GenerateKeyPair(AKem: UInt16; out APublicKey: TBytes;
      out APrivateKey: ISecretBuffer);
    /// <summary>
    /// Decodes a PKCS#8 private key (RFC 8410 X25519/X448 or RFC 5915 EC) for the KEM
    /// AKem into the raw HPKE scalar, wiped on release. Raises EArgumentTlsLibException
    /// on a malformed key or one whose algorithm does not match AKem.
    /// </summary>
    function ImportPrivateKey(AKem: UInt16; const APkcs8Der: TBytes): ISecretBuffer;
    /// <summary>
    /// Every HPKE suite this provider can instantiate for the KEM AKem: one entry per
    /// supported (KDF, real AEAD) pair, empty for an unknown KEM. The provider is the single
    /// authority on the HPKE vocabulary, so a caller that needs a plausible suite (a GREASE
    /// ech, RFC 9849 sec. 6.2) draws from this rather than hard-coding its own list.
    /// </summary>
    function SupportedSuites(AKem: UInt16): TArray<THpkeSuiteId>;
    /// <summary>
    /// Whether APublicKey is a well-formed serialized KEM public key for AKem (correct length
    /// and, for an EC KEM, a valid curve point). Used by the ECH config filter to skip a config
    /// whose public_key could not be used, rather than let a malformed key fail later inside a
    /// seal. False for an unknown KEM.
    /// </summary>
    function ValidatePublicKey(AKem: UInt16; const APublicKey: TBytes): Boolean;
    /// <summary>
    /// A KEM encapsulation for AKem against a throwaway placeholder recipient - the real output of
    /// a base-mode setup, not a bare public key, so it is a valid encapsulation for any KEM (the
    /// two coincide only for a DH KEM). A GREASE ech (RFC 9849 sec. 6.2) uses it as its enc so the
    /// decoy carries a genuine encapsulation shape. nil for an unknown KEM.
    /// </summary>
    function RandomEncapsulation(AKem: UInt16): TBytes;
  end;

{ ===== Composition root ===== }

  /// <summary>
  /// The coherent composition root for the crypto primitives - one backend family,
  /// so its <see cref="ISigningKey" /> handles, SPKI encodings and HPKE all agree.
  /// X.509/PKIX (certificate inspection, path validation, revocation) is a separate
  /// concern, composed by <see cref="IPkixProvider" />. Each accessor returns a stable,
  /// thread-safe, never-nil facet reference (the same reference every call); consumers
  /// hold this aggregator and reach a facet through its accessor.
  /// </summary>
  ICryptoProvider = interface(IInterface)
    ['{8945BF7C-FB99-42DC-B3BD-69C6E3FFB3C0}']
    function Primitives: ICryptoPrimitives;
    function Signing: ISigningCrypto;
    /// <summary>The HPKE facet (RFC 9180), used by Encrypted Client Hello.</summary>
    function Hpke: IHpkeCrypto;
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
    function WithHpke(const AHpke: IHpkeCrypto): ICryptoProviderBuilder;
    /// <summary>Composes the provider from the accumulated overrides.</summary>
    function Build: ICryptoProvider;
  end;

implementation

end.
