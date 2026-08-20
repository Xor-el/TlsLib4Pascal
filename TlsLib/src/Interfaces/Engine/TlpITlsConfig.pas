{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpITlsConfig;

{$I ..\..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpICryptoProvider,
  TlpINamedGroup,
  TlpINegotiation,
  TlpNegotiationTypes,
  TlpICertificateTrust,
  TlpICertificateCompression,
  TlpICertificateCompressionCache,
  TlpCertificateLimits,
  TlpTrustPolicy,
  TlpTlsCredential,
  TlpITlsCredentialResolver,
  TlpISession,
  TlpIClock,
  TlpSession;

type
  /// <summary>
  /// The immutable settings shared by a client and a server endpoint: the crypto
  /// provider, the negotiation registries, the enabled versions and group
  /// preference, and ALPN. There is no process-wide mutable config; an endpoint is
  /// built once, frozen, and reused.
  /// </summary>
  ITlsCommonConfig = interface(IInterface)
    ['{7C2A9E15-4D83-4B70-A1F6-3E5C0D7B92A8}']
    function Provider: ICryptoProvider;
    function CipherSuites: ICipherSuiteRegistry;
    function SignatureSchemes: ISignatureSchemeRegistry;
    function NamedGroups: INamedGroupRegistry;
    function SupportedVersions: TArray<UInt16>;
    /// <summary>The named-group codes in preference order (the client's key_share order).</summary>
    function PreferredGroups: TArray<UInt16>;
    function AlpnProtocols: TArray<string>;
    /// <summary>The certificate-compression algorithms this endpoint compresses a sent
    /// Certificate with (RFC 8879); empty never sends a CompressedCertificate.</summary>
    function CertificateCompressors: TArray<ICertificateCompressor>;
    /// <summary>The certificate-compression algorithms this endpoint can decompress,
    /// advertised in compress_certificate; empty omits the extension.</summary>
    function CertificateDecompressors: TArray<ICertificateDecompressor>;
    /// <summary>The optional cross-connection cache memoizing the server's compressed
    /// Certificate (RFC 8879), so a stable certificate is deflated once rather than every
    /// handshake. Shared across the connections built from this config; nil (the default)
    /// compresses each time.</summary>
    function CertificateCompressionCache: ICertificateCompressionCache;
    /// <summary>This endpoint's own credential: the server certificate, or (mutual TLS)
    /// the client certificate. Empty when the endpoint presents none.</summary>
    function Credential: TTlsCredential;
    /// <summary>Trusts the peer certificate chain (the server chain for a client, or the
    /// client chain when a server requests one). Required for a client; required for a
    /// server only when it requests client authentication.</summary>
    function TrustStore: ITrustAnchorStore;
    /// <summary>An injected whole-verifier that replaces the built-in trust pipeline (e.g.
    /// an OS delegate). Mutually exclusive with any anchor source. nil uses the built-in
    /// pipeline over TrustStore.</summary>
    function CertificateVerifier: ICertificateVerifier;
    /// <summary>The certificate-chain resource caps applied before PKIX validation.</summary>
    function CertificateChainLimits: TCertificateChainLimits;
    /// <summary>The stapled-OCSP revocation posture (RFC 6960): Soft (default), Hard, or
    /// Off. Applies to the peer server certificate; must-staple (RFC 7633) is enforced
    /// regardless.</summary>
    function RevocationPosture: TRevocationPosture;
    /// <summary>Optional SPKI-SHA256 pins: when non-empty, some certificate in the peer
    /// chain must have a SubjectPublicKeyInfo whose SHA-256 matches one pin (public-key
    /// pinning). Augments PKIX validation; it never replaces it. Empty disables pinning.</summary>
    function CertificatePins: TArray<TBytes>;
    /// <summary>Optional untrusted intermediate certificates that seed PKIX path building:
    /// when the peer sends an incomplete chain (e.g. a leaf-only server), these fill the gap
    /// so a path to a trust anchor can still be built. They are never trusted on their own -
    /// only trust anchors anchor a path - and they never bypass validation. Empty (the
    /// default) validates the peer chain exactly as received.</summary>
    function IntermediateCertificates: TArray<TBytes>;
    /// <summary>Whether TLS 1.2 requires extended_master_secret (RFC 7627); when False,
    /// a peer that does not offer it falls back to the plain master secret.</summary>
    function RequireExtendedMasterSecret: Boolean;
    /// <summary>Whether a server that received a server_name (SNI) echoes the empty
    /// server_name acknowledgement (RFC 6066 3); default True.</summary>
    function ServerNameAcknowledgement: Boolean;
    /// <summary>How the server resolves the cipher suite: ServerOrder (default) imposes the
    /// server's own preference; ClientOrder honors the client's offered order. Server-only; a
    /// client config ignores it.</summary>
    function CipherSuitePreference: TServerCipherPreference;
    /// <summary>Whether a server rejects ALPN unconditionally: on any client ALPN offer it
    /// aborts with no_application_protocol (RFC 7301) rather than selecting or declining;
    /// default False.</summary>
    function AlpnRejectAll: Boolean;
    /// <summary>The DER-encoded DistinguishedName issuers a server names in its CertificateRequest
    /// certificate_authorities (RFC 8446 4.2.4 / RFC 5246 7.4.4); empty names none.</summary>
    function ClientCertificateAuthorities: TArray<TBytes>;
    /// <summary>Whether a client sprinkles GREASE values (RFC 8701) across its offers to keep
    /// peers tolerant of unknown values. Optional per the RFC; default True.</summary>
    function Grease: Boolean;
    /// <summary>The dangerous escape hatches for the peer-certificate decision: an
    /// InsecureSkipVerify that bypasses the built-in trust pipeline, and an augment-only
    /// VerifyCallback that can only additionally reject. Both default off.</summary>
    function DangerousTrust: TDangerousTrust;
    /// <summary>The asynchronous peer-certificate verdict setting. When enabled, the engine
    /// parks the handshake after its built-in trust pipeline accepts the chain and raises a
    /// CertificateReceived event so a host can decide out-of-band, resuming with
    /// SetCertificateVerdict (augment-only, fail-closed). Disabled by default (inline).</summary>
    function AsyncCertificateVerdict: TAsyncCertificateVerdict;
    /// <summary>Whether session resumption is engaged (RFC 8446 4.6.1 / RFC 5077). When
    /// False, the endpoint neither offers/uses (client) nor issues/accepts (server) a
    /// resumed session even if a cache/store is configured. Presets set the default;
    /// hardened profiles may default it off.</summary>
    function Resumption: Boolean;
    /// <summary>The out-of-band external pre-shared keys (RFC 9258), in preference order.
    /// A client imports and offers them (TLS 1.3 only); a server imports and matches an
    /// offered pre_shared_key against them, preferring a matching PSK over its
    /// certificate. Empty leaves external PSK off. Independent of Resumption.</summary>
    function ExternalPsks: TArray<TExternalPsk>;
    /// <summary>The clock this endpoint reads for time-dependent decisions - a resumption PSK's
    /// obfuscated_ticket_age and ticket-lifetime expiry, a server's 0-RTT anti-replay window,
    /// and certificate/OCSP freshness (RFC 8446 4.2.11 / 4.6.1). Never nil: the builder defaults
    /// it to the system clock.</summary>
    function Clock: ITlsClock;
  end;

  /// <summary>A frozen client endpoint config: a trust source is mandatory.</summary>
  ITlsClientConfig = interface(ITlsCommonConfig)
    ['{2E9C6A14-5D73-4F80-B1A8-6C3E0D5B94F7}']
    /// <summary>Whether the server certificate must match the connected host (RFC 6125).</summary>
    function CheckServerName: Boolean;
    /// <summary>Whether the client offers status_request (OCSP stapling, RFC 6066). Off by
    /// default; a stapled response is only accepted when explicitly requested.</summary>
    function RequestOcspStapling: Boolean;
    /// <summary>The client-side session cache resumption draws from and stores into; nil
    /// disables client resumption.</summary>
    function SessionCache: ISessionCache;
    /// <summary>Whether the client offers TLS 1.3 early data (0-RTT) when a cached ticket
    /// authorizes it. Off by default; a separate, explicit opt-in.</summary>
    function EarlyData: Boolean;
    /// <summary>Whether a client that configured external PSKs requires the server to select
    /// one: when True (the default), a ServerHello that omits pre_shared_key is fatal rather
    /// than a fall-through to certificate authentication. Set False to also accept a
    /// certificate handshake. No effect without configured external PSKs.</summary>
    function ExternalPskRequired: Boolean;
  end;

  /// <summary>A frozen server endpoint config: a certificate credential is mandatory.</summary>
  ITlsServerConfig = interface(ITlsCommonConfig)
    ['{9A4E1C28-6D50-4B63-8F17-2E6C0A5F84D3}']
    /// <summary>Whether the server requests a client certificate and how strictly
    /// (RFC 8446 4.3.2 / RFC 5246 7.4.4).</summary>
    function ClientAuth: TClientAuthMode;
    /// <summary>The stateful session store (session-id and stateful tickets); nil uses the
    /// stateless STEK path (or disables stateful storage).</summary>
    function SessionStore: ISessionStore;
    /// <summary>The session-ticket encryption keys for stateless tickets; nil disables
    /// stateless ticket issuance.</summary>
    function SessionTicketKeys: ISessionTicketKeyManager;
    /// <summary>Selects the server certificate per handshake from the client's SNI (virtual
    /// hosting). Composed at build from WithCredential / WithSniCredential / a custom
    /// WithCredentialResolver. nil for a PSK-only server (no certificate). The Credential
    /// accessor still returns the no-SNI / no-match default.</summary>
    function CredentialResolver: ITlsServerCredentialResolver;
    /// <summary>The anti-replay register guarding accepted 0-RTT early data; required for
    /// the server to accept early data.</summary>
    function AntiReplay: IAntiReplayStrategy;
    /// <summary>The lifetime advertised for issued sessions and tickets, in seconds.</summary>
    function TicketLifetimeSeconds: UInt32;
    /// <summary>How many TLS 1.3 NewSessionTickets to issue per handshake.</summary>
    function TicketCount: Int32;
    /// <summary>The 0-RTT early-data byte budget the server authorizes (0 = no early data).</summary>
    function MaxEarlyData: UInt32;
  end;

implementation

end.
