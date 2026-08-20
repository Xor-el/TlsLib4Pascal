{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpITlsConfigBuilder;

{$I ..\..\Include\TlsLib.inc}

interface

uses
  SysUtils,
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
  TlpSession,
  TlpITlsConfig;

type
  ITlsClientConfigBuilder = interface;
  ITlsServerConfigBuilder = interface;
  ITls13ClientConfigFacet = interface;
  ITls12ClientConfigFacet = interface;
  ITls13ServerConfigFacet = interface;
  ITls12ServerConfigFacet = interface;

  /// <summary>
  /// Chooses the endpoint before anything else is configured. There is no shared
  /// mutable builder that can build "either" endpoint: picking Client or Server hands
  /// back a builder whose surface holds only that endpoint's settings and whose Build
  /// yields only that endpoint's config, so a wrong-endpoint setting is impossible to
  /// express rather than silently ignored.
  /// </summary>
  ITlsConfigBuilder = interface(IInterface)
    ['{B3F1A0C4-7E52-4D89-9A16-0C7E3B5D2F84}']
    /// <summary>The client-endpoint builder, seeded with the preset's defaults.</summary>
    function Client: ITlsClientConfigBuilder;
    /// <summary>The server-endpoint builder, seeded with the preset's defaults.</summary>
    function Server: ITlsServerConfigBuilder;
  end;

  /// <summary>
  /// Assembles a client endpoint. Common setters and the client-only knobs live here;
  /// version-specific settings live behind Tls13/Tls12 so the version is explicit at the
  /// call site (and Build refuses a version facet touched for a version not offered).
  /// Every setter returns this builder so they chain. A client build requires a trust
  /// source (no silent-insecure).
  /// </summary>
  ITlsClientConfigBuilder = interface(IInterface)
    ['{2E9C6A14-5D73-4F80-B1A8-6C3E0D5B94F7}']
    function WithCipherSuites(const ARegistry: ICipherSuiteRegistry): ITlsClientConfigBuilder;
    function WithSignatureSchemes(const ARegistry: ISignatureSchemeRegistry): ITlsClientConfigBuilder;
    function WithNamedGroups(const ARegistry: INamedGroupRegistry): ITlsClientConfigBuilder;
    function WithSupportedVersions(const AVersions: TArray<UInt16>): ITlsClientConfigBuilder;
    function WithPreferredGroups(const AGroups: TArray<UInt16>): ITlsClientConfigBuilder;
    function WithAlpnProtocols(const AProtocols: TArray<string>): ITlsClientConfigBuilder;
    /// <summary>Whether the client sends GREASE values (RFC 8701). Optional per the RFC;
    /// default True. Pass False to omit GREASE (e.g. for deterministic wire output).</summary>
    function WithGrease(AEnable: Boolean): ITlsClientConfigBuilder;
    function WithTrustStore(const AStore: ITrustAnchorStore): ITlsClientConfigBuilder;
    /// <summary>Trust anchors from a PEM block (one certificate or a bundle) or a single
    /// DER certificate, loaded through the provider.</summary>
    function WithTrustAnchors(const AData: TBytes): ITlsClientConfigBuilder;
    /// <summary>Injects a whole-verifier that replaces the built-in trust pipeline for the
    /// server certificate (e.g. an OS delegate). Exclusive: combining it with any anchor
    /// source (WithTrustStore/WithTrustAnchors), or setting two verifiers, is a typed error
    /// at Build.</summary>
    function WithCertificateVerifier(
      const AVerifier: ICertificateVerifier): ITlsClientConfigBuilder;
    /// <summary>The certificate-chain resource caps applied before PKIX validation.</summary>
    function WithCertificateChainLimits(
      const ALimits: TCertificateChainLimits): ITlsClientConfigBuilder;
    /// <summary>The client's own credential for mutual TLS, presented when the server
    /// sends a CertificateRequest the credential can satisfy.</summary>
    function WithCredential(const ACredential: TTlsCredential): ITlsClientConfigBuilder; overload;
    /// <summary>A credential from a certificate chain and an unencrypted private key, each
    /// a PEM block or DER, loaded and normalized through the provider.</summary>
    function WithCredential(const ACertificateChainData,
      APrivateKeyData: TBytes): ITlsClientConfigBuilder; overload;
    /// <summary>As above, decrypting an encrypted private key with APassword.</summary>
    function WithCredential(const ACertificateChainData, APrivateKeyData: TBytes;
      const APassword: string): ITlsClientConfigBuilder; overload;
    /// <summary>A credential imported from a PKCS#12 (.pfx/.p12) blob decrypted with
    /// APassword: leaf + intermediates as the chain and the enclosed private key.</summary>
    function WithCredentialPkcs12(const AData: TBytes;
      const APassword: string): ITlsClientConfigBuilder;
    /// <summary>The stapled-OCSP revocation posture (RFC 6960): Soft (default) accepts a
    /// missing or indeterminate staple, Hard requires a current Good one, Off skips the
    /// check. Must-staple (RFC 7633) is always enforced.</summary>
    function WithRevocation(APosture: TRevocationPosture): ITlsClientConfigBuilder;
    /// <summary>SPKI-SHA256 public-key pins: when set, some certificate in the server chain
    /// must match one pin. Augments PKIX validation; never a bypass. Empty disables it.</summary>
    function WithCertificatePinning(const APins: TArray<TBytes>): ITlsClientConfigBuilder;
    /// <summary>Untrusted intermediate certificates that seed PKIX path building when the server
    /// sends an incomplete chain (e.g. a leaf-only server that omits its issuing CA). AData is a
    /// PEM bundle (one or more certificates) or a single DER certificate; call more than once to
    /// add several DER certificates. They are never trusted on their own and never bypass
    /// validation - a path must still reach a configured trust anchor, and a complete chain the
    /// server sends is still validated exactly as presented. Calls accumulate. Use this when a
    /// server you must reach ships a partial chain; the well-behaved fix is to have the server
    /// send its full chain.</summary>
    function WithIntermediateCertificates(const AData: TBytes): ITlsClientConfigBuilder;
    /// <summary>Whether the server certificate must match the connected host (RFC 6125).
    /// Default True.</summary>
    function WithNameCheck(AEnabled: Boolean): ITlsClientConfigBuilder;
    /// <summary>Whether the client offers status_request (OCSP stapling, RFC 6066). Off by
    /// default: without it the client requests no staple and rejects an unsolicited one.</summary>
    function WithOcspStaplingRequest(AEnabled: Boolean): ITlsClientConfigBuilder;
    /// <summary>DANGEROUS: when enabled, the server certificate chain is accepted without
    /// PKIX, revocation, host-name, or pinning checks. For tests and pinned/self-signed
    /// development peers only - never production. Off by default.</summary>
    function WithDangerousInsecureSkipVerify(AEnabled: Boolean): ITlsClientConfigBuilder;
    /// <summary>An augment-only peer-certificate hook that runs after the built-in pipeline
    /// and can only additionally reject (never loosen it). Bridges a host framework's own
    /// verify callback.</summary>
    function WithCertificateVerifyCallback(
      const ACallback: TTlsCertificateVerifyCallback): ITlsClientConfigBuilder;
    /// <summary>Enables the async peer-certificate verdict (the deferred-verdict seam): after
    /// the built-in pipeline accepts the server chain the handshake parks and raises a
    /// CertificateReceived event for an out-of-band decision, resumed with the engine's
    /// SetCertificateVerdict. Augment-only and fail-closed. ADeadlineMs is advisory to the
    /// driver (the engine owns no timer); 0 imposes no engine-suggested deadline. Off by
    /// default.</summary>
    function WithAsyncCertificateVerdict(AEnabled: Boolean;
      ADeadlineMs: Cardinal): ITlsClientConfigBuilder;
    /// <summary>The client-side session cache to draw resumed sessions from and store new
    /// ones into; providing one engages client resumption (subject to WithResumption).</summary>
    function WithSessionCache(const ACache: ISessionCache): ITlsClientConfigBuilder;
    /// <summary>The clock the client reads for a resumption PSK's obfuscated_ticket_age and
    /// ticket-lifetime expiry (RFC 8446 4.2.11 / 4.6.1); nil (the default) uses the system
    /// clock. Injectable primarily so tests can drive a deterministic time.</summary>
    function WithClock(const AClock: ITlsClock): ITlsClientConfigBuilder;
    /// <summary>The out-of-band external pre-shared keys (RFC 9258) the client imports and
    /// offers in the ClientHello (TLS 1.3 only), in preference order. When set, the client
    /// offers these instead of drawing a resumption session from the cache. Empty leaves
    /// external PSK off.</summary>
    function WithExternalPreSharedKeys(
      const APsks: TArray<TExternalPsk>): ITlsClientConfigBuilder;
    /// <summary>Whether configured external PSKs are required (default True): a non-PSK
    /// ServerHello is fatal rather than a fall-through to certificate authentication. Set
    /// False to let the client accept a certificate handshake as well. No effect without
    /// configured external PSKs.</summary>
    function WithExternalPskRequired(AEnabled: Boolean): ITlsClientConfigBuilder;
    /// <summary>Whether session resumption is engaged; defaults to the preset's posture.</summary>
    function WithResumption(AEnabled: Boolean): ITlsClientConfigBuilder;
    /// <summary>The TLS 1.3-only settings.</summary>
    function Tls13: ITls13ClientConfigFacet;
    /// <summary>The TLS 1.2-only settings.</summary>
    function Tls12: ITls12ClientConfigFacet;
    /// <summary>Freezes and returns the client config; raises without a trust source.</summary>
    function Build: ITlsClientConfig;
  end;

  /// <summary>The TLS 1.3-only client settings; each setter returns this facet so they
  /// chain, and the endpoint build and the sibling version facet are reachable here.</summary>
  ITls13ClientConfigFacet = interface(IInterface)
    ['{7C3A9E12-4F85-4B60-A1D9-2E6C0B5F84A7}']
    /// <summary>The certificate-compression backends this endpoint advertises and can
    /// decompress (RFC 8879); empty omits compress_certificate. Defaults to zlib.</summary>
    function WithCertificateDecompressors(
      const ADecompressors: TArray<ICertificateDecompressor>): ITls13ClientConfigFacet;
    /// <summary>The certificate-compression backends this endpoint sends with (RFC 8879);
    /// empty sends only uncompressed. Defaults to zlib.</summary>
    function WithCertificateCompressors(
      const ACompressors: TArray<ICertificateCompressor>): ITls13ClientConfigFacet;
    /// <summary>Whether the client offers 0-RTT early data when a cached ticket authorizes
    /// it (TLS 1.3, RFC 8446 4.2.10). Off by default; an explicit opt-in.</summary>
    function WithEarlyData(AEnabled: Boolean): ITls13ClientConfigFacet;
    function Tls12: ITls12ClientConfigFacet;
    function Build: ITlsClientConfig;
  end;

  /// <summary>The TLS 1.2-only client settings.</summary>
  ITls12ClientConfigFacet = interface(IInterface)
    ['{D5B3C2E6-9A74-4F01-9C38-2E9A5D7F4B06}']
    /// <summary>Whether extended_master_secret (RFC 7627) is required. It is always
    /// offered and used when the peer supports it; True additionally refuses a peer that
    /// does not. Default False.</summary>
    function WithExtendedMasterSecret(ARequire: Boolean): ITls12ClientConfigFacet;
    function Tls13: ITls13ClientConfigFacet;
    function Build: ITlsClientConfig;
  end;

  /// <summary>
  /// Assembles a server endpoint. Common setters and the server-only knobs live here;
  /// version-specific settings live behind Tls13/Tls12. A server build requires a
  /// certificate credential.
  /// </summary>
  ITlsServerConfigBuilder = interface(IInterface)
    ['{9A4E1C28-6D50-4B63-8F17-2E6C0A5F84D3}']
    function WithCipherSuites(const ARegistry: ICipherSuiteRegistry): ITlsServerConfigBuilder;
    function WithSignatureSchemes(const ARegistry: ISignatureSchemeRegistry): ITlsServerConfigBuilder;
    function WithNamedGroups(const ARegistry: INamedGroupRegistry): ITlsServerConfigBuilder;
    function WithSupportedVersions(const AVersions: TArray<UInt16>): ITlsServerConfigBuilder;
    function WithPreferredGroups(const AGroups: TArray<UInt16>): ITlsServerConfigBuilder;
    function WithAlpnProtocols(const AProtocols: TArray<string>): ITlsServerConfigBuilder;
    /// <summary>Whether the server echoes an empty server_name acknowledgement (RFC 6066 3)
    /// when the client offered a host_name. Default True; pass False to omit it.</summary>
    function WithServerNameAcknowledgement(ASend: Boolean): ITlsServerConfigBuilder;
    /// <summary>How the server resolves the cipher suite when more than one is mutually supported.
    /// TServerCipherPreference.ServerOrder (the default) imposes the server's own preference;
    /// TServerCipherPreference.ClientOrder selects the client's most-preferred suite instead.</summary>
    function WithCipherSuitePreference(APreference: TServerCipherPreference): ITlsServerConfigBuilder;
    /// <summary>Reject ALPN unconditionally: on any client ALPN offer the server aborts with
    /// no_application_protocol (RFC 7301 3.2) instead of selecting or declining. Default False.</summary>
    function WithAlpnRejection(AReject: Boolean): ITlsServerConfigBuilder;
    /// <summary>The DER-encoded DistinguishedName issuers the server names in its CertificateRequest
    /// certificate_authorities (RFC 8446 4.2.4 / RFC 5246 7.4.4); empty names none.</summary>
    function WithClientCertificateAuthorities(const AAuthorities: TArray<TBytes>): ITlsServerConfigBuilder;
    /// <summary>The trust source for a requested client certificate chain (mutual TLS);
    /// required whenever WithPeerAuth is not None.</summary>
    function WithTrustStore(const AStore: ITrustAnchorStore): ITlsServerConfigBuilder;
    /// <summary>As WithTrustStore, from a PEM block/bundle or a single DER certificate.</summary>
    function WithTrustAnchors(const AData: TBytes): ITlsServerConfigBuilder;
    /// <summary>Injects a whole-verifier that replaces the built-in trust pipeline for a
    /// requested client certificate. Exclusive: combining it with any anchor source, or
    /// setting two verifiers, is a typed error at Build.</summary>
    function WithCertificateVerifier(
      const AVerifier: ICertificateVerifier): ITlsServerConfigBuilder;
    function WithCertificateChainLimits(
      const ALimits: TCertificateChainLimits): ITlsServerConfigBuilder;
    /// <summary>The server credential the Certificate chain is sent from and whose key
    /// signs the handshake.</summary>
    function WithCredential(const ACredential: TTlsCredential): ITlsServerConfigBuilder; overload;
    /// <summary>A credential from a certificate chain and an unencrypted private key.</summary>
    function WithCredential(const ACertificateChainData,
      APrivateKeyData: TBytes): ITlsServerConfigBuilder; overload;
    /// <summary>As above, decrypting an encrypted private key with APassword.</summary>
    function WithCredential(const ACertificateChainData, APrivateKeyData: TBytes;
      const APassword: string): ITlsServerConfigBuilder; overload;
    /// <summary>A credential imported from a PKCS#12 (.pfx/.p12) blob decrypted with
    /// APassword: leaf + intermediates as the chain and the enclosed private key. To also
    /// staple an OCSP response, compose the returned credential and pass WithCredential.</summary>
    function WithCredentialPkcs12(const AData: TBytes;
      const APassword: string): ITlsServerConfigBuilder;
    /// <summary>Maps a certificate credential to an SNI host_name for virtual hosting: the
    /// server presents this certificate when the client's SNI matches AHost, which may be an
    /// exact name or a single left-most-label wildcard (*.example.com). Call it once per host.
    /// The certificate must cover AHost (its dNSName SANs) or Build fails. A WithCredential set
    /// alongside is the no-SNI / no-match default; without one, an unmatched host is rejected
    /// with unrecognized_name.</summary>
    function WithSniCredential(const AHost: string;
      const ACredential: TTlsCredential): ITlsServerConfigBuilder; overload;
    /// <summary>As above, from a certificate chain and an unencrypted private key.</summary>
    function WithSniCredential(const AHost: string; const ACertificateChainData,
      APrivateKeyData: TBytes): ITlsServerConfigBuilder; overload;
    /// <summary>As above, decrypting an encrypted private key with APassword.</summary>
    function WithSniCredential(const AHost: string; const ACertificateChainData,
      APrivateKeyData: TBytes; const APassword: string): ITlsServerConfigBuilder; overload;
    /// <summary>Full custom control over per-handshake certificate selection (e.g. selecting
    /// by client signature-scheme capability as well as SNI). Mutually exclusive with
    /// WithCredential / WithSniCredential.</summary>
    function WithCredentialResolver(
      const AResolver: ITlsServerCredentialResolver): ITlsServerConfigBuilder;
    /// <summary>Whether the server requests a client certificate (mutual TLS) and how
    /// strictly. A server that requests one also needs a trust source (WithTrustStore).
    /// Defaults to None.</summary>
    function WithPeerAuth(AMode: TClientAuthMode): ITlsServerConfigBuilder;
    /// <summary>The revocation posture applied to a requested client certificate (RFC 6960);
    /// Soft by default. Must-staple (RFC 7633) is always enforced.</summary>
    function WithRevocation(APosture: TRevocationPosture): ITlsServerConfigBuilder;
    /// <summary>SPKI-SHA256 pins the requested client chain must match one of; augments
    /// PKIX, never a bypass. Empty disables it.</summary>
    function WithCertificatePinning(const APins: TArray<TBytes>): ITlsServerConfigBuilder;
    /// <summary>Untrusted intermediate certificates that seed PKIX path building for a requested
    /// client certificate whose chain arrives incomplete. AData is a PEM bundle (one or more
    /// certificates) or a single DER certificate; call more than once to add several DER
    /// certificates. Never trusted on their own and never a bypass - a path must still reach a
    /// configured trust anchor. Calls accumulate.</summary>
    function WithIntermediateCertificates(const AData: TBytes): ITlsServerConfigBuilder;
    /// <summary>DANGEROUS: when enabled, a requested client certificate chain is accepted
    /// without PKIX, revocation, or pinning checks. For tests only - never production.</summary>
    function WithDangerousInsecureSkipVerify(AEnabled: Boolean): ITlsServerConfigBuilder;
    /// <summary>An augment-only client-certificate hook that runs after the built-in pipeline
    /// and can only additionally reject (never loosen it).</summary>
    function WithCertificateVerifyCallback(
      const ACallback: TTlsCertificateVerifyCallback): ITlsServerConfigBuilder;
    /// <summary>Enables the async client-certificate verdict (the deferred-verdict seam) for a
    /// server that requests client authentication: after the built-in pipeline accepts the
    /// client chain the handshake parks for an out-of-band decision, resumed with the engine's
    /// SetCertificateVerdict. Augment-only and fail-closed. ADeadlineMs is advisory (the
    /// engine owns no timer). Off by default.</summary>
    function WithAsyncCertificateVerdict(AEnabled: Boolean;
      ADeadlineMs: Cardinal): ITlsServerConfigBuilder;
    /// <summary>The out-of-band external pre-shared keys (RFC 9258) the server imports and
    /// matches an offered pre_shared_key against (TLS 1.3 only), in preference order. A
    /// matching PSK is preferred over the server's certificate. Empty leaves external PSK
    /// off.</summary>
    function WithExternalPreSharedKeys(
      const APsks: TArray<TExternalPsk>): ITlsServerConfigBuilder;
    /// <summary>The stateful session store backing session-id resumption and stateful
    /// tickets; providing one engages server resumption (subject to WithResumption).</summary>
    function WithSessionStore(const AStore: ISessionStore): ITlsServerConfigBuilder;
    /// <summary>The session-ticket encryption keys for stateless (STEK) tickets.</summary>
    function WithSessionTicketKeys(const AKeys: ISessionTicketKeyManager): ITlsServerConfigBuilder;
    /// <summary>Requests a default STEK, minted at build time from this configuration's own
    /// provider RNG and clock, so stateless tickets honor an injected crypto provider rather than
    /// any concrete default. An explicit WithSessionTicketKeys always overrides this. The keys are
    /// scoped to the built config's lifetime; share a STEK across servers/a fleet via a manager's
    /// InstallKey (e.g. from a KMS).</summary>
    function WithDefaultSessionTicketKeys: ITlsServerConfigBuilder;
    /// <summary>The clock the server reads for ticket issue time, 0-RTT anti-replay windows and
    /// certificate/OCSP freshness; nil (the default) uses the system clock. Injectable primarily
    /// so tests can drive a deterministic time.</summary>
    function WithClock(const AClock: ITlsClock): ITlsServerConfigBuilder;
    /// <summary>The lifetime advertised for issued sessions and tickets, in seconds.</summary>
    function WithTicketLifetime(ASeconds: UInt32): ITlsServerConfigBuilder;
    /// <summary>How many TLS 1.3 NewSessionTickets to issue per handshake.</summary>
    function WithTicketCount(ACount: Int32): ITlsServerConfigBuilder;
    /// <summary>Whether session resumption is engaged; defaults to the preset's posture.</summary>
    function WithResumption(AEnabled: Boolean): ITlsServerConfigBuilder;
    function Tls13: ITls13ServerConfigFacet;
    function Tls12: ITls12ServerConfigFacet;
    /// <summary>Freezes and returns the server config; raises without a credential.</summary>
    function Build: ITlsServerConfig;
  end;

  /// <summary>The TLS 1.3-only server settings.</summary>
  ITls13ServerConfigFacet = interface(IInterface)
    ['{E6C4D3F7-0B85-4012-8D49-3F0B6E8A5C17}']
    function WithCertificateDecompressors(
      const ADecompressors: TArray<ICertificateDecompressor>): ITls13ServerConfigFacet;
    function WithCertificateCompressors(
      const ACompressors: TArray<ICertificateCompressor>): ITls13ServerConfigFacet;
    /// <summary>A cross-connection cache memoizing the server's compressed Certificate
    /// (RFC 8879); providing one deflates a stable certificate once and reuses it across the
    /// connections built from this config (a bounded, thread-safe
    /// TInMemoryCertificateCompressionCache ships for this). nil (the default) compresses on
    /// every handshake.</summary>
    function WithCertificateCompressionCache(
      const ACache: ICertificateCompressionCache): ITls13ServerConfigFacet;
    /// <summary>The 0-RTT early-data byte budget the server authorizes (TLS 1.3, RFC 8446
    /// 4.2.10); 0 disables early data. Accepting early data also needs WithAntiReplay.</summary>
    function WithEarlyData(AMaxBytes: UInt32): ITls13ServerConfigFacet;
    /// <summary>The anti-replay register guarding accepted early data; when a positive
    /// early-data budget is set without one, a default in-memory register is used.</summary>
    function WithAntiReplay(const AStrategy: IAntiReplayStrategy): ITls13ServerConfigFacet;
    function Tls12: ITls12ServerConfigFacet;
    function Build: ITlsServerConfig;
  end;

  /// <summary>The TLS 1.2-only server settings.</summary>
  ITls12ServerConfigFacet = interface(IInterface)
    ['{A1B2C3D4-1E2F-4A3B-8C5D-6E7F80912A34}']
    function WithExtendedMasterSecret(ARequire: Boolean): ITls12ServerConfigFacet;
    function Tls13: ITls13ServerConfigFacet;
    function Build: ITlsServerConfig;
  end;

implementation

end.
