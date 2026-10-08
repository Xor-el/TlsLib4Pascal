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
  TlpITrustAnchorStore,
  TlpICertificateVerifierSource,
  TlpICertificateCompression,
  TlpICertificateCompressionCache,
  TlpCertificateLimits,
  TlpTrustPolicy,
  TlpCertificateStrengthPolicy,
  TlpTlsCredential,
  TlpITlsCredentialResolver,
  TlpISession,
  TlpIClock,
  TlpIKeyLog,
  TlpIEch,
  TlpServerName,
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
    /// <summary>The client-endpoint builder, seeded with the preset's defaults. Raises once the
    /// server view has been taken: one builder configures one endpoint.</summary>
    function Client: ITlsClientConfigBuilder;
    /// <summary>The server-endpoint builder, seeded with the preset's defaults. Raises once the
    /// client view has been taken.</summary>
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
    ['{C71D422B-62F3-4D05-B5F9-A1CA5F0CE99C}']
    function WithCipherSuites(const ARegistry: ICipherSuiteRegistry): ITlsClientConfigBuilder;
    function WithSignatureSchemes(const ARegistry: ISignatureSchemeRegistry): ITlsClientConfigBuilder;
    function WithNamedGroups(const ARegistry: INamedGroupRegistry): ITlsClientConfigBuilder;
    function WithSupportedVersions(const AVersions: TArray<UInt16>): ITlsClientConfigBuilder;
    function WithPreferredGroups(const AGroups: TArray<UInt16>): ITlsClientConfigBuilder;
    /// <summary>The application protocols offered in preference order; an empty list offers no
    /// ALPN. Each name is a non-empty ASCII string of at most 255 bytes and is listed once;
    /// anything else is rejected here (RFC 7301 3.1).</summary>
    function WithAlpnProtocols(const AProtocols: TArray<string>): ITlsClientConfigBuilder;
    /// <summary>Offers record_size_limit (RFC 8449): the largest record this client accepts inbound,
    /// as TLSInnerPlaintext in TLS 1.3. 0 (the default) offers nothing; otherwise 64..16384.</summary>
    function WithRecordSizeLimit(ALimit: Int32): ITlsClientConfigBuilder;
    /// <summary>Whether the client sends GREASE values (RFC 8701). Optional per the RFC;
    /// default True.</summary>
    function WithGrease(AEnable: Boolean): ITlsClientConfigBuilder;
    function WithTrustStore(const AStore: ITrustAnchorStore): ITlsClientConfigBuilder;
    /// <summary>Trust anchors from a PEM block (one certificate or a bundle) or a single
    /// DER certificate, loaded through the provider.</summary>
    function WithTrustAnchors(const AData: TBytes): ITlsClientConfigBuilder;
    /// <summary>DANGEROUS: injects a whole-verifier that REPLACES the built-in trust pipeline for
    /// the server certificate (e.g. an OS delegate) - the caller owns every check the pipeline would
    /// have run. Exclusive: combining it with any anchor source (WithTrustStore/WithTrustAnchors),
    /// or setting two verifiers, is a typed error at Build.</summary>
    function WithDangerousCertificateVerifier(
      const AVerifier: IServerCertificateVerifier): ITlsClientConfigBuilder;
    /// <summary>Installs a per-connection source that builds the server-certificate verifier
    /// from the connection's trust context (its clock and revocation posture), rather than a
    /// pre-built instance - so an OS trust delegate (TlsLib.Trust.System) can honor them.
    /// Same exclusivity as WithDangerousCertificateVerifier: not combinable with an anchor source
    /// or a second verifier.</summary>
    function WithCertificateVerifierSource(
      const ASource: IServerCertificateVerifierSource): ITlsClientConfigBuilder;
    /// <summary>The certificate-chain resource caps applied before PKIX validation.</summary>
    function WithCertificateChainLimits(
      const ALimits: TCertificateChainLimits): ITlsClientConfigBuilder;
    /// <summary>The minimum-strength floors a peer certificate chain's keys must meet
    /// (RSA modulus bits, allowed EC curves, EdDSA). The advertised-scheme chain-signature
    /// filter and the MD5/SHA-1 rejection are always applied and not affected by this.</summary>
    function WithMinimumCertificateStrength(
      const APolicy: TCertificateStrengthPolicy): ITlsClientConfigBuilder;
    /// <summary>The client's own credential for mutual TLS, presented when the server
    /// sends a CertificateRequest the credential can satisfy. Build one with
    /// TTlsCredential.Load / LoadPkcs12.</summary>
    function WithCredential(const ACredential: TTlsCredential): ITlsClientConfigBuilder;
    /// <summary>The stapled-OCSP revocation posture (RFC 6960): Soft (default) accepts a
    /// missing or indeterminate staple, Hard requires a current Good one, Off skips the
    /// check. Must-staple (RFC 7633) is enforced only for an initial-handshake server
    /// certificate the client requested a staple for (WithOcspStaplingRequest). Under Hard with
    /// WithResumeVerification(Reverify) and no WithLiveRevocationVerdict, the client declines
    /// resumption and does a full handshake (a resume carries no staple to check).</summary>
    function WithRevocation(APosture: TRevocationPosture): ITlsClientConfigBuilder;
    /// <summary>SPKI-SHA256 public-key pins: when set, some certificate in the server chain
    /// must match one pin. Augments PKIX validation; never a bypass. Empty disables it.</summary>
    function WithCertificatePinning(const APins: TArray<TBytes>): ITlsClientConfigBuilder;
    /// <summary>Untrusted intermediate certificates that seed PKIX path building when the server
    /// sends an incomplete chain (e.g. a leaf-only server that omits its issuing CA). AData is a
    /// PEM bundle (one or more certificates) or a single DER certificate; call more than once to
    /// add several DER certificates. They are never trusted on their own and never bypass
    /// validation - a path must still reach a configured trust anchor, and a complete chain the
    /// server sends is still validated exactly as presented. Calls accumulate. This is NOT a
    /// substitute for a trust anchor: if validation fails with unknown_ca even when the server
    /// sends a complete chain, the client is missing the ROOT, not an intermediate - configure the
    /// root with WithTrustAnchors (or opt into OS system trust) instead, since an intermediate can
    /// never terminate a path. Public-CA intermediates rotate, so a pinned intermediate can go
    /// stale - bundle the currently valid set and refresh it with your trust configuration. The
    /// library never fetches (sans-IO); an application that wants AIA behaviour can resolve the
    /// issuer URL out of band and feed the result here.</summary>
    function WithIntermediateCertificates(const AData: TBytes): ITlsClientConfigBuilder;
    /// <summary>DANGEROUS: stop checking that the server certificate matches the connected
    /// host (RFC 9525). The chain is still validated to a trust anchor, but ANY trusted
    /// certificate is then accepted regardless of the host it was issued for - a
    /// man-in-the-middle risk. Name checking is on by default; only a deliberate pin-only
    /// trust model should disable it.</summary>
    function WithDangerousDisableServerNameCheck: ITlsClientConfigBuilder;
    /// <summary>Whether the client sends the connection host as server_name (SNI, RFC 6066 sec.
    /// 3). Send, the default, sends a DNS host and never an IP literal; Omit sends none, while the
    /// server certificate is still verified against the host (RFC 9525) unless the name check is
    /// disabled. Applies to TLS 1.3 and 1.2. Under ECH the ClientHelloOuter still carries the
    /// public_name (RFC 9849 sec. 6.1) and Omit leaves the inner without a name. A server may
    /// refuse a ClientHello without server_name (missing_extension, RFC 8446 sec. 9.2) or present a
    /// default certificate that then fails the name check.</summary>
    function WithServerNameIndication(AMode: TServerNameIndication): ITlsClientConfigBuilder;
    /// <summary>Whether the client offers status_request (OCSP stapling, RFC 6066). Off by
    /// default: without it the client requests no staple and rejects an unsolicited one.</summary>
    function WithOcspStaplingRequest(AEnabled: Boolean): ITlsClientConfigBuilder;
    /// <summary>DANGEROUS: when enabled, the server certificate chain is accepted without
    /// PKIX, revocation, host-name, or pinning checks. For tests and pinned/self-signed
    /// development peers only - never production. Off by default. Satisfies the Build-time
    /// trust-source requirement on its own; no anchor store is needed (one supplied is kept
    /// but not consulted).</summary>
    function WithDangerousInsecureSkipVerify: ITlsClientConfigBuilder;
    /// <summary>DANGEROUS: hands every secret of every connection built from this config to
    /// AKeyLog in the SSLKEYLOGFILE format (RFC 9850), so a packet capture can be decrypted.
    /// For debugging only - never production. nil (the default) clears it.</summary>
    function WithDangerousKeyLog(const AKeyLog: IKeyLog): ITlsClientConfigBuilder;
    /// <summary>An augment-only peer-certificate hook that runs after the built-in pipeline
    /// and can only additionally reject (never loosen it). Bridges a host framework's own
    /// verify callback.</summary>
    function WithCertificateVerifyCallback(
      const ACallback: TTlsCertificateVerifyCallback): ITlsClientConfigBuilder;
    /// <summary>Enables a host-decision peer-certificate verdict (the deferred-verdict seam):
    /// after the built-in pipeline accepts the server chain the handshake parks and raises a
    /// CertificateReceived event for an out-of-band decision, resumed with the engine's
    /// SetCertificateVerdict. Augment-only and fail-closed; it does not change how an
    /// indeterminate stapled revocation outcome is decided (the posture still decides that
    /// inline). Calling this arms the park unconditionally; it is off unless called. ADeadlineMs is
    /// the resolver's time budget (the engine owns no timer); 0 imposes no budget. The last of this
    /// and WithLiveRevocationVerdict wins.</summary>
    function WithAsyncCertificateVerdict(
      ADeadlineMs: Cardinal): ITlsClientConfigBuilder;
    /// <summary>Defers an indeterminate stapled revocation outcome to a live OCSP/CRL resolver at
    /// the park (rather than deciding it inline by the posture), so a Hard posture is reachable for
    /// a server that carries no staple. Parks after the pipeline accepts the chain, augment-only and
    /// fail-closed. ADeadlineMs is the resolver's fetch budget (the engine owns no timer). The
    /// last of this and WithAsyncCertificateVerdict wins.</summary>
    function WithLiveRevocationVerdict(ADeadlineMs: Cardinal): ITlsClientConfigBuilder;
    /// <summary>The client-side session cache to draw resumed sessions from and store new
    /// ones into; providing one engages client resumption (subject to WithResumption). Sessions
    /// this configuration establishes are scoped to it: a cache instance shared with another
    /// configuration does not resume across the two, so a strict configuration never resumes a
    /// session a lenient one authenticated. Use WithResumptionScope to opt two configurations into
    /// sharing (asserting they trust identically), or WithResumeVerification to re-check a resumed
    /// server when trust may differ.</summary>
    function WithSessionCache(const ACache: ISessionCache): ITlsClientConfigBuilder;
    /// <summary>Pins this configuration's cache scope to AScope (an opaque tag of at most 32 bytes)
    /// so configurations given the same scope resume each other's sessions from a shared cache; the
    /// caller asserts they trust identically. Empty or unset (the default) mints a fresh
    /// per-configuration scope, so a shared cache never resumes across configurations. Independent of
    /// the WithSessionCache call order.</summary>
    function WithResumptionScope(const AScope: TBytes): ITlsClientConfigBuilder;
    /// <summary>The clock the client reads for a resumption PSK's obfuscated_ticket_age and
    /// ticket-lifetime expiry (RFC 8446 4.2.11 / 4.6.1); defaults to the system
    /// clock, and nil is refused. Injectable primarily so tests can drive a deterministic time.</summary>
    function WithClock(const AClock: ITlsClock): ITlsClientConfigBuilder;
    /// <summary>The out-of-band external pre-shared keys (RFC 9258) the client imports and
    /// offers in the ClientHello (TLS 1.3 only), in preference order. When set, the client
    /// offers these instead of drawing a resumption session from the cache. Empty leaves
    /// external PSK off.</summary>
    function WithExternalPreSharedKeys(
      const APsks: TArray<TExternalPsk>): ITlsClientConfigBuilder;
    /// <summary>Whether configured external PSKs are required (default True): a non-PSK
    /// ServerHello is fatal rather than a fall-through to certificate authentication. Set
    /// False to let the client accept a certificate handshake as well - which then needs a
    /// trust source, so a PSK-only client (no trust) with False is refused at Build. No effect
    /// without configured external PSKs.</summary>
    function WithExternalPskRequired(AEnabled: Boolean): ITlsClientConfigBuilder;
    /// <summary>Whether session resumption is engaged; defaults to the preset's posture.</summary>
    function WithResumption(AEnabled: Boolean): ITlsClientConfigBuilder;
    /// <summary>How the client verifies a resumed server: ReuseOriginal (the default) reuses the
    /// original handshake's authentication (RFC 8446 2.2); Reverify re-runs the certificate
    /// verifier against the stored peer chain, for a stricter posture that re-checks a resumed
    /// server against current trust, at the cost of the verification work on every resume. Under
    /// WithRevocation(Hard) without WithLiveRevocationVerdict a reverified resume could never obtain
    /// revocation status (a resume carries no staple), so the client offers no resumption and does a
    /// full handshake instead.</summary>
    function WithResumeVerification(AMode: TResumeVerification): ITlsClientConfigBuilder;
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
    ['{BB34A64C-9B36-435A-A380-263DCA60E186}']
    /// <summary>The certificate-compression backends this endpoint advertises and can
    /// decompress (RFC 8879); empty omits compress_certificate. Defaults to zlib.</summary>
    function WithCertificateDecompressors(
      const ADecompressors: TArray<ICertificateDecompressor>): ITls13ClientConfigFacet;
    /// <summary>The certificate-compression backends this endpoint sends with (RFC 8879);
    /// empty sends only uncompressed. Defaults to zlib.</summary>
    function WithCertificateCompressors(
      const ACompressors: TArray<ICertificateCompressor>): ITls13ClientConfigFacet;
    /// <summary>Whether the client offers 0-RTT early data when a cached ticket authorizes
    /// it (TLS 1.3, RFC 8446 4.2.10). Off by default.</summary>
    function WithEarlyData(AEnabled: Boolean): ITls13ClientConfigFacet;
    /// <summary>
    /// Offers Encrypted Client Hello (RFC 9849) with the application-supplied
    /// ECHConfigList (typically fetched from the DNS HTTPS/SVCB ech parameter). A
    /// malformed list is rejected when the config is built. On an ECH reject the
    /// handshake raises EEchRejectedTlsLibException carrying the server's retry_configs;
    /// the library never falls back to plaintext.
    /// </summary>
    function WithEncryptedClientHello(
      const AEchConfigList: TBytes): ITls13ClientConfigFacet;
    /// <summary>
    /// Offers Encrypted Client Hello for a reconnection driven by a prior reject's
    /// retry_configs (RFC 9849 sec. 6.1.6). Identical to WithEncryptedClientHello but marks
    /// the attempt as a retry, so a second reject is not itself retried - the one-retry cap.
    /// </summary>
    function WithEncryptedClientHelloRetry(
      const AEchConfigList: TBytes): ITls13ClientConfigFacet;
    /// <summary>Whether to send a GREASE ECH (RFC 9849 sec. 6.2) when no usable config is
    /// available. Off by default.</summary>
    function WithEchGrease(AEnabled: Boolean): ITls13ClientConfigFacet;
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
    ['{6D799A9D-DAB4-42B8-82BE-195CE6796A27}']
    function WithCipherSuites(const ARegistry: ICipherSuiteRegistry): ITlsServerConfigBuilder;
    function WithSignatureSchemes(const ARegistry: ISignatureSchemeRegistry): ITlsServerConfigBuilder;
    function WithNamedGroups(const ARegistry: INamedGroupRegistry): ITlsServerConfigBuilder;
    function WithSupportedVersions(const AVersions: TArray<UInt16>): ITlsServerConfigBuilder;
    function WithPreferredGroups(const AGroups: TArray<UInt16>): ITlsServerConfigBuilder;
    /// <summary>The application protocols the server selects from, in preference order; an empty
    /// list offers no ALPN. Each name is a non-empty ASCII string of at most 255 bytes and is
    /// listed once; anything else is rejected here (RFC 7301 3.1).</summary>
    function WithAlpnProtocols(const AProtocols: TArray<string>): ITlsServerConfigBuilder;
    /// <summary>Offers record_size_limit (RFC 8449): the largest record this server accepts inbound,
    /// as TLSInnerPlaintext in TLS 1.3. 0 (the default) offers nothing; otherwise 64..16384.</summary>
    function WithRecordSizeLimit(ALimit: Int32): ITlsServerConfigBuilder;
    /// <summary>Whether the server echoes an empty server_name acknowledgement (RFC 6066 3)
    /// when the client offered a host_name. Default True; pass False to omit it.</summary>
    function WithServerNameAcknowledgement(ASend: Boolean): ITlsServerConfigBuilder;
    /// <summary>How the server resolves the cipher suite when more than one is mutually supported.
    /// TServerCipherPreference.ServerOrder (the default) imposes the server's own preference;
    /// TServerCipherPreference.ClientOrder selects the client's most-preferred suite instead.
    /// Applies to both TLS 1.3 and TLS 1.2 (default ServerOrder).</summary>
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
    /// <summary>DANGEROUS: injects a whole-verifier that REPLACES the built-in trust pipeline for a
    /// requested client certificate - the caller owns every check the pipeline would have run.
    /// Exclusive: combining it with any anchor source, or setting two verifiers, is a typed error
    /// at Build.</summary>
    function WithDangerousCertificateVerifier(
      const AVerifier: IClientCertificateVerifier): ITlsServerConfigBuilder;
    /// <summary>Installs a per-connection source that builds the client-certificate verifier
    /// from the connection's client-trust context (its clock and revocation posture) - so an OS
    /// client delegate (TlsLib.Trust.System) can validate the peer against the configured
    /// client-CA anchors as an exclusive trust root. The source consumes those anchors, so
    /// (unlike an injected whole-verifier) it composes with WithTrustAnchors/WithTrustStore. With
    /// WithPeerAuth on, Build requires those anchors to yield at least one root (a source with
    /// nothing to consume is refused, not deferred to a handshake failure); a verifier that brings
    /// its own roots belongs in WithDangerousCertificateVerifier.</summary>
    function WithCertificateVerifierSource(
      const ASource: IClientCertificateVerifierSource): ITlsServerConfigBuilder;
    function WithCertificateChainLimits(
      const ALimits: TCertificateChainLimits): ITlsServerConfigBuilder;
    /// <summary>The minimum-strength floors a peer (client) certificate chain's keys must meet
    /// (RSA modulus bits, allowed EC curves, EdDSA). The advertised-scheme chain-signature
    /// filter and the MD5/SHA-1 rejection are always applied and not affected by this.</summary>
    function WithMinimumCertificateStrength(
      const APolicy: TCertificateStrengthPolicy): ITlsServerConfigBuilder;
    /// <summary>The server credential the Certificate chain is sent from and whose key
    /// signs the handshake. Build one with TTlsCredential.Load / LoadPkcs12.</summary>
    function WithCredential(const ACredential: TTlsCredential): ITlsServerConfigBuilder;
    /// <summary>Maps a certificate credential to an SNI host_name for virtual hosting: the
    /// server presents this certificate when the client's SNI matches AHost, which may be an
    /// exact name or a single left-most-label wildcard (*.example.com). Call it once per host.
    /// The certificate must cover AHost (its dNSName SANs) or Build fails. A WithCredential set
    /// alongside is the no-SNI / no-match default; without one, an unmatched host is rejected
    /// with unrecognized_name.</summary>
    function WithSniCredential(const AHost: string;
      const ACredential: TTlsCredential): ITlsServerConfigBuilder;
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
    /// Soft by default. Must-staple (RFC 7633) never applies to a client certificate (it is
    /// never stapled).</summary>
    function WithRevocation(APosture: TRevocationPosture): ITlsServerConfigBuilder;
    /// <summary>SPKI-SHA256 pins, one of which some certificate on the validated client path must
    /// match; augments PKIX, never a bypass, and applies only when client authentication is
    /// requested. Each pin must be 32 bytes. Empty disables it.</summary>
    function WithCertificatePinning(const APins: TArray<TBytes>): ITlsServerConfigBuilder;
    /// <summary>Untrusted intermediate certificates that seed PKIX path building for a requested
    /// client certificate whose chain arrives incomplete (leaf-only client certificates are common
    /// in enterprise mutual-TLS). AData is a PEM bundle (one or more certificates) or a single DER
    /// certificate; call more than once to add several DER certificates. Never trusted on their own
    /// and never a bypass - a path must still reach a configured trust anchor. Calls accumulate.
    /// This is NOT a substitute for a trust anchor: if validation fails with unknown_ca even when
    /// the client sends a complete chain, the missing piece is the ROOT, not an intermediate -
    /// configure it with WithTrustAnchors, since an intermediate can never terminate a path.
    /// Public-CA intermediates rotate, so a pinned intermediate can go stale - bundle the currently
    /// valid set and refresh it with your trust configuration.</summary>
    function WithIntermediateCertificates(const AData: TBytes): ITlsServerConfigBuilder;
    /// <summary>DANGEROUS: when enabled, a requested client certificate chain is accepted
    /// without PKIX, revocation, or pinning checks. For tests only - never production. Satisfies
    /// the Build-time client-auth trust-source requirement on its own; no anchor store is needed
    /// (one supplied is kept but not consulted).</summary>
    function WithDangerousInsecureSkipVerify: ITlsServerConfigBuilder;
    /// <summary>DANGEROUS: hands every secret of every connection built from this config to
    /// AKeyLog in the SSLKEYLOGFILE format (RFC 9850), so a packet capture can be decrypted.
    /// For debugging only - never production. nil (the default) clears it.</summary>
    function WithDangerousKeyLog(const AKeyLog: IKeyLog): ITlsServerConfigBuilder;
    /// <summary>An augment-only client-certificate hook that runs after the built-in pipeline
    /// and can only additionally reject (never loosen it).</summary>
    function WithCertificateVerifyCallback(
      const ACallback: TTlsCertificateVerifyCallback): ITlsServerConfigBuilder;
    /// <summary>Enables a host-decision client-certificate verdict (the deferred-verdict seam) for a
    /// server that requests client authentication: after the built-in pipeline accepts the client
    /// chain the handshake parks for an out-of-band decision, resumed with the engine's
    /// SetCertificateVerdict. Augment-only and fail-closed; it does not change how an indeterminate
    /// revocation outcome is decided (the posture still decides that inline). Calling this arms the
    /// park unconditionally; it is off unless called. ADeadlineMs is the resolver's fetch budget
    /// (the engine and stream drivers enforce no timer). The last of this and
    /// WithLiveRevocationVerdict wins.</summary>
    function WithAsyncCertificateVerdict(
      ADeadlineMs: Cardinal): ITlsServerConfigBuilder;
    /// <summary>Defers an indeterminate client-certificate revocation outcome to a live OCSP/CRL
    /// resolver at the park (rather than deciding it inline by the posture). A client certificate is
    /// never stapled, so this is the only way a Hard posture is reachable for client authentication.
    /// Parks after the pipeline accepts the chain, augment-only and fail-closed. ADeadlineMs is the
    /// resolver's fetch budget. The last of this and WithAsyncCertificateVerdict wins.</summary>
    function WithLiveRevocationVerdict(ADeadlineMs: Cardinal): ITlsServerConfigBuilder;
    /// <summary>The out-of-band external pre-shared keys (RFC 9258) the server imports and
    /// matches an offered pre_shared_key against (TLS 1.3 only), in preference order. A
    /// matching PSK is preferred over the server's certificate. Empty leaves external PSK
    /// off.</summary>
    function WithExternalPreSharedKeys(
      const APsks: TArray<TExternalPsk>): ITlsServerConfigBuilder;
    /// <summary>The stateful session store backing session-id resumption and stateful
    /// tickets; providing one engages server resumption (subject to WithResumption). A store or
    /// ticket-key manager shared across configurations lets them resume each other's sessions;
    /// use WithResumptionScope to partition configurations that do not trust identically. A
    /// configuration requesting client authentication must set a scope when it supplies a store
    /// (refused at Build otherwise).</summary>
    function WithSessionStore(const AStore: ISessionStore): ITlsServerConfigBuilder;
    /// <summary>The session-ticket encryption keys for stateless (STEK) tickets. A manager shared
    /// across configurations (e.g. a fleet key) lets them resume each other's tickets; use
    /// WithResumptionScope to partition configurations that do not trust identically. A
    /// configuration requesting client authentication must set a scope when it supplies a manager
    /// (refused at Build otherwise).</summary>
    function WithSessionTicketKeys(const AKeys: ISessionTicketKeyManager): ITlsServerConfigBuilder;
    /// <summary>An opaque scope (at most 32 bytes) sealed into every ticket/session this
    /// configuration issues and required to match on resumption. When a ticket key or session
    /// store is shared across configurations, only those given the same scope resume each other's
    /// sessions - so a configuration never
    /// resumes a session another established under different client-authentication trust. Empty
    /// (the default) does not partition: configurations sharing a key/store resume each other, as
    /// before. Set the same scope on configurations that trust identically, different scopes to
    /// keep them apart.</summary>
    function WithResumptionScope(const AScope: TBytes): ITlsServerConfigBuilder;
    /// <summary>Requests a default STEK, minted at build time from this configuration's own
    /// provider RNG and clock, so stateless tickets honor an injected crypto provider rather than
    /// any concrete default. An explicit WithSessionTicketKeys always overrides this. The keys are
    /// scoped to the built config's lifetime; share a STEK across servers/a fleet via a manager's
    /// InstallKey (e.g. from a KMS).</summary>
    function WithDefaultSessionTicketKeys: ITlsServerConfigBuilder;
    /// <summary>The clock the server reads for ticket issue time, 0-RTT anti-replay windows and
    /// certificate/OCSP freshness; defaults to the system clock, and nil is refused. Injectable
    /// primarily so tests can drive a deterministic time.</summary>
    function WithClock(const AClock: ITlsClock): ITlsServerConfigBuilder;
    /// <summary>The lifetime advertised for issued sessions and tickets, in seconds.</summary>
    function WithTicketLifetime(ASeconds: UInt32): ITlsServerConfigBuilder;
    /// <summary>How many TLS 1.3 NewSessionTickets to issue per handshake, 0..8 (0 issues none).</summary>
    function WithTicketCount(ACount: Int32): ITlsServerConfigBuilder;
    /// <summary>Whether session resumption is engaged; defaults to the preset's posture.</summary>
    function WithResumption(AEnabled: Boolean): ITlsServerConfigBuilder;
    function Tls13: ITls13ServerConfigFacet;
    function Tls12: ITls12ServerConfigFacet;
    /// <summary>Freezes and returns the server config; raises without a credential, credential
    /// resolver or external PSK.</summary>
    function Build: ITlsServerConfig;
  end;

  /// <summary>The TLS 1.3-only server settings.</summary>
  ITls13ServerConfigFacet = interface(IInterface)
    ['{2A9D4E71-6C38-4B05-9F82-7E1C0A5D6B34}']
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
    /// 4.2.10); 0 disables early data. A default anti-replay register is provided when none is
    /// set (see WithAntiReplay); resumption must be enabled for 0-RTT, and the budget must be below
    /// 1 MiB. With an explicit WithSessionTicketKeys the default per-configuration register
    /// cannot guard tickets shared across instances, so a session store or WithAntiReplay is
    /// required. Accepted early data is bounded by the value carried in the resumed ticket (what
    /// the client was told), so lowering this later does not retroactively shrink already-issued
    /// tickets - rotate the ticket keys.</summary>
    function WithEarlyData(AMaxBytes: UInt32): ITls13ServerConfigFacet;
    /// <summary>The anti-replay register guarding accepted early data; when a positive
    /// early-data budget is set without one, a default in-memory register is used (one per config,
    /// shared across connections). That default is not enough for tickets minted under shared
    /// ticket keys, which need a session store or a strategy shared by every instance; a
    /// single-instance deployment opts in by passing a register here explicitly.</summary>
    function WithAntiReplay(const AStrategy: IAntiReplayStrategy): ITls13ServerConfigFacet;
    /// <summary>Enables Encrypted Client Hello: the key store the server decrypts offers with
    /// and advertises as retry_configs (RFC 9849), swapped to rotate keys. Build one from a
    /// store class - e.g. TInMemoryEchKeyStore.FromPem / .FromConfig - or supply your own. Raises on a
    /// nil store, or on an entry the crypto provider cannot serve; a second call replaces the first.</summary>
    function WithEchKeyStore(const AKeyStore: IEchServerKeyStore): ITls13ServerConfigFacet; overload;
    /// <summary>As WithEchKeyStore, and ATrialDecrypt makes the server trial-decrypt an ECH offer
    /// against every key when the config_id does not match (RFC 9849 sec. 7.1); off by default
    /// (match by config_id). Every entry must be one the crypto provider can serve, or this
    /// raises.</summary>
    function WithEchKeyStore(const AKeyStore: IEchServerKeyStore;
      ATrialDecrypt: Boolean): ITls13ServerConfigFacet; overload;
    /// <summary>Deploys this server as a split-mode ECH backend (RFC 9849 sec. 7.2): it accepts an
    /// inner-type ech forwarded by a client-facing server and confirms it. Off by default, so an
    /// inner-type ech at a non-backend server aborts with illegal_parameter. Mutually exclusive with
    /// WithEchKeyStore (a backend holds no ECH keys): whichever is called second raises.</summary>
    function WithEchBackend: ITls13ServerConfigFacet;
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
