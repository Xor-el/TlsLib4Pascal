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
  TlpICertificateVerifierSource,
  TlpICertificateCompression,
  TlpICertificateCompressionCache,
  TlpCertificateLimits,
  TlpTrustPolicy,
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
    ['{29AF3A6C-72D0-4EC3-803D-28C8EC0D8632}']
    /// <summary>The cipher-suite registry offered. A configured TLS 1.2 PSK adds its ECDHE_PSK
    /// suites to it.</summary>
    function WithCipherSuites(const ARegistry: ICipherSuiteRegistry): ITlsClientConfigBuilder;
    /// <summary>Narrows the configured cipher suites to ASuites, in that order, per protocol: a
    /// protocol ASuites names keeps exactly the listed suites; one it does not name is unchanged.
    /// Never widens - a code outside the configured set is refused at Build, and so is a list
    /// naming only suites of a protocol version that is not offered (a TLS 1.2 list beside a TLS
    /// 1.3-only config); a mixed list is accepted and its off-version part is ignored. The
    /// configured set includes the ECDHE_PSK suites a configured TLS 1.2 PSK adds.</summary>
    function WithCipherSuiteList(const ASuites: TArray<UInt16>): ITlsClientConfigBuilder;
    /// <summary>The signature schemes this client offers and accepts from the server. Its own
    /// client-certificate signatures follow the credential key (ISigningKey.WithPreferredSchemes).</summary>
    function WithSignatureSchemes(const ARegistry: ISignatureSchemeRegistry): ITlsClientConfigBuilder;
    /// <summary>The named groups this client offers and accepts.</summary>
    function WithNamedGroups(const ARegistry: INamedGroupRegistry): ITlsClientConfigBuilder;
    /// <summary>The protocol versions this client offers.</summary>
    function WithSupportedVersions(const AVersions: TArray<UInt16>): ITlsClientConfigBuilder;
    /// <summary>The groups to prefer, in order, among the registered ones; a code the group
    /// registry lacks is skipped. Build refuses an empty list, a list with no registered group,
    /// and, when TLS 1.2 is offered, a list with no registered classical ECDHE group. Each group
    /// is listed once; a repeat is rejected here.</summary>
    function WithPreferredGroups(const AGroups: TArray<UInt16>): ITlsClientConfigBuilder;
    /// <summary>The application protocols offered in preference order; an empty list offers no
    /// ALPN. Each name is 1..255 opaque octets and is listed once; anything else is rejected here
    /// (RFC 7301 3.1). TAlpnProtocols.FromText turns ASCII names such as "h2" into octets.</summary>
    function WithAlpnProtocols(const AProtocols: TArray<TBytes>): ITlsClientConfigBuilder;
    /// <summary>Offers record_size_limit (RFC 8449): the largest record this client accepts inbound,
    /// as TLSInnerPlaintext in TLS 1.3. 0 (the default) offers nothing; otherwise 64..16384.</summary>
    function WithRecordSizeLimit(ALimit: Int32): ITlsClientConfigBuilder;
    /// <summary>The certificate-chain resource caps applied before PKIX validation. A Custom
    /// verifier is bound only by MaxTotalChainLength.</summary>
    function WithCertificateChainLimits(
      const ALimits: TCertificateChainLimits): ITlsClientConfigBuilder;
    /// <summary>The client's own credential for mutual TLS, presented when the server
    /// sends a CertificateRequest the credential can satisfy. Build one with
    /// TTlsCredential.Load / LoadPkcs12.</summary>
    function WithCredential(const ACredential: TTlsCredential): ITlsClientConfigBuilder;
    /// <summary>SPKI-SHA256 public-key pins: when set, some certificate in the server chain
    /// must match one pin. Augments PKIX validation; never a bypass. Empty disables it.</summary>
    function WithCertificatePinning(const APins: TArray<TBytes>): ITlsClientConfigBuilder;
    /// <summary>DANGEROUS: stop checking that the server certificate matches the connected
    /// host (RFC 9525). The chain is still validated to a trust anchor, but ANY trusted
    /// certificate is then accepted regardless of the host it was issued for - a
    /// man-in-the-middle risk. Name checking is on by default; only a deliberate pin-only
    /// trust model should disable it. It governs the connected host only: an Encrypted Client
    /// Hello reject is still verified against the config's public_name (RFC 9849 6.1.7). Ignored
    /// under a Custom verifier, which owns the identity check. Build refuses it on a PSK-only
    /// client.</summary>
    function WithDangerousDisableServerNameCheck: ITlsClientConfigBuilder;
    /// <summary>Whether the client sends the connection host as server_name (SNI, RFC 6066 sec.
    /// 3). Send, the default, sends a DNS host and never an IP literal; Omit sends none, while the
    /// server certificate is still verified against the host (RFC 9525) unless the name check is
    /// disabled. Applies to TLS 1.3 and 1.2. Under ECH the ClientHelloOuter still carries the
    /// public_name (RFC 9849 sec. 6.1) and Omit leaves the inner without a name. A server may
    /// refuse a ClientHello without server_name (missing_extension, RFC 9846 sec. 9.2) or present a
    /// default certificate that then fails the name check.</summary>
    function WithServerNameIndication(AMode: TServerNameIndication): ITlsClientConfigBuilder;
    /// <summary>Whether the client offers status_request (OCSP stapling, RFC 6066). Off by
    /// default, but the Hardened and Strict presets enable it: without it the client requests no
    /// staple and rejects an unsolicited one.</summary>
    function WithOcspStaplingRequest(AEnabled: Boolean): ITlsClientConfigBuilder;
    /// <summary>How the client verifies the server's certificate: one policy, made by
    /// TServerVerification (WebPki over anchors, a source that owns its roots, a whole verifier, or
    /// DangerousSkip). A later call replaces an earlier one. Build requires a policy unless the
    /// client authenticates by an external PSK. DangerousSkip accepts the chain without PKIX,
    /// revocation or host-name checks (configured pins still apply to the leaf); tests and pinned
    /// development peers only.</summary>
    function WithServerVerification(const AVerification: IServerVerification): ITlsClientConfigBuilder;
    /// <summary>DANGEROUS: hands every secret of every connection built from this config to
    /// AKeyLog in the SSLKEYLOGFILE format (RFC 9850), so a packet capture can be decrypted.
    /// For debugging only - never production. nil (the default) clears it.</summary>
    function WithDangerousKeyLog(const AKeyLog: IKeyLog): ITlsClientConfigBuilder;
    /// <summary>An augment-only peer-certificate hook that runs last, after the built-in pipeline
    /// and pinning, and can only additionally reject (never loosen it). Bridges a host framework's
    /// own verify callback. On an Encrypted Client Hello reject its host is the config's
    /// public_name.</summary>
    function WithCertificateVerifyCallback(
      const ACallback: TTlsCertificateVerifyCallback): ITlsClientConfigBuilder;
    /// <summary>Enables a host-decision peer-certificate verdict (the deferred-verdict seam):
    /// after the built-in pipeline accepts the server chain the handshake parks and raises a
    /// CertificateReceived event for an out-of-band decision, resumed with the engine's
    /// SetCertificateVerdict. Augment-only and fail-closed; it does not change how an
    /// indeterminate stapled revocation outcome is decided (the posture still decides that
    /// inline). Calling this arms the park unconditionally; it is off unless called. ADeadlineMs is
    /// the resolver's time budget (the engine owns no timer); 0 imposes no budget. Raises if
    /// WithLiveRevocationVerdict was called: the two share one verdict slot. On an Encrypted
    /// Client Hello reject the host decision sees the config's public_name.</summary>
    function WithAsyncCertificateVerdict(
      ADeadlineMs: Cardinal): ITlsClientConfigBuilder;
    /// <summary>Defers an indeterminate stapled revocation outcome to a live OCSP/CRL resolver at
    /// the park (rather than deciding it inline by the posture), so a Hard posture is reachable for
    /// a server that carries no staple. Parks after the pipeline accepts the chain, augment-only and
    /// fail-closed. ADeadlineMs is the resolver's fetch budget (the engine owns no timer). Raises
    /// if WithAsyncCertificateVerdict was called: the two share one verdict slot.</summary>
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
    /// the WithSessionCache call order. The server method of the same name has the opposite empty
    /// default: it shares rather than isolates.</summary>
    function WithResumptionScope(const AScope: TBytes): ITlsClientConfigBuilder;
    /// <summary>The clock the client reads for a resumption PSK's obfuscated_ticket_age and
    /// ticket-lifetime expiry (RFC 9846 4.3.11 / 4.7.1) and for the server chain's certificate
    /// validity and stapled-OCSP freshness; defaults to the system
    /// clock, and nil is refused. Injectable primarily so tests can drive a deterministic time.</summary>
    function WithClock(const AClock: ITlsClock): ITlsClientConfigBuilder;
    /// <summary>The elapsed-time source the connection layer measures its handshake read cap on;
    /// defaults to the system source, and nil is refused. Injectable primarily so tests can drive
    /// deterministic elapsed time.</summary>
    function WithMonotonicClock(const AClock: ITlsMonotonicClock): ITlsClientConfigBuilder;
    /// <summary>Whether session resumption is engaged; defaults to the preset's posture.</summary>
    function WithResumption(AEnabled: Boolean): ITlsClientConfigBuilder;
    /// <summary>How the client verifies a resumed server: ReuseOriginal (the default) keeps the
    /// original authentication (inferred from RFC 9846 2.2); Reverify re-runs the certificate
    /// verifier against the stored peer chain before the session is offered, at the cost of a
    /// verification per resume. A session whose chain fails current trust is not offered, so no
    /// ticket, binder or early data is sent and the client runs a full handshake (Resumed = False).
    /// Build refuses Reverify without a session cache and resumption on, with WithEarlyData(True)
    /// and an async certificate verdict, and, since a resume carries no staple, under a Hard
    /// revocation posture without WithLiveRevocationVerdict.</summary>
    function WithResumeVerification(AMode: TResumeVerification): ITlsClientConfigBuilder;
    /// <summary>Whether the client sends GREASE values (RFC 8701) in its ClientHello, whatever
    /// versions it offers. Optional per the RFC; default True.</summary>
    function WithGrease(AEnable: Boolean): ITlsClientConfigBuilder;
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
    ['{95EA36E2-4E85-4C11-A62A-712DEFE59D2C}']
    /// <summary>The out-of-band external pre-shared keys (RFC 9258) the client imports and
    /// offers in the ClientHello, in preference order, after any cached resumption ticket. Empty
    /// leaves external PSK off.</summary>
    function WithExternalPreSharedKeys(
      const APsks: TArray<TExternalPsk>): ITls13ClientConfigFacet;
    /// <summary>Whether configured external PSKs are required (default True): a non-PSK
    /// ServerHello is fatal rather than a fall-through to certificate authentication. Set
    /// False to let the client accept a certificate handshake as well - which then needs a
    /// trust source, so a PSK-only client (no trust) with False is refused at Build. No effect
    /// without configured external PSKs.</summary>
    function WithExternalPskRequired(AEnabled: Boolean): ITls13ClientConfigFacet;
    /// <summary>The backends the client can decompress the server's Certificate with (RFC 8879),
    /// advertised in its ClientHello compress_certificate; empty omits the extension. Defaults to
    /// zlib. A nil entry, the reserved codepoint 0, a codepoint listed twice, or more than 127
    /// entries is refused.</summary>
    function WithCertificateDecompressors(
      const ADecompressors: TArray<ICertificateDecompressor>): ITls13ClientConfigFacet;
    /// <summary>The backends the client compresses its own Certificate with when a server asks
    /// for a client certificate and advertises a matching algorithm (RFC 8879); empty sends it
    /// uncompressed. Defaults to zlib. Refuses a nil entry, codepoint 0 or a repeated codepoint,
    /// and Build refuses a non-empty list on a client with no WithCredential.</summary>
    function WithCertificateCompressors(
      const ACompressors: TArray<ICertificateCompressor>): ITls13ClientConfigFacet;
    /// <summary>An optional cache memoizing the client's compressed Certificate across
    /// connections, so a stable certificate is deflated once (an in-memory implementation ships
    /// as TInMemoryCertificateCompressionCache). nil (the default) compresses each time. Build
    /// refuses a cache on a client with no WithCredential or beside an empty compressor list.</summary>
    function WithCertificateCompressionCache(
      const ACache: ICertificateCompressionCache): ITls13ClientConfigFacet;
    /// <summary>Whether the client offers 0-RTT early data when a cached ticket authorizes
    /// it (TLS 1.3, RFC 9846 4.3.10). Off by default. Build refuses it together with Reverify and
    /// an async certificate verdict (the verdict resolves after the server flight).</summary>
    function WithEarlyData(AEnabled: Boolean): ITls13ClientConfigFacet;
    /// <summary>
    /// How the client offers Encrypted Client Hello (RFC 9849), as one exclusive choice from
    /// TEchClientModes: Enable offers an application-supplied ECHConfigList (typically from the
    /// DNS HTTPS/SVCB ech parameter), Retry does so for a reconnection driven by a reject's
    /// retry_configs (a second reject is not retried), Grease only sends a GREASE ECH (sec. 6.2).
    /// Enable and Retry need a usable config in the list and a TLS 1.3-only client (sec. 6.1);
    /// Build refuses either otherwise, so falling back to GREASE is the caller's explicit choice;
    /// it also refuses either under TServerVerification.DangerousSkip, since a reject must be
    /// authenticated against public_name (sec. 6.1.7). On an ECH reject the handshake raises
    /// EEchRejectedTlsLibException carrying the server's retry_configs only after that
    /// authentication; the library never falls back to plaintext. A TServerVerification.Custom
    /// verifier receives the public_name as the host on a reject and owns that check. A later
    /// call replaces an earlier one. ECH is off unless called.
    /// </summary>
    function WithEch(const AMode: IEchClientMode): ITls13ClientConfigFacet;
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
    /// <summary>The pre-shared key (RFC 4279 / RFC 5489) the client presents when the server
    /// selects an ECDHE_PSK suite; the PSK suites are offered only once this is set. The identity
    /// and the secret are each 1 to 2^16-1 bytes (a text identity should be UTF-8, RFC 4279 5.1).
    /// The config shares the secret buffer rather than copying it, so keep it alive for the life of
    /// the config. Use a secret distinct from any TLS 1.3 external PSK.</summary>
    function WithPreSharedKey(const APsk: TTls12Psk): ITls12ClientConfigFacet;
    /// <summary>Whether a client holding a TLS 1.2 PSK offers only the PSK suites for TLS 1.2, so
    /// no TLS 1.2 handshake can fall back to certificate authentication. Default True; False also
    /// offers the certificate suites, which then needs a trust source. No effect without a PSK.</summary>
    function WithPreSharedKeyRequired(AEnabled: Boolean): ITls12ClientConfigFacet;
    function Tls13: ITls13ClientConfigFacet;
    function Build: ITlsClientConfig;
  end;

  /// <summary>
  /// Assembles a server endpoint. Common setters and the server-only knobs live here;
  /// version-specific settings live behind Tls13/Tls12. A server build requires a
  /// certificate credential.
  /// </summary>
  ITlsServerConfigBuilder = interface(IInterface)
    ['{CB741560-7E47-4C87-ABBB-A90E087ED9B0}']
    /// <summary>The cipher-suite registry offered. A configured TLS 1.2 PSK adds its ECDHE_PSK
    /// suites to it.</summary>
    function WithCipherSuites(const ARegistry: ICipherSuiteRegistry): ITlsServerConfigBuilder;
    /// <summary>Narrows the configured cipher suites to ASuites, in that order, per protocol: a
    /// protocol ASuites names keeps exactly the listed suites; one it does not name is unchanged.
    /// Never widens - a code outside the configured set is refused at Build, and so is a list
    /// naming only suites of a protocol version that is not offered (a TLS 1.2 list beside a TLS
    /// 1.3-only config); a mixed list is accepted and its off-version part is ignored. The
    /// configured set includes the ECDHE_PSK suites a configured TLS 1.2 PSK adds.</summary>
    function WithCipherSuiteList(const ASuites: TArray<UInt16>): ITlsServerConfigBuilder;
    /// <summary>The signature schemes this server advertises in a CertificateRequest and accepts
    /// from the client. Its own signatures follow the credential key (ISigningKey.WithPreferredSchemes);
    /// without WithPeerAuth a registry other than the preset's is refused at Build.</summary>
    function WithSignatureSchemes(const ARegistry: ISignatureSchemeRegistry): ITlsServerConfigBuilder;
    /// <summary>The named groups this server accepts for key exchange.</summary>
    function WithNamedGroups(const ARegistry: INamedGroupRegistry): ITlsServerConfigBuilder;
    /// <summary>The protocol versions this server accepts.</summary>
    function WithSupportedVersions(const AVersions: TArray<UInt16>): ITlsServerConfigBuilder;
    /// <summary>The groups to prefer, in order, among the registered ones; a code the group
    /// registry lacks is skipped. Build refuses an empty list, a list with no registered group,
    /// and, when TLS 1.2 is offered, a list with no registered classical ECDHE group. Each group
    /// is listed once; a repeat is rejected here.</summary>
    function WithPreferredGroups(const AGroups: TArray<UInt16>): ITlsServerConfigBuilder;
    /// <summary>The application protocols the server selects from, in preference order; an empty
    /// list offers no ALPN. Each name is 1..255 opaque octets and is listed once; anything else is
    /// rejected here (RFC 7301 3.1). TAlpnProtocols.FromText turns ASCII names such as "h2" into
    /// octets.</summary>
    function WithAlpnProtocols(const AProtocols: TArray<TBytes>): ITlsServerConfigBuilder;
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
    /// certificate_authorities (RFC 9846 4.3.4 / RFC 5246 7.4.4); empty names none. Refuses an empty
    /// name, or names totalling over 65535 bytes with their 2-byte length prefixes, at the call;
    /// Build refuses a list too long for the TLS 1.3 CertificateRequest beside its other
    /// extensions.</summary>
    function WithClientCertificateAuthorities(const AAuthorities: TArray<TBytes>): ITlsServerConfigBuilder;
    /// <summary>The certificate-chain resource caps for a requested client certificate; they bound
    /// that chain only; without WithPeerAuth any value other than the preset's is refused at
    /// Build. A Custom verifier is bound only by MaxTotalChainLength.</summary>
    function WithCertificateChainLimits(
      const ALimits: TCertificateChainLimits): ITlsServerConfigBuilder;
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
    /// strictly. A server that requests one also needs a client verification policy
    /// (WithClientVerification). The client-certificate trust settings (the policy, pins,
    /// client-CA list, verify callback, async or live verdict, chain limits changed from the
    /// preset, certificate decompressors) take effect only with a mode other than None; Build
    /// refuses them otherwise, and refuses a mode other than None on a server holding no
    /// certificate credential (it never sends a CertificateRequest). Defaults to None.</summary>
    function WithPeerAuth(AMode: TClientAuthMode): ITlsServerConfigBuilder;
    /// <summary>SPKI-SHA256 pins, one of which some certificate on the validated client path must
    /// match; augments PKIX, never a bypass, and applies only when client authentication is
    /// requested. Each pin must be 32 bytes. Empty disables it.</summary>
    function WithCertificatePinning(const APins: TArray<TBytes>): ITlsServerConfigBuilder;
    /// <summary>How the server verifies a client's certificate: one policy, made by
    /// TClientVerification (WebPki over client-CA anchors, a source over them, a whole verifier, or
    /// DangerousSkip). It takes effect with WithPeerAuth; a later call replaces an earlier one.
    /// DangerousSkip accepts a requested client chain without PKIX or revocation checks
    /// (configured pins still apply to the leaf); tests only.</summary>
    function WithClientVerification(const AVerification: IClientVerification): ITlsServerConfigBuilder;
    /// <summary>DANGEROUS: hands every secret of every connection built from this config to
    /// AKeyLog in the SSLKEYLOGFILE format (RFC 9850), so a packet capture can be decrypted.
    /// For debugging only - never production. nil (the default) clears it.</summary>
    function WithDangerousKeyLog(const AKeyLog: IKeyLog): ITlsServerConfigBuilder;
    /// <summary>An augment-only client-certificate hook that runs last, after the built-in pipeline
    /// and pinning, and can only additionally reject (never loosen it).</summary>
    function WithCertificateVerifyCallback(
      const ACallback: TTlsCertificateVerifyCallback): ITlsServerConfigBuilder;
    /// <summary>Enables a host-decision client-certificate verdict (the deferred-verdict seam) for a
    /// server that requests client authentication: after the built-in pipeline accepts the client
    /// chain the handshake parks for an out-of-band decision, resumed with the engine's
    /// SetCertificateVerdict. Augment-only and fail-closed; it does not change how an indeterminate
    /// revocation outcome is decided (the posture still decides that inline). Calling this arms the
    /// park unconditionally; it is off unless called. ADeadlineMs is the resolver's fetch budget
    /// (the engine and stream drivers enforce no timer). Raises if WithLiveRevocationVerdict was
    /// called: the two share one verdict slot.</summary>
    function WithAsyncCertificateVerdict(
      ADeadlineMs: Cardinal): ITlsServerConfigBuilder;
    /// <summary>Defers an indeterminate client-certificate revocation outcome to a live OCSP/CRL
    /// resolver at the park (rather than deciding it inline by the posture). A client certificate is
    /// never stapled, so this is the only way a Hard posture is reachable for client authentication.
    /// Parks after the pipeline accepts the chain, augment-only and fail-closed. ADeadlineMs is the
    /// resolver's fetch budget. Raises if WithAsyncCertificateVerdict was called: the two share one
    /// verdict slot.</summary>
    function WithLiveRevocationVerdict(ADeadlineMs: Cardinal): ITlsServerConfigBuilder;
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
    /// sessions, so a configuration never resumes a session another established under different
    /// client-authentication trust. Empty (the default) does not partition: configurations sharing
    /// a key/store resume each other. Set the same scope on configurations that trust identically,
    /// different scopes to keep them apart. The client method of the same name has the opposite
    /// empty default: it isolates rather than shares.</summary>
    function WithResumptionScope(const AScope: TBytes): ITlsServerConfigBuilder;
    /// <summary>Requests a default STEK, minted at build time from this configuration's own
    /// provider RNG and clock, so stateless tickets honor an injected crypto provider rather than
    /// any concrete default; with a session store configured it also issues stateless tickets
    /// alongside the store. Raises if WithSessionTicketKeys was called, which it could never
    /// take effect beside. The keys are
    /// scoped to the built config's lifetime; share a STEK across servers/a fleet through a
    /// TFleetTicketKeyManager and its InstallKey (e.g. from a KMS).</summary>
    function WithDefaultSessionTicketKeys: ITlsServerConfigBuilder;
    /// <summary>The clock the server reads for ticket issue time, 0-RTT anti-replay windows and
    /// certificate/OCSP freshness; defaults to the system clock, and nil is refused. Injectable
    /// primarily so tests can drive a deterministic time.</summary>
    function WithClock(const AClock: ITlsClock): ITlsServerConfigBuilder;
    /// <summary>The elapsed-time source the connection layer measures its handshake read cap on;
    /// defaults to the system source, and nil is refused. Injectable primarily so tests can drive
    /// deterministic elapsed time.</summary>
    function WithMonotonicClock(const AClock: ITlsMonotonicClock): ITlsServerConfigBuilder;
    /// <summary>The lifetime advertised for issued sessions and tickets, in seconds, at most seven
    /// days (a larger value is refused at the call). 0 tells the client to discard the ticket at
    /// once (RFC 9846 4.7.1), so Build refuses it while resumption is on. A ticket renewed on a
    /// resumption advertises at most what remains of seven days since the full handshake that
    /// authenticated the session, and no session resumes past that.</summary>
    function WithTicketLifetime(ASeconds: UInt32): ITlsServerConfigBuilder;
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
    ['{8DBA71D8-F01C-4F5B-941A-960DC5474713}']
    /// <summary>The out-of-band external pre-shared keys (RFC 9258) the server imports and
    /// matches an offered pre_shared_key against, in preference order. A matching PSK is
    /// preferred over the server's certificate, and an accepted PSK stands in for client
    /// authentication (no CertificateRequest is sent, RFC 9846 4.4.2). Empty leaves external PSK
    /// off.</summary>
    function WithExternalPreSharedKeys(
      const APsks: TArray<TExternalPsk>): ITls13ServerConfigFacet;
    /// <summary>How many NewSessionTickets to issue per TLS 1.3 handshake, 0..8 (0 issues none).
    /// TLS 1.2 tickets are governed by WithResumption alone. A TLS 1.3 server issuing none resumes
    /// nothing unless a store, keys or scope shared with another node is set, and Build still
    /// accepts that; use WithResumption(False) to turn resumption off explicitly. With 0 and
    /// resumption on, Build refuses
    /// an early-data limit unless a session store or ticket keys can resume another server's
    /// tickets, and on a server not offering TLS 1.2 also default ticket keys or a lifetime: use
    /// WithResumption(False) to turn resumption off.</summary>
    function WithTicketCount(ACount: Int32): ITls13ServerConfigFacet;
    /// <summary>The backends the server can decompress a client Certificate with (RFC 8879),
    /// advertised in its CertificateRequest when client authentication is requested; empty
    /// advertises none. Defaults to zlib. A nil entry, the reserved codepoint 0, a codepoint
    /// listed twice, or more than 127 entries is refused, and Build refuses a non-empty list on a
    /// server that requests no client certificate.</summary>
    function WithCertificateDecompressors(
      const ADecompressors: TArray<ICertificateDecompressor>): ITls13ServerConfigFacet;
    /// <summary>The backends the server compresses its own Certificate with when the client
    /// advertised a matching algorithm (RFC 8879), in the server's preference order; empty sends
    /// it uncompressed. Defaults to zlib. Refuses a nil entry, codepoint 0 or a repeated
    /// codepoint, and Build refuses a non-empty list on a server holding no certificate
    /// credential.</summary>
    function WithCertificateCompressors(
      const ACompressors: TArray<ICertificateCompressor>): ITls13ServerConfigFacet;
    /// <summary>A cross-connection cache memoizing the server's compressed Certificate
    /// (RFC 8879); providing one deflates a stable certificate once and reuses it across the
    /// connections built from this config (a bounded, thread-safe
    /// TInMemoryCertificateCompressionCache ships for this). nil (the default) compresses on
    /// every handshake. Build refuses a cache on a server holding no certificate credential or
    /// beside an empty compressor list.</summary>
    function WithCertificateCompressionCache(
      const ACache: ICertificateCompressionCache): ITls13ServerConfigFacet;
    /// <summary>The 0-RTT early-data byte budget the server authorizes (TLS 1.3, RFC 9846
    /// 4.3.10); 0 disables early data. A default anti-replay register is provided when none is
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
    /// <summary>True rejects every client that does not offer extended_master_secret (RFC 7627), which
    /// makes WithNonEmsResumption moot; combining it with Abort or Resume is refused at Build.</summary>
    function WithExtendedMasterSecret(ARequire: Boolean): ITls12ServerConfigFacet;
    /// <summary>How the server treats a ClientHello that resumes a session established without
    /// extended_master_secret when the hello does not offer it either (RFC 7627 5.3): Decline, the
    /// default, runs a full handshake; Abort ends the handshake with handshake_failure; Resume
    /// performs the legacy abbreviated handshake. Decline and Abort also stop issuing resumable
    /// sessions from a non-EMS full handshake. For a server that accepts no non-EMS client at all,
    /// use WithExtendedMasterSecret(True), which makes this moot; combining that with Abort or
    /// Resume is refused at Build.</summary>
    function WithNonEmsResumption(AMode: TNonEmsResumption): ITls12ServerConfigFacet;
    /// <summary>The pre-shared keys (RFC 4279 / RFC 5489) the server accepts for the ECDHE_PSK
    /// suites, looked up by the identity the client presents. A configured PSK is preferred over
    /// the certificate suites. An identity the server does not know ends the handshake at the
    /// client's encrypted Finished, exactly as a wrong secret does. A known identity stands in for
    /// client authentication when it is required. A PSK session resumes while its identity is still
    /// configured with the same secret. Each identity and secret is 1 to 2^16-1 bytes, identities
    /// unique; the config shares the secret buffers rather than copying them.</summary>
    function WithPreSharedKeys(const APsks: TArray<TTls12Psk>): ITls12ServerConfigFacet;
    /// <summary>The psk_identity_hint the server sends in its ServerKeyExchange (RFC 4279 5.2), at
    /// most 65535 bytes; empty (the default) sends none. The hint travels in the clear and a client
    /// ignores it, so it names a key only for a peer whose profile reads it. Needs a PSK.</summary>
    function WithPreSharedKeyIdentityHint(const AHint: TBytes): ITls12ServerConfigFacet;
    function Tls13: ITls13ServerConfigFacet;
    function Build: ITlsServerConfig;
  end;

implementation

end.
