{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpTlsConfigBuilder;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpArrayUtilities,
  TlpTlsVersion,
  TlpHandshakeMessages,
  TlpTlsLibExceptions,
  TlpICryptoProvider,
  TlpIPkixProvider,
  TlpCryptoDomainTypes,
  TlpPkixDomainTypes,
  TlpINamedGroup,
  TlpINegotiation,
  TlpNegotiationTypes,
  TlpCipherSuiteCatalog,
  TlpCipherSuiteRegistry,
  TlpNegotiationPolicy,
  TlpSignatureSchemeRegistry,
  TlpICertificateTrust,
  TlpITrustAnchorStore,
  TlpTrustAnchorStore,
  TlpTrustTypes,
  TlpICertificateVerifierSource,
  TlpCertificateVerifier,
  TlpCertificateVerifierSource,
  TlpICertificateCompression,
  TlpICertificateCompressionCache,
  TlpCertificateCompression,
  TlpZlibCertificateCompression,
  TlpCertificateLimits,
  TlpTrustPolicy,
  TlpCertificateStrengthPolicy,
  TlpTlsCredential,
  TlpITlsCredentialResolver,
  TlpCredentialResolvers,
  TlpEndpointIdentity,
  TlpServerName,
  TlpISession,
  TlpISecretBuffer,
  TlpIClock,
  TlpClock,
  TlpIKeyLog,
  TlpSession,
  TlpExternalPskImporter,
  TlpSessionTicketKeys,
  TlpAntiReplay,
  TlpIEch,
  TlpEchConfig,
  TlpEchClient,
  TlpEchServer,
  TlpITlsConfig,
  TlpITlsConfigBuilder;

resourcestring
  SNilCryptoProvider = 'a crypto provider is required (pass a provider, not nil)';

type
  /// <summary>The endpoint-neutral settings a preset decides before the endpoint is chosen. A nil
  /// registry or an empty list leaves that setting unset (Build refuses a builder with no offered
  /// version); the three scalars are always applied.</summary>
  TTlsConfigProfile = record
    CipherSuites: ICipherSuiteRegistry;
    SignatureSchemes: ISignatureSchemeRegistry;
    NamedGroups: INamedGroupRegistry;
    SupportedVersions: TArray<UInt16>;
    PreferredGroups: TArray<UInt16>;
    CertificateChainLimits: TCertificateChainLimits;
    RequestOcspStapling: Boolean;
    Resumption: Boolean;
    /// <summary>The builder's own values for these settings: no registries or lists, default chain
    /// limits, no staple request, resumption on.</summary>
    class function Default: TTlsConfigProfile; static;
  end;

  /// <summary>
  /// Accumulates the settings for one connection and freezes them into an immutable
  /// config. The endpoint is chosen up front through Client/Server; version-specific
  /// settings are reached through the Tls13/Tls12 facets. Those endpoint views and
  /// facets are thin forwarders over this one object, whose mutators are the single
  /// source of truth the presets also seed through. Single use: once built it rejects
  /// further mutation. A client build requires a trust source and a server a credential,
  /// and a version facet touched for a version that is not offered is refused at build.
  /// </summary>
  TTlsConfigBuilder = class(TInterfacedObject, ITlsConfigBuilder)
  strict private
  var
    FFrozen: Boolean;
    FCrypto: ICryptoProvider;
    FPkix: IPkixProvider;
    FCipherSuites: ICipherSuiteRegistry;
    FCipherSuiteList: TArray<UInt16>;
    FSignatureSchemes: ISignatureSchemeRegistry;
    FNamedGroups: INamedGroupRegistry;
    FSupportedVersions: TArray<UInt16>;
    FPreferredGroups: TArray<UInt16>;
    FAlpnProtocols: TArray<TBytes>;
    FRecordSizeLimit: Int32;
    // anchor contributions accumulate (union); a whole-verifier is exclusive of them.
    // Only the endpoint-appropriate slot is ever set (the facet is chosen up front).
    FAnchorStores: TArray<ITrustAnchorStore>;
    // the union of FAnchorStores, built when first needed and dropped when a store is added
    FComposedTrust: ITrustAnchorStore;
    FServerCertVerifier: IServerCertificateVerifier;
    FServerVerifierSource: IServerCertificateVerifierSource;
    FClientCertVerifier: IClientCertificateVerifier;
    FClientVerifierSource: IClientCertificateVerifierSource;
    // the role's verification policy; the trust fields above are derived from it at Build
    FServerVerification: IServerVerification;
    FClientVerification: IClientVerification;
    FCheckServerName: Boolean;
    FServerNameIndication: TServerNameIndication;
    FRequestOcspStapling: Boolean;
    FChainLimits: TCertificateChainLimits;
    FStrengthPolicy: TCertificateStrengthPolicy;
    FCredential: TTlsCredential;
    FHasCredential: Boolean;
    FClientViewTaken: Boolean;
    FServerViewTaken: Boolean;
    FSniCredentialEntries: TArray<TSniCredentialEntry>;
    FCredentialResolver: ITlsServerCredentialResolver;
    FClientAuth: TClientAuthMode;
    FRevocationPosture: TRevocationPosture;
    FCertificatePins: TArray<TBytes>;
    FIntermediateCertificates: TArray<TBytes>;
    FDangerousTrust: TDangerousTrust;
    FAsyncVerdict: TAsyncCertificateVerdict;
    FCertificateCompressors: TArray<ICertificateCompressor>;
    FCertificateDecompressors: TArray<ICertificateDecompressor>;
    FCertificateCompressionCache: ICertificateCompressionCache;
    FRequireExtendedMasterSecret: Boolean;
    FNonEmsResumption: TNonEmsResumption;
    FServerNameAck: Boolean;
    FCipherPreference: TServerCipherPreference;
    FAlpnRejectAll: Boolean;
    FClientCertificateAuthorities: TArray<TBytes>;
    FGrease: Boolean;
    FResumption: Boolean;
    FExternalPsks: TArray<TExternalPsk>;
    FExternalPskRequired: Boolean;
    FTls12Psks: TArray<TTls12Psk>;
    FTls12PskRequired: Boolean;
    FTls12PskIdentityHint: TBytes;
    FSessionCache: ISessionCache;
    FSessionScope: TBytes;
    FResumeVerification: TResumeVerification;
    FClock: ITlsClock;
    FMonotonicClock: ITlsMonotonicClock;
    FKeyLog: IKeyLog;
    FClientEarlyData: Boolean;
    FSessionStore: ISessionStore;
    FSessionTicketKeys: ISessionTicketKeyManager;
    FResumptionScope: TBytes;
    FWantDefaultSessionTicketKeys: Boolean;
    FAntiReplay: IAntiReplayStrategy;
    FTicketLifetimeSeconds: UInt32;
    FTicketCount: Int32;
    FMaxEarlyData: UInt32;
    FEchMode: IEchClientMode;
    FEchServerPolicy: IEchServerPolicy;
    // a certificate-codec list has no non-default value to compare, so setting one counts
    FCompressorsSet: Boolean;
    FDecompressorsSet: Boolean;
    // the starting point a setting is judged against: a preset's values are never refused as inert
    FBaseline: TTlsConfigProfile;
    procedure GuardMutable;
    /// <summary>Whether any TLS 1.3-only setting differs from its default (defaults are seeded
    /// directly, not through a facet), so restating a default on a config that does not offer the
    /// version is not refused.</summary>
    function Tls13FacetConfigured: Boolean;
    function Tls12FacetConfigured: Boolean;
    /// <summary>Refuses a client whose external-PSK offer, beside its ALPN list, a cached ticket and
    /// ECH at their ceilings, would overflow the ClientHello extensions block.</summary>
    procedure ValidateExternalPskOfferFits;
    /// <summary>Refuses a version facet that was configured for a version not offered.</summary>
    procedure ValidateVersionScoping;
    /// <summary>Refuses a setting that only a certificate handshake consults on a client that
    /// authenticates by PSK alone, where none can ever run.</summary>
    procedure ValidatePskOnlyClientSettings;
    /// <summary>Refuses a server resumption setting that a ticket count of 0 makes dead: early
    /// data when no store or keys can resume another server's tickets, and the default keys and the
    /// lifetime on a server not offering TLS 1.2.</summary>
    procedure ValidateTicketCountZeroSettings;
    /// <summary>Refuses a client-CA list that, with the signature_algorithms and compress_certificate
    /// extensions this config sends, overflows a TLS 1.3 CertificateRequest extensions block.</summary>
    procedure ValidateClientCertificateAuthoritiesFit;
    /// <summary>Composes the accumulated anchor sources into one store: nil for none (a PSK-only
    /// or skip-verify client), the single store for one, else a union. nil when a whole-verifier
    /// is used instead.</summary>
    function ComposeTrustStore: ITrustAnchorStore;
    /// <summary>True when at least one accumulated anchor store yields a root certificate. A store
    /// object is not a trust source; only its roots are (an empty store can trust nothing).</summary>
    function HasAnchorRoots: Boolean;
    /// <summary>True when the profile baseline carries a signature-scheme registry and the
    /// configured one lists different scheme codes, compared by content and order.</summary>
    function SignatureSchemesDifferFromBaseline: Boolean;
    /// <summary>Enforces the trust-composition rule at build: a whole-verifier is exclusive
    /// of any anchor source and of a second verifier (typed error).</summary>
    /// <summary>Derives the anchor, intermediate, strength, posture and skip state from a
    /// verification policy, replacing whatever an earlier Build derived. The kind-specific verifier
    /// and source slots are set by the caller.</summary>
    procedure ApplyTrustData(const AVerification: ITrustVerification);
    /// <summary>Refuses an anchor store holding a certificate that does not parse: one such root
    /// would otherwise fail every verification against the store, far from its cause.</summary>
    procedure ValidateAnchorRoots;
    procedure ValidateRequiredCollaborators;
    /// <summary>The cipher suites a built config carries: the configured set narrowed to the list
    /// WithCipherSuiteList set - per protocol the list names, exactly the listed suites in list
    /// order; a protocol it does not name keeps its configured suites. Never widens: a code outside
    /// the configured set is refused. Leaves the builder unchanged, so a Build that fails later can
    /// be corrected and retried.</summary>
    function EffectiveCipherSuites: ICipherSuiteRegistry;
    /// <summary>Refuses an offered protocol version for which ASuites holds no suite, which would
    /// otherwise build and fail every handshake.</summary>
    procedure ValidateOfferedVersionsHaveSuites(const ASuites: ICipherSuiteRegistry);
    /// <summary>Composes the server credential resolver at build: a custom resolver (exclusive
    /// of the built-in map/credential), else the SNI map plus the single credential as the
    /// default fallback, else nil for a PSK-only server.</summary>
    function ComposeCredentialResolver: ITlsServerCredentialResolver;
    /// <summary>Composes the server-certificate verifier source at build: a custom source
    /// (exclusive of the built-in), else a wrapped whole-verifier instance, else the built-in
    /// PKIX source. The engine's single path builds the connection verifier from it.</summary>
    function ComposeServerVerifierSource: IServerCertificateVerifierSource;
    /// <summary>Composes the client-certificate verifier source at build (mTLS): a custom source
    /// (the OS delegate, which consumes the configured client-CA anchors), else a wrapped
    /// whole-verifier instance, else the built-in PKIX source.</summary>
    function ComposeClientVerifierSource: IClientCertificateVerifierSource;
    /// <summary>Fails the build (typed error) when an SNI entry's certificate does not cover
    /// its host, so a swapped cert/host mapping is caught up front, not per handshake.</summary>
    procedure ValidateSniEntryCoversHost(const AHost: string;
      const ACredential: TTlsCredential);
    /// <summary>Fails the build (typed error) when a credential's private key does not own its
    /// end-entity certificate, or that leaf cannot sign a handshake, so a wrong/mis-ordered
    /// leaf is caught up front rather than as a rejected CertificateVerify mid-handshake.</summary>
    procedure ValidateCredentialConsistency(const ACredential: TTlsCredential);
    constructor Create(const ACryptoProvider: ICryptoProvider;
      const APkixProvider: IPkixProvider; const AProfile: TTlsConfigProfile);
  private
    /// <summary>A credential sharing no mutable byte array (chain, staple) with ACredential, so a
    /// caller reusing its buffers after Build cannot change what a built config sends or validated.
    /// The signing key handle is shared by reference.</summary>
    class function CloneCredential(const ACredential: TTlsCredential): TTlsCredential; static;
    /// <summary>The PSKs with their identity and context copied (the secret is an immutable
    /// buffer, shared by reference).</summary>
    class function CloneExternalPsks(
      const APsks: TArray<TExternalPsk>): TArray<TExternalPsk>; static;
    /// <summary>The TLS 1.2 PSKs with their identity copied (the secret is an immutable buffer,
    /// shared by reference).</summary>
    class function CloneTls12Psks(
      const APsks: TArray<TTls12Psk>): TArray<TTls12Psk>; static;
    /// <summary>Raises unless every PSK has a 1 to 2^16-1 byte identity and secret and no two
    /// share an identity.</summary>
    class procedure ValidateTls12Psks(const APsks: TArray<TTls12Psk>); static;
    /// <summary>Raises unless every external PSK has a 1 to 2^16-1 byte identity, a non-empty
    /// secret and an imported identity that fits the wire, and no two share an identity and
    /// context.</summary>
    class procedure ValidateExternalPsks(const APsks: TArray<TExternalPsk>); static;
    /// <summary>Raises unless AIdentity is 1 to 2^16-1 bytes and ASecret is non-nil and
    /// non-empty.</summary>
    class procedure ValidatePskEntry(const AIdentity: TBytes;
      const ASecret: ISecretBuffer); static;
    /// <summary>ABase with the TLS 1.2 PSK suites the provider can run placed ahead of its TLS
    /// 1.2 certificate suites, when a TLS 1.2 PSK is configured; ABase itself otherwise.</summary>
    function WithTls12PskSuites(const ABase: ICipherSuiteRegistry): ICipherSuiteRegistry;
    // the single-source-of-truth mutators; reached only by the endpoint views and facets
    function WithCipherSuites(const ARegistry: ICipherSuiteRegistry): TTlsConfigBuilder;
    function WithCipherSuiteList(const ASuites: TArray<UInt16>): TTlsConfigBuilder;
    function WithSignatureSchemes(const ARegistry: ISignatureSchemeRegistry): TTlsConfigBuilder;
    function WithNamedGroups(const ARegistry: INamedGroupRegistry): TTlsConfigBuilder;
    function WithSupportedVersions(const AVersions: TArray<UInt16>): TTlsConfigBuilder;
    function WithPreferredGroups(const AGroups: TArray<UInt16>): TTlsConfigBuilder;
    function WithAlpnProtocols(const AProtocols: TArray<TBytes>): TTlsConfigBuilder;
    function WithRecordSizeLimit(ALimit: Int32): TTlsConfigBuilder;
    function WithCertificateChainLimits(
      const ALimits: TCertificateChainLimits): TTlsConfigBuilder;
    function WithCredential(const ACredential: TTlsCredential): TTlsConfigBuilder;
    function WithSniCredential(const AHost: string;
      const ACredential: TTlsCredential): TTlsConfigBuilder;
    function WithCredentialResolver(
      const AResolver: ITlsServerCredentialResolver): TTlsConfigBuilder;
    function WithCertificateCompressors(
      const ACompressors: TArray<ICertificateCompressor>): TTlsConfigBuilder;
    function WithCertificateDecompressors(
      const ADecompressors: TArray<ICertificateDecompressor>): TTlsConfigBuilder;
    function WithEch(const AMode: IEchClientMode): TTlsConfigBuilder;
    function WithCertificateCompressionCache(
      const ACache: ICertificateCompressionCache): TTlsConfigBuilder;
    function WithExtendedMasterSecret(ARequire: Boolean): TTlsConfigBuilder;
    function WithNonEmsResumption(AMode: TNonEmsResumption): TTlsConfigBuilder;
    function WithServerNameAcknowledgement(ASend: Boolean): TTlsConfigBuilder;
    function WithCipherSuitePreference(APreference: TServerCipherPreference): TTlsConfigBuilder;
    function WithAlpnRejection(AReject: Boolean): TTlsConfigBuilder;
    function WithClientCertificateAuthorities(const AAuthorities: TArray<TBytes>): TTlsConfigBuilder;
    function WithGrease(AEnable: Boolean): TTlsConfigBuilder;
    function WithDangerousDisableServerNameCheck: TTlsConfigBuilder;
    function WithServerNameIndication(AMode: TServerNameIndication): TTlsConfigBuilder;
    function WithOcspStaplingRequest(AEnabled: Boolean): TTlsConfigBuilder;
    function WithPeerAuth(AMode: TClientAuthMode): TTlsConfigBuilder;
    function WithCertificatePinning(const APins: TArray<TBytes>): TTlsConfigBuilder;
    function WithServerVerification(const AVerification: IServerVerification): TTlsConfigBuilder;
    function WithClientVerification(const AVerification: IClientVerification): TTlsConfigBuilder;
    function WithCertificateVerifyCallback(
      const ACallback: TTlsCertificateVerifyCallback): TTlsConfigBuilder;
    function WithAsyncCertificateVerdict(
      ADeadlineMs: Cardinal): TTlsConfigBuilder;
    function WithLiveRevocationVerdict(ADeadlineMs: Cardinal): TTlsConfigBuilder;
    function WithResumption(AEnabled: Boolean): TTlsConfigBuilder;
    function WithExternalPreSharedKeys(
      const APsks: TArray<TExternalPsk>): TTlsConfigBuilder;
    function WithExternalPskRequired(AEnabled: Boolean): TTlsConfigBuilder;
    function WithTls12PreSharedKeys(const APsks: TArray<TTls12Psk>): TTlsConfigBuilder;
    function WithTls12PreSharedKeyRequired(AEnabled: Boolean): TTlsConfigBuilder;
    function WithTls12PskIdentityHint(const AHint: TBytes): TTlsConfigBuilder;
    function WithSessionCache(const ACache: ISessionCache): TTlsConfigBuilder;
    function WithSessionScope(const AScope: TBytes): TTlsConfigBuilder;
    function WithResumeVerification(AMode: TResumeVerification): TTlsConfigBuilder;
    function WithClock(const AClock: ITlsClock): TTlsConfigBuilder;
    function WithMonotonicClock(const AClock: ITlsMonotonicClock): TTlsConfigBuilder;
    function WithDangerousKeyLog(const AKeyLog: IKeyLog): TTlsConfigBuilder;
    function WithSessionStore(const AStore: ISessionStore): TTlsConfigBuilder;
    function WithSessionTicketKeys(const AKeys: ISessionTicketKeyManager): TTlsConfigBuilder;
    function WithResumptionScope(const AScope: TBytes): TTlsConfigBuilder;
    function WithDefaultSessionTicketKeys: TTlsConfigBuilder;
    function WithTicketLifetime(ASeconds: UInt32): TTlsConfigBuilder;
    function WithTicketCount(ACount: Int32): TTlsConfigBuilder;
    function WithClientEarlyData(AEnabled: Boolean): TTlsConfigBuilder;
    function WithServerEarlyData(AMaxBytes: UInt32): TTlsConfigBuilder;
    function WithAntiReplay(const AStrategy: IAntiReplayStrategy): TTlsConfigBuilder;
    function WithEchKeyStore(const AKeyStore: IEchServerKeyStore): TTlsConfigBuilder; overload;
    function WithEchKeyStore(const AKeyStore: IEchServerKeyStore;
      ATrialDecrypt: Boolean): TTlsConfigBuilder; overload;
    function WithEchBackend: TTlsConfigBuilder;

    // the version facet instances (returned by the endpoint views and cross-accessors)
    function Client13: ITls13ClientConfigFacet;
    function Client12: ITls12ClientConfigFacet;
    function Server13: ITls13ServerConfigFacet;
    function Server12: ITls12ServerConfigFacet;

    /// <summary>Freezes and returns the client config; raises without a trust source.</summary>
    function BuildClient: ITlsClientConfig;
    /// <summary>Freezes and returns the server config; raises without a credential, credential resolver or external PSK.</summary>
    function BuildServer: ITlsServerConfig;
  public
    /// <summary>A still-mutable endpoint chooser built from AProfile; the caller narrows to Client
    /// or Server. The presets build theirs from this.</summary>
    class function CreateFromProfile(const ACryptoProvider: ICryptoProvider;
      const APkixProvider: IPkixProvider;
      const AProfile: TTlsConfigProfile): ITlsConfigBuilder; static;

    // ITlsConfigBuilder
    function Client: ITlsClientConfigBuilder;
    function Server: ITlsServerConfigBuilder;
  end;

implementation

resourcestring
  SNilPkixProvider = 'a PKIX provider is required (pass a provider, not nil)';
  SNilClock = 'a clock is required (pass a clock, not nil)';
  SNilMonotonicClock = 'a monotonic clock is required (pass a clock, not nil)';
  SBuilderFrozen = 'the configuration has been built and can no longer be changed';
  SEchBackendWithKeyStore = 'a split-mode ECH backend holds no keys; WithEchBackend is mutually ' +
    'exclusive with WithEchKeyStore';
  SNilVerification = 'a verification policy must not be nil';
  SNilEchMode = 'an ECH mode must not be nil';
  SEchNeedsTls13Only = 'Encrypted Client Hello with a config list needs a TLS 1.3-only client ' +
    '(RFC 9849 sec. 6.1: the inner hello never offers TLS 1.2); pin WithSupportedVersions to ' +
    'TLS 1.3, or use TEchClientModes.Grease';
  SEchNeedsVerification = 'Encrypted Client Hello with a config list cannot be combined with ' +
    'TServerVerification.DangerousSkip: an ECH reject must be authenticated against the ' +
    'public_name (RFC 9849 sec. 6.1.7); verify the server, or use TEchClientModes.Grease';
  SCustomHardNeedsLiveVerdict = 'a Hard revocation posture over an injected verifier needs ' +
    'WithLiveRevocationVerdict: an injected verifier does not apply the posture';
  SReverifyHardNeedsLiveVerdict = 'WithResumeVerification(Reverify) under a Hard revocation ' +
    'posture needs WithLiveRevocationVerdict: a resume carries no staple, so the client could ' +
    'never resume; add the verdict or keep ReuseOriginal';
  SEarlyDataReverifyAsyncVerdict = 'WithEarlyData(True) cannot be combined with ' +
    'WithResumeVerification(Reverify) and an asynchronous certificate verdict: the verdict ' +
    'arrives after the server flight, so no early data could precede it; drop the early data ' +
    'or the async verdict';
  SPskOnlyClientSetting = '%s has no effect on a client that authenticates by PSK alone, which ' +
    'verifies no certificate: add a trust source or drop it';
  SClientCompressionNeedsCredential = 'certificate compressors and their cache apply only to a ' +
    'client certificate, but no credential is set: add WithCredential or drop them';
  SServerCompressionNeedsCertificate = 'certificate compressors and their cache apply only to a ' +
    'certificate the server sends, but it holds no certificate credential: add WithCredential or ' +
    'drop them';
  SServerDecompressorsNeedPeerAuth = 'certificate decompressors are advertised only in a ' +
    'CertificateRequest, but the server requests no client certificate: call WithPeerAuth or drop ' +
    'Tls13.WithCertificateDecompressors';
  SServerChainLimitsNeedPeerAuth = 'certificate-chain limits bound only a requested client ' +
    'certificate, but the server requests none: call WithPeerAuth or leave the limits as the ' +
    'preset set them';
  SServerSchemesNeedPeerAuth = 'a signature-scheme registry other than the profile''s has no ' +
    'effect unless the server requests a client certificate, but it requests none: call ' +
    'WithPeerAuth or leave the registry as the preset set it';
  SPskOnlyServerPeerAuth = 'a server holding no certificate credential never sends a ' +
    'CertificateRequest, so WithPeerAuth would have no effect: add a credential or drop it';
  SVerdictSlotConflict = 'WithAsyncCertificateVerdict and WithLiveRevocationVerdict set the same ' +
    'verdict slot: call only one';
  SDefaultKeysBesideExplicitKeys = 'WithDefaultSessionTicketKeys can never take effect beside ' +
    'WithSessionTicketKeys: call only one';
  SCipherSuiteListNotOffered = 'the cipher-suite list names only suites of a protocol version ' +
    'that is not offered, so it would change nothing: list a suite of an offered version or drop ' +
    'WithCipherSuiteList';
  SServerEarlyDataNeedsTickets = '0-RTT early data rides a resumption ticket, but ' +
    'Tls13.WithTicketCount(0) issues none and no session store or ticket keys are set to resume ' +
    'another server''s: raise the count, add them, or drop the early-data limit';
  SServerSettingNeedsTickets = 'default ticket keys or a ticket lifetime was supplied to a ' +
    'server that offers only TLS 1.3 and issues no tickets (Tls13.WithTicketCount(0)), so it ' +
    'would have no effect: use WithResumption(False), or leave it out';
  STicketLifetimeZero = 'a ticket lifetime of 0 tells the client to discard the ticket at once ' +
    '(RFC 9846 4.7.1), so no session could resume: pass a positive lifetime or turn resumption off';
  SNoTrustStore = 'a client configuration requires a trust source (no silent-insecure)';
  SEmptyTrustStore = 'a trust store was supplied but contains no root certificates; a store ' +
    'with no anchors is not a trust source (no silent-insecure)';
  SPskOnlyClientNeedsPskRequired = 'a client with external PSKs and no trust source cannot fall ' +
    'back to certificate authentication; keep Tls13.WithExternalPskRequired(True) or add a trust source';
  SPskOnlyClientNeedsTls13Only = 'a client with external PSKs and no trust source must offer TLS ' +
    '1.3 only (external PSKs are TLS 1.3-only), or also hold a TLS 1.2 PSK; use WithSupportedVersions([TLS 1.3])';
  SPskOnlyClientNeedsTls12Only = 'a client with only a TLS 1.2 PSK and no trust source must offer ' +
    'TLS 1.2 only, or also hold an external PSK for TLS 1.3; use WithSupportedVersions([TLS 1.2])';
  SPskOnlyClientNeedsTls12PskRequired = 'a client with a TLS 1.2 PSK and no trust source cannot fall ' +
    'back to certificate authentication; keep Tls12.WithPreSharedKeyRequired(True) or add a trust source';
  STls12PskNeedsTls12 = 'a TLS 1.2 PSK is unusable without TLS 1.2; add TLS 1.2 to the offered ' +
    'versions or remove the PSK';
  SPskIdentityLength = 'a PSK identity must be 1 to 65535 bytes';
  SPskSecretEmpty = 'a PSK secret must not be empty';
  STls12PskSecretLength = 'a TLS 1.2 PSK secret must be at most 65535 bytes (RFC 4279 2)';
  STls12PskDuplicateIdentity = 'two TLS 1.2 PSKs share an identity';
  SExternalPskDuplicateIdentity = 'two external PSKs share an identity and context';
  SExternalPskIdentityTooLong = 'an external PSK identity and context together make an imported ' +
    'identity beyond 65535 bytes (RFC 9258 5.1)';
  SExternalPskOfferTooLarge = 'the external PSKs, offered once per KDF hash beside the ALPN ' +
    'list, a cached ticket and ECH, exceed the ClientHello extensions budget of 65535 bytes ' +
    '(RFC 9846 4.2.2)';
  STls12PskClientHoldsOne = 'a client presents one TLS 1.2 PSK';
  STls12PskHintLength = 'a TLS 1.2 PSK identity hint must be at most 65535 bytes';
  STls12PskHintNeedsPsk = 'a TLS 1.2 PSK identity hint is sent only with a PSK; configure ' +
    'Tls12.WithPreSharedKeys or drop the hint';
  STls12PskNeedsSuite = 'a TLS 1.2 PSK is configured but the cipher suites hold no PSK suite ' +
    '(a cipher-suite list must name at least one TLS_ECDHE_PSK suite)';
  SBuilderOneEndpoint = 'a configuration builder configures one endpoint: use a separate builder ' +
    'for the client and for the server';
  SPskOnlyServerNeedsTls13Only = 'a server with external PSKs and no certificate must offer TLS ' +
    '1.3 only (external PSKs are TLS 1.3-only), or also hold a TLS 1.2 PSK; use WithSupportedVersions([TLS 1.3])';
  SPskOnlyServerNeedsTls12Only = 'a server with only TLS 1.2 PSKs and no certificate must offer ' +
    'TLS 1.2 only, or also hold an external PSK for TLS 1.3; use WithSupportedVersions([TLS 1.2])';
  SNoCredential = 'a server configuration requires a certificate credential or a pre-shared key';
  SCredentialChainEmpty = 'a credential needs at least its leaf certificate in the chain';
  SCredentialKeyMissing = 'a credential needs a private key to sign the handshake';
  SNilNegotiationRegistry = 'the cipher-suite, signature-scheme and named-group registries are required';
  SNoPreferredGroups = 'at least one preferred key-exchange group is required';
  SNoClientAuthTrustStore = 'client authentication requires a trust source for the client certificate chain';
  SClientVerifierSourceNeedsAnchors = 'a client-certificate verifier source consumes the ' +
    'configured client-CA anchors as its exclusive trust root and can trust nothing without them; ' +
    'give the TClientVerification.VerifierSource store at least one root certificate (a verifier ' +
    'that brings its own roots is installed with TClientVerification.Custom instead)';
  SMtlsSharedResumptionNeedsScope = 'client authentication with a supplied session store or ' +
    'ticket-key manager requires WithResumptionScope: a key or store may be shared across ' +
    'configurations, and a resumed handshake reuses the stored client identity unverified';
  SSniCertMissing = 'the SNI credential for host "%s" has no certificate chain';
  SSniCertMismatch = 'the certificate mapped to SNI host "%s" does not cover it: its ' +
    'SubjectAltName dNSName entries do not match the host';
  SSniResolverConflict = 'a custom WithCredentialResolver cannot be combined with ' +
    'WithCredential or WithSniCredential; supply one or the other';
  SSniDuplicateHost = 'the SNI host "%s" is mapped by more than one WithSniCredential entry';
  SSniWildcardMalformed = 'the SNI host "%s" is not a supported wildcard; only a single ' +
    'left-most label wildcard (*.example.com) is allowed';
  STls13NotOffered = 'TLS 1.3 settings were configured but TLS 1.3 is not in the offered versions';
  STls12NotOffered = 'TLS 1.2 settings were configured but TLS 1.2 is not in the offered versions';
  SNonEmsResumeWithRequiredEms = 'a non-EMS resumption mode other than Decline cannot apply when ' +
    'extended_master_secret is required, since a non-EMS client is rejected outright';
  SClientScopeNeedsCache = 'a resumption scope was supplied without a session cache to resume ' +
    'from; set WithSessionCache or drop the scope';
  SExternalPskRequiredNeedsPsk = 'external PSKs were marked optional but none is configured; ' +
    'set WithExternalPreSharedKeys or drop the toggle';
  STls12PskRequiredNeedsPsk = 'the TLS 1.2 PSK was marked optional but none is configured; ' +
    'set WithPreSharedKey or drop the toggle';
  SAntiReplayNeedsEarlyData = 'an anti-replay strategy is consulted only for 0-RTT, but no ' +
    'early-data budget is set; set WithEarlyData or drop the strategy';
  SNoSupportedVersions = 'at least one protocol version must be offered (TLS 1.3 and/or TLS 1.2)';
  SUnsupportedVersion = 'protocol version 0x%.4x is not negotiable; only TLS 1.3 (0x0304) and ' +
    'TLS 1.2 (0x0303) are supported';
  SDuplicateVersion = 'a protocol version may be offered only once';
  SAlpnProtocolEmpty = 'an ALPN protocol name must not be empty (RFC 7301 3.1)';
  SAlpnProtocolTooLong = 'an ALPN protocol name must not exceed 255 bytes (RFC 7301 3.1)';
  SAlpnListTooLong = 'the ALPN protocol list must not exceed 16384 bytes on the wire, so that ' +
    'a ClientHello''s extensions block (RFC 9846 4.2.2) can always carry it';
  SCertificateAuthorityEmpty = 'a client certificate authority name must not be empty ' +
    '(RFC 9846 4.3.4)';
  SCertificateAuthoritiesTooLong = 'the client certificate authority names must not exceed ' +
    '65535 bytes with their 2-byte length prefixes (RFC 5246 7.4.4, RFC 9846 4.3.4)';
  SCertificateAuthoritiesNeedRoom = 'the client certificate authority names take %d bytes with ' +
    'their length prefixes, but a TLS 1.3 CertificateRequest has room for %d beside its other ' +
    'extensions (RFC 9846 4.4.2): shorten the list or offer TLS 1.2 only';
  SCompressionCacheNeedsCompressor = 'a certificate compression cache needs at least one ' +
    'compressor, but the compressor list is empty: add a compressor or drop the cache';
  SNoRegisteredPreferredGroup = 'none of the preferred key-exchange groups is in the named-group ' +
    'registry, so no handshake could ever select a group';
  SCipherSuiteListEmpty = 'a cipher-suite list must name at least one suite';
  SCipherSuiteNotConfigured = 'cipher suite %s is not in the configured cipher-suite set';
  SNoSuiteForVersion = '%s is offered but the cipher-suite set holds no %s suite';
  SNoClassicalEcdheGroup = 'TLS 1.2 is offered but none of the preferred key-exchange groups is a ' +
    'registered classical ECDHE group, so no TLS 1.2 handshake could ever select a group';
  SDuplicatePreferredGroup = 'a preferred key-exchange group may be listed only once';
  SAlpnProtocolDuplicate = 'an ALPN protocol name is offered more than once';
  SRecordSizeLimitRange = 'the record_size_limit must be 0 (not offered) or 64..16384 (the library cap; RFC 8449 4)';
  SHardRevocationUnusable = 'a Hard revocation posture rejects a peer whose certificate has no ' +
    'stapled OCSP response, so it always-rejects unless the client obtains revocation status: ' +
    'call WithOcspStaplingRequest(True) to request a staple, or configure a live OCSP/CRL verdict ' +
    'resolver (WithLiveRevocationVerdict)';
  SServerTrustNeedsPeerAuth = 'client-certificate trust settings (trust anchors or store, pins, ' +
    'intermediates, client-CA list, verifier, verify callback, skip-verify, Hard revocation or an ' +
    'async or live certificate verdict) are set on a server that does not request client ' +
    'certificates, so they would be ignored and clients admitted unauthenticated; call ' +
    'WithPeerAuth, or remove them';
  SHardServerRevocationUnusable = 'a Hard revocation posture rejects a client whose certificate ' +
    'has no revocation status; a server cannot request a client OCSP staple, so Hard ' +
    'client-certificate revocation requires a live OCSP/CRL verdict resolver ' +
    '(WithLiveRevocationVerdict)';
  STicketLifetimeTooLong = 'the session-ticket lifetime must not exceed 604800 seconds ' +
    '(7 days), the maximum a server may advertise (RFC 9846 4.7.1)';
  SResumptionScopeTooLong = 'the resumption scope must not exceed 32 bytes';
  SExternalPskNeedsTls13 = 'external PSKs are TLS 1.3-only (RFC 9258); offering them without TLS ' +
    '1.3 leaves them unusable, so add TLS 1.3 to the offered versions or remove the external PSKs';
  SEarlyDataNeedsResumption = '0-RTT early data is sent only on a resumed handshake; enabling it ' +
    'requires resumption to be on and a session cache to hold the ticket it resumes from';
  SResumeVerifyNeedsCache = 'resumed-session certificate re-verification is inert unless the ' +
    'client can resume: turn resumption on and configure WithSessionCache, or leave the default ' +
    'reuse mode';
  SServerEarlyDataTooLarge = 'the 0-RTT early-data budget must be below 1 MiB (1048576 ' +
    'bytes): the engine stops draining the handshake once that much application data is buffered';
  SExplicitStekEarlyDataNeedsAntiReplay = '0-RTT early data with an explicit session-ticket ' +
    'key manager needs a session store or an anti-replay strategy: the default strike ' +
    'register is per configuration, so a ticket from a shared key could be replayed against ' +
    'another instance; set WithSessionStore or WithAntiReplay';
  SClientResumptionSettingNeedsResumption = 'a session cache or resumption scope was supplied but ' +
    'resumption is off, so it would have no effect: turn resumption on or leave it out';
  SServerResumptionSettingNeedsResumption = 'a session store, ticket keys, ticket lifetime or count, ' +
    'resumption scope, anti-replay strategy or non-EMS resumption mode was supplied but ' +
    'resumption is off, so it would have no effect: turn resumption on or leave it out';
  SAlpnRejectionWithProtocols = 'ALPN rejection refuses every client offer, so a configured ALPN ' +
    'protocol list could never be selected: drop one of them';
  SServerEarlyDataNeedsResumption = '0-RTT early data is offered only on a resumed session; a ' +
    'server early-data limit requires resumption to be enabled';
  STicketCountOutOfRange = 'the session-ticket count must be between 0 and 8 per handshake';
  SInvalidChainLimits = 'the certificate-chain limits must be positive, with ' +
    'MaxCertificateLength no larger than MaxTotalChainLength, which must not exceed the ' +
    '16 MiB handshake-message ceiling, and MaxChainCertificates must be between 1 and 255';
  SInvalidCertificatePin = 'a certificate pin must be a 32-byte SHA-256 SubjectPublicKeyInfo ' +
    'digest; a wrong-width pin can never match and would silently fail every handshake';
  SCredentialKeyLeafMismatch = 'the credential''s private key does not match the public key in ' +
    'its end-entity certificate (CertificateChain[0]); load a leaf-first chain (from PEM) whose ' +
    'first certificate pairs with the key';
  SCredentialLeafCannotSign = 'the credential''s end-entity certificate has a keyUsage extension ' +
    'that forbids digitalSignature, so it cannot sign a handshake (RFC 5280 4.2.1.3)';
  SCredentialLeafRsaPssUnsupported = 'the credential''s end-entity certificate carries an ' +
    'id-RSASSA-PSS public key, which is not supported for signing here; use an rsaEncryption ' +
    'certificate (RFC 9846 4.3.3)';
  SCredentialKeyNotExportable = 'the credential''s private key cannot export its public key, so it ' +
    'cannot be matched to its certificate; supply a credential whose key exposes a public key';
  SMalformedTrustAnchor = 'anchor %d of trust store %d is not a well-formed certificate; one unparsable root ' +
    'would fail every verification against the store';
  SSniCredentialInvalid = 'the SNI credential for host "%s" is invalid: %s';

const
  DefaultTicketLifetimeSeconds = UInt32(7200);
  DefaultTicketCount = Int32(2);
  MaxTicketCount = Int32(8);
  SessionScopeLength = Int32(16);
  MaxResumptionScopeLength = Int32(32);
  MaxServerEarlyData = UInt32(1 shl 20);
  MaxAlpnListBytes = Int32(16384);
  // the names ride one list with a 2-byte length in both versions (RFC 5246 7.4.4, RFC 9846 4.3.4)
  MaxCertificateAuthoritiesBytes = Int32(65535);
  // the whole CertificateRequest extensions block is one 2-byte-length vector (RFC 9846 4.4.2)
  MaxCertificateRequestExtensionsBytes = Int32(65535);
  // the ClientHello extensions block is one vector of at most 2^16-1 bytes (RFC 9846 4.2.2)
  MaxClientHelloExtensionsBytes = Int32(65535);
  // the other extensions (key_share, SNI, groups, schemes, versions, GREASE, the ECH decoy) need about 2 KB
  ClientHelloOtherExtensionsBytes = Int32(4096);
  // a cached ticket as a TLS 1.3 PSK: its length prefix and age, plus a SHA-384 binder with its length byte
  CachedTicketOfferBytes = Int32(TSessionTicketLimits.MaxCachedTicketBytes + 2 + 4 + 1 + 48);
  // the ECH payload tag, the encapsulated key, the padding and the extension headers
  EchOverheadBytes = Int32(1024);

type
  /// <summary>The immutable common settings, shared by the client and server config.</summary>
  TFrozenCommonConfigBase = class abstract(TInterfacedObject)
  protected
  var
    FCrypto: ICryptoProvider;
    FPkix: IPkixProvider;
    FCipherSuites: ICipherSuiteRegistry;
    FSignatureSchemes: ISignatureSchemeRegistry;
    FNamedGroups: INamedGroupRegistry;
    FSupportedVersions: TArray<UInt16>;
    FPreferredGroups: TArray<UInt16>;
    FAlpnProtocols: TArray<TBytes>;
    FRecordSizeLimit: Int32;
    FCertificateCompressors: TArray<ICertificateCompressor>;
    FCertificateDecompressors: TArray<ICertificateDecompressor>;
    FCertificateCompressionCache: ICertificateCompressionCache;
    FCredential: TTlsCredential;
    FTrustStore: ITrustAnchorStore;
    FChainLimits: TCertificateChainLimits;
    FStrengthPolicy: TCertificateStrengthPolicy;
    FRevocationPosture: TRevocationPosture;
    FCertificatePins: TArray<TBytes>;
    FIntermediateCertificates: TArray<TBytes>;
    FDangerousTrust: TDangerousTrust;
    FAsyncVerdict: TAsyncCertificateVerdict;
    FRequireExtendedMasterSecret: Boolean;
    FResumption: Boolean;
    FExternalPsks: TArray<TExternalPsk>;
    FTls12Psks: TArray<TTls12Psk>;
    FClock: ITlsClock;
    FMonotonicClock: ITlsMonotonicClock;
    FKeyLog: IKeyLog;
  public
    function Crypto: ICryptoProvider;
    function Pkix: IPkixProvider;
    function CipherSuites: ICipherSuiteRegistry;
    function SignatureSchemes: ISignatureSchemeRegistry;
    function NamedGroups: INamedGroupRegistry;
    function SupportedVersions: TArray<UInt16>;
    function PreferredGroups: TArray<UInt16>;
    function AlpnProtocols: TArray<TBytes>;
    function RecordSizeLimit: Int32;
    function CertificateCompressors: TArray<ICertificateCompressor>;
    function CertificateDecompressors: TArray<ICertificateDecompressor>;
    function CertificateCompressionCache: ICertificateCompressionCache;
    function Credential: TTlsCredential;
    function TrustStore: ITrustAnchorStore;
    function CertificateChainLimits: TCertificateChainLimits;
    function CertificateStrengthPolicy: TCertificateStrengthPolicy;
    function RevocationPosture: TRevocationPosture;
    function CertificatePins: TArray<TBytes>;
    function IntermediateCertificates: TArray<TBytes>;
    function DangerousTrust: TDangerousTrust;
    function AsyncCertificateVerdict: TAsyncCertificateVerdict;
    function RequireExtendedMasterSecret: Boolean;
    function Resumption: Boolean;
    function ExternalPsks: TArray<TExternalPsk>;
    function Tls12Psks: TArray<TTls12Psk>;
    function Clock: ITlsClock;
    function MonotonicClock: ITlsMonotonicClock;
    function KeyLog: IKeyLog;
  end;

  TFrozenClientConfig = class sealed(TFrozenCommonConfigBase, ITlsClientConfig)
  private
  var
    FGrease: Boolean;
    FCheckServerName: Boolean;
    FServerNameIndication: TServerNameIndication;
    FServerVerifierSource: IServerCertificateVerifierSource;
    FRequestOcspStapling: Boolean;
    FSessionCache: ISessionCache;
    FSessionScope: TBytes;
    FResumeVerification: TResumeVerification;
    FEarlyData: Boolean;
    FExternalPskRequired: Boolean;
    FTls12PskRequired: Boolean;
    FEchPolicy: IEchClientPolicy;
  public
    function Grease: Boolean;
    function CheckServerName: Boolean;
    function ServerNameIndication: TServerNameIndication;
    function ServerVerifierSource: IServerCertificateVerifierSource;
    function RequestOcspStapling: Boolean;
    function SessionCache: ISessionCache;
    function SessionScope: TBytes;
    function ResumeVerification: TResumeVerification;
    function EarlyData: Boolean;
    function ExternalPskRequired: Boolean;
    function Tls12PreSharedKeyRequired: Boolean;
    function EncryptedClientHello: IEchClientPolicy;
  end;

  TFrozenServerConfig = class sealed(TFrozenCommonConfigBase, ITlsServerConfig)
  private
  var
    FServerNameAck: Boolean;
    FCipherPreference: TServerCipherPreference;
    FNonEmsResumption: TNonEmsResumption;
    FAlpnRejectAll: Boolean;
    FClientCertificateAuthorities: TArray<TBytes>;
    FClientAuth: TClientAuthMode;
    FClientVerifierSource: IClientCertificateVerifierSource;
    FSessionStore: ISessionStore;
    FSessionTicketKeys: ISessionTicketKeyManager;
    FResumptionScope: TBytes;
    FCredentialResolver: ITlsServerCredentialResolver;
    FAntiReplay: IAntiReplayStrategy;
    FTicketLifetimeSeconds: UInt32;
    FTicketCount: Int32;
    FTls12PskIdentityHint: TBytes;
    FMaxEarlyData: UInt32;
    FEchServerPolicy: IEchServerPolicy;
  public
    function ServerNameAcknowledgement: Boolean;
    function CipherSuitePreference: TServerCipherPreference;
    function NonEmsResumption: TNonEmsResumption;
    function AlpnRejectAll: Boolean;
    function ClientCertificateAuthorities: TArray<TBytes>;
    function ClientAuth: TClientAuthMode;
    function ClientVerifierSource: IClientCertificateVerifierSource;
    function SessionStore: ISessionStore;
    function SessionTicketKeys: ISessionTicketKeyManager;
    function ResumptionScope: TBytes;
    function CredentialResolver: ITlsServerCredentialResolver;
    function AntiReplay: IAntiReplayStrategy;
    function TicketLifetimeSeconds: UInt32;
    function TicketCount: Int32;
    function Tls12PskIdentityHint: TBytes;
    function MaxEarlyData: UInt32;
    function EncryptedClientHello: IEchServerPolicy;
  end;

  /// <summary>Shared view plumbing over the owning builder whose mutators the view forwards to.
  /// FOwner is the builder typed concretely for its same-unit private mutators; FOwnerRef is the
  /// interface reference to the same builder.</summary>
  TTlsConfigViewBase = class abstract(TInterfacedObject)
  strict protected
  var
    FOwner: TTlsConfigBuilder;
    FOwnerRef: ITlsConfigBuilder;
  public
    constructor Create(const AOwner: TTlsConfigBuilder);
  end;

  TTlsClientConfigBuilder = class sealed(TTlsConfigViewBase, ITlsClientConfigBuilder)
  public
    function WithCipherSuites(const ARegistry: ICipherSuiteRegistry): ITlsClientConfigBuilder;
    function WithCipherSuiteList(const ASuites: TArray<UInt16>): ITlsClientConfigBuilder;
    function WithSignatureSchemes(const ARegistry: ISignatureSchemeRegistry): ITlsClientConfigBuilder;
    function WithNamedGroups(const ARegistry: INamedGroupRegistry): ITlsClientConfigBuilder;
    function WithSupportedVersions(const AVersions: TArray<UInt16>): ITlsClientConfigBuilder;
    function WithPreferredGroups(const AGroups: TArray<UInt16>): ITlsClientConfigBuilder;
    function WithAlpnProtocols(const AProtocols: TArray<TBytes>): ITlsClientConfigBuilder;
    function WithRecordSizeLimit(ALimit: Int32): ITlsClientConfigBuilder;
    function WithCertificateChainLimits(
      const ALimits: TCertificateChainLimits): ITlsClientConfigBuilder;
    function WithCredential(const ACredential: TTlsCredential): ITlsClientConfigBuilder;
    function WithCertificatePinning(
      const APins: TArray<TBytes>): ITlsClientConfigBuilder;
    function WithDangerousDisableServerNameCheck: ITlsClientConfigBuilder;
    function WithServerNameIndication(AMode: TServerNameIndication): ITlsClientConfigBuilder;
    function WithOcspStaplingRequest(AEnabled: Boolean): ITlsClientConfigBuilder;
    function WithServerVerification(const AVerification: IServerVerification): ITlsClientConfigBuilder;
    function WithCertificateVerifyCallback(
      const ACallback: TTlsCertificateVerifyCallback): ITlsClientConfigBuilder;
    function WithAsyncCertificateVerdict(
      ADeadlineMs: Cardinal): ITlsClientConfigBuilder;
    function WithLiveRevocationVerdict(
      ADeadlineMs: Cardinal): ITlsClientConfigBuilder;
    function WithSessionCache(const ACache: ISessionCache): ITlsClientConfigBuilder;
    function WithResumptionScope(const AScope: TBytes): ITlsClientConfigBuilder;
    function WithResumeVerification(AMode: TResumeVerification): ITlsClientConfigBuilder;
    function WithGrease(AEnable: Boolean): ITlsClientConfigBuilder;
    function WithClock(const AClock: ITlsClock): ITlsClientConfigBuilder;
    function WithMonotonicClock(const AClock: ITlsMonotonicClock): ITlsClientConfigBuilder;
    function WithDangerousKeyLog(const AKeyLog: IKeyLog): ITlsClientConfigBuilder;
    function WithResumption(AEnabled: Boolean): ITlsClientConfigBuilder;
    function Tls13: ITls13ClientConfigFacet;
    function Tls12: ITls12ClientConfigFacet;
    function Build: ITlsClientConfig;
  end;

  TTlsServerConfigBuilder = class sealed(TTlsConfigViewBase, ITlsServerConfigBuilder)
  public
    function WithCipherSuites(const ARegistry: ICipherSuiteRegistry): ITlsServerConfigBuilder;
    function WithCipherSuiteList(const ASuites: TArray<UInt16>): ITlsServerConfigBuilder;
    function WithSignatureSchemes(const ARegistry: ISignatureSchemeRegistry): ITlsServerConfigBuilder;
    function WithNamedGroups(const ARegistry: INamedGroupRegistry): ITlsServerConfigBuilder;
    function WithSupportedVersions(const AVersions: TArray<UInt16>): ITlsServerConfigBuilder;
    function WithPreferredGroups(const AGroups: TArray<UInt16>): ITlsServerConfigBuilder;
    function WithAlpnProtocols(const AProtocols: TArray<TBytes>): ITlsServerConfigBuilder;
    function WithRecordSizeLimit(ALimit: Int32): ITlsServerConfigBuilder;
    function WithServerNameAcknowledgement(ASend: Boolean): ITlsServerConfigBuilder;
    function WithCipherSuitePreference(APreference: TServerCipherPreference): ITlsServerConfigBuilder;
    function WithAlpnRejection(AReject: Boolean): ITlsServerConfigBuilder;
    function WithClientCertificateAuthorities(const AAuthorities: TArray<TBytes>): ITlsServerConfigBuilder;
    function WithCertificateChainLimits(
      const ALimits: TCertificateChainLimits): ITlsServerConfigBuilder;
    function WithCredential(const ACredential: TTlsCredential): ITlsServerConfigBuilder;
    function WithSniCredential(const AHost: string;
      const ACredential: TTlsCredential): ITlsServerConfigBuilder;
    function WithCredentialResolver(
      const AResolver: ITlsServerCredentialResolver): ITlsServerConfigBuilder;
    function WithPeerAuth(AMode: TClientAuthMode): ITlsServerConfigBuilder;
    function WithCertificatePinning(
      const APins: TArray<TBytes>): ITlsServerConfigBuilder;
    function WithClientVerification(const AVerification: IClientVerification): ITlsServerConfigBuilder;
    function WithCertificateVerifyCallback(
      const ACallback: TTlsCertificateVerifyCallback): ITlsServerConfigBuilder;
    function WithAsyncCertificateVerdict(
      ADeadlineMs: Cardinal): ITlsServerConfigBuilder;
    function WithLiveRevocationVerdict(
      ADeadlineMs: Cardinal): ITlsServerConfigBuilder;
    function WithSessionStore(const AStore: ISessionStore): ITlsServerConfigBuilder;
    function WithSessionTicketKeys(const AKeys: ISessionTicketKeyManager): ITlsServerConfigBuilder;
    function WithResumptionScope(const AScope: TBytes): ITlsServerConfigBuilder;
    function WithDefaultSessionTicketKeys: ITlsServerConfigBuilder;
    function WithClock(const AClock: ITlsClock): ITlsServerConfigBuilder;
    function WithMonotonicClock(const AClock: ITlsMonotonicClock): ITlsServerConfigBuilder;
    function WithDangerousKeyLog(const AKeyLog: IKeyLog): ITlsServerConfigBuilder;
    function WithTicketLifetime(ASeconds: UInt32): ITlsServerConfigBuilder;
    function WithResumption(AEnabled: Boolean): ITlsServerConfigBuilder;
    function Tls13: ITls13ServerConfigFacet;
    function Tls12: ITls12ServerConfigFacet;
    function Build: ITlsServerConfig;
  end;

  TTls13ClientConfigFacet = class sealed(TTlsConfigViewBase, ITls13ClientConfigFacet)
  public
    function WithExternalPreSharedKeys(
      const APsks: TArray<TExternalPsk>): ITls13ClientConfigFacet;
    function WithExternalPskRequired(AEnabled: Boolean): ITls13ClientConfigFacet;
    function WithCertificateDecompressors(
      const ADecompressors: TArray<ICertificateDecompressor>): ITls13ClientConfigFacet;
    function WithCertificateCompressors(
      const ACompressors: TArray<ICertificateCompressor>): ITls13ClientConfigFacet;
    function WithCertificateCompressionCache(
      const ACache: ICertificateCompressionCache): ITls13ClientConfigFacet;
    function WithEarlyData(AEnabled: Boolean): ITls13ClientConfigFacet;
    function WithEch(const AMode: IEchClientMode): ITls13ClientConfigFacet;
    function Tls12: ITls12ClientConfigFacet;
    function Build: ITlsClientConfig;
  end;

  TTls12ClientConfigFacet = class sealed(TTlsConfigViewBase, ITls12ClientConfigFacet)
  public
    function WithExtendedMasterSecret(ARequire: Boolean): ITls12ClientConfigFacet;
    function WithPreSharedKey(const APsk: TTls12Psk): ITls12ClientConfigFacet;
    function WithPreSharedKeyRequired(AEnabled: Boolean): ITls12ClientConfigFacet;
    function Tls13: ITls13ClientConfigFacet;
    function Build: ITlsClientConfig;
  end;

  TTls13ServerConfigFacet = class sealed(TTlsConfigViewBase, ITls13ServerConfigFacet)
  public
    function WithExternalPreSharedKeys(
      const APsks: TArray<TExternalPsk>): ITls13ServerConfigFacet;
    function WithTicketCount(ACount: Int32): ITls13ServerConfigFacet;
    function WithCertificateDecompressors(
      const ADecompressors: TArray<ICertificateDecompressor>): ITls13ServerConfigFacet;
    function WithCertificateCompressors(
      const ACompressors: TArray<ICertificateCompressor>): ITls13ServerConfigFacet;
    function WithCertificateCompressionCache(
      const ACache: ICertificateCompressionCache): ITls13ServerConfigFacet;
    function WithEarlyData(AMaxBytes: UInt32): ITls13ServerConfigFacet;
    function WithAntiReplay(const AStrategy: IAntiReplayStrategy): ITls13ServerConfigFacet;
    function WithEchKeyStore(const AKeyStore: IEchServerKeyStore): ITls13ServerConfigFacet; overload;
    function WithEchKeyStore(const AKeyStore: IEchServerKeyStore;
      ATrialDecrypt: Boolean): ITls13ServerConfigFacet; overload;
    function WithEchBackend: ITls13ServerConfigFacet;
    function Tls12: ITls12ServerConfigFacet;
    function Build: ITlsServerConfig;
  end;

  TTls12ServerConfigFacet = class sealed(TTlsConfigViewBase, ITls12ServerConfigFacet)
  public
    function WithExtendedMasterSecret(ARequire: Boolean): ITls12ServerConfigFacet;
    function WithNonEmsResumption(AMode: TNonEmsResumption): ITls12ServerConfigFacet;
    function WithPreSharedKeys(const APsks: TArray<TTls12Psk>): ITls12ServerConfigFacet;
    function WithPreSharedKeyIdentityHint(const AHint: TBytes): ITls12ServerConfigFacet;
    function Tls13: ITls13ServerConfigFacet;
    function Build: ITlsServerConfig;
  end;

{ TFrozenCommonConfigBase }

function TFrozenCommonConfigBase.Crypto: ICryptoProvider;
begin
  Result := FCrypto;
end;

function TFrozenCommonConfigBase.Pkix: IPkixProvider;
begin
  Result := FPkix;
end;

function TFrozenCommonConfigBase.CipherSuites: ICipherSuiteRegistry;
begin
  Result := FCipherSuites;
end;

function TFrozenCommonConfigBase.SignatureSchemes: ISignatureSchemeRegistry;
begin
  Result := FSignatureSchemes;
end;

function TFrozenCommonConfigBase.NamedGroups: INamedGroupRegistry;
begin
  Result := FNamedGroups;
end;

function TFrozenCommonConfigBase.SupportedVersions: TArray<UInt16>;
begin
  Result := System.Copy(FSupportedVersions);
end;

function TFrozenCommonConfigBase.PreferredGroups: TArray<UInt16>;
begin
  Result := System.Copy(FPreferredGroups);
end;

function TFrozenCommonConfigBase.AlpnProtocols: TArray<TBytes>;
begin
  Result := TArrayUtilities.DeepCopy<Byte>(FAlpnProtocols);
end;

function TFrozenCommonConfigBase.RecordSizeLimit: Int32;
begin
  Result := FRecordSizeLimit;
end;

function TFrozenCommonConfigBase.CertificateCompressors: TArray<ICertificateCompressor>;
begin
  Result := System.Copy(FCertificateCompressors);
end;

function TFrozenCommonConfigBase.CertificateDecompressors: TArray<ICertificateDecompressor>;
begin
  Result := System.Copy(FCertificateDecompressors);
end;

function TFrozenCommonConfigBase.CertificateCompressionCache: ICertificateCompressionCache;
begin
  // the shared instance, not a copy: every connection from this config memoizes into the
  // same cache - that cross-connection sharing is the whole point of this seam
  Result := FCertificateCompressionCache;
end;

function TFrozenCommonConfigBase.Credential: TTlsCredential;
begin
  Result := TTlsConfigBuilder.CloneCredential(FCredential);
end;

function TFrozenCommonConfigBase.TrustStore: ITrustAnchorStore;
begin
  Result := FTrustStore;
end;

function TFrozenCommonConfigBase.CertificateChainLimits: TCertificateChainLimits;
begin
  Result := FChainLimits;
end;

function TFrozenCommonConfigBase.CertificateStrengthPolicy: TCertificateStrengthPolicy;
begin
  Result := FStrengthPolicy;
end;

function TFrozenCommonConfigBase.RevocationPosture: TRevocationPosture;
begin
  Result := FRevocationPosture;
end;

function TFrozenCommonConfigBase.CertificatePins: TArray<TBytes>;
begin
  Result := TArrayUtilities.DeepCopy<Byte>(FCertificatePins);
end;

function TFrozenCommonConfigBase.IntermediateCertificates: TArray<TBytes>;
begin
  Result := TArrayUtilities.DeepCopy<Byte>(FIntermediateCertificates);
end;

function TFrozenCommonConfigBase.DangerousTrust: TDangerousTrust;
begin
  Result := FDangerousTrust;
end;

function TFrozenCommonConfigBase.AsyncCertificateVerdict: TAsyncCertificateVerdict;
begin
  Result := FAsyncVerdict;
end;

function TFrozenCommonConfigBase.RequireExtendedMasterSecret: Boolean;
begin
  Result := FRequireExtendedMasterSecret;
end;

function TFrozenCommonConfigBase.Resumption: Boolean;
begin
  Result := FResumption;
end;

function TFrozenCommonConfigBase.ExternalPsks: TArray<TExternalPsk>;
begin
  Result := TTlsConfigBuilder.CloneExternalPsks(FExternalPsks);
end;

function TFrozenCommonConfigBase.Tls12Psks: TArray<TTls12Psk>;
begin
  Result := TTlsConfigBuilder.CloneTls12Psks(FTls12Psks);
end;

function TFrozenCommonConfigBase.Clock: ITlsClock;
begin
  Result := FClock;
end;

function TFrozenCommonConfigBase.MonotonicClock: ITlsMonotonicClock;
begin
  Result := FMonotonicClock;
end;

function TFrozenCommonConfigBase.KeyLog: IKeyLog;
begin
  Result := FKeyLog;
end;

{ TFrozenClientConfig }

function TFrozenClientConfig.Grease: Boolean;
begin
  Result := FGrease;
end;

function TFrozenClientConfig.CheckServerName: Boolean;
begin
  Result := FCheckServerName;
end;

function TFrozenClientConfig.ServerNameIndication: TServerNameIndication;
begin
  Result := FServerNameIndication;
end;

function TFrozenClientConfig.ServerVerifierSource: IServerCertificateVerifierSource;
begin
  Result := FServerVerifierSource;
end;

function TFrozenClientConfig.RequestOcspStapling: Boolean;
begin
  Result := FRequestOcspStapling;
end;

function TFrozenClientConfig.SessionCache: ISessionCache;
begin
  Result := FSessionCache;
end;

function TFrozenClientConfig.SessionScope: TBytes;
begin
  Result := System.Copy(FSessionScope);
end;

function TFrozenClientConfig.ResumeVerification: TResumeVerification;
begin
  Result := FResumeVerification;
end;

function TFrozenClientConfig.EarlyData: Boolean;
begin
  Result := FEarlyData;
end;

function TFrozenClientConfig.ExternalPskRequired: Boolean;
begin
  Result := FExternalPskRequired;
end;

function TFrozenClientConfig.Tls12PreSharedKeyRequired: Boolean;
begin
  Result := FTls12PskRequired;
end;

function TFrozenClientConfig.EncryptedClientHello: IEchClientPolicy;
begin
  Result := FEchPolicy;
end;

{ TFrozenServerConfig }

function TFrozenServerConfig.ServerNameAcknowledgement: Boolean;
begin
  Result := FServerNameAck;
end;

function TFrozenServerConfig.CipherSuitePreference: TServerCipherPreference;
begin
  Result := FCipherPreference;
end;

function TFrozenServerConfig.NonEmsResumption: TNonEmsResumption;
begin
  Result := FNonEmsResumption;
end;

function TFrozenServerConfig.AlpnRejectAll: Boolean;
begin
  Result := FAlpnRejectAll;
end;

function TFrozenServerConfig.ClientCertificateAuthorities: TArray<TBytes>;
begin
  Result := TArrayUtilities.DeepCopy<Byte>(FClientCertificateAuthorities);
end;

function TFrozenServerConfig.ClientAuth: TClientAuthMode;
begin
  Result := FClientAuth;
end;

function TFrozenServerConfig.ClientVerifierSource: IClientCertificateVerifierSource;
begin
  Result := FClientVerifierSource;
end;

function TFrozenServerConfig.SessionStore: ISessionStore;
begin
  Result := FSessionStore;
end;

function TFrozenServerConfig.SessionTicketKeys: ISessionTicketKeyManager;
begin
  Result := FSessionTicketKeys;
end;

function TFrozenServerConfig.ResumptionScope: TBytes;
begin
  Result := System.Copy(FResumptionScope);
end;

function TFrozenServerConfig.CredentialResolver: ITlsServerCredentialResolver;
begin
  Result := FCredentialResolver;
end;

function TFrozenServerConfig.AntiReplay: IAntiReplayStrategy;
begin
  Result := FAntiReplay;
end;

function TFrozenServerConfig.TicketLifetimeSeconds: UInt32;
begin
  Result := FTicketLifetimeSeconds;
end;

function TFrozenServerConfig.TicketCount: Int32;
begin
  Result := FTicketCount;
end;

function TFrozenServerConfig.Tls12PskIdentityHint: TBytes;
begin
  Result := System.Copy(FTls12PskIdentityHint);
end;

function TFrozenServerConfig.MaxEarlyData: UInt32;
begin
  Result := FMaxEarlyData;
end;

function TFrozenServerConfig.EncryptedClientHello: IEchServerPolicy;
begin
  Result := FEchServerPolicy;
end;

{ TTlsConfigViewBase }

constructor TTlsConfigViewBase.Create(const AOwner: TTlsConfigBuilder);
begin
  inherited Create;
  FOwner := AOwner;
  FOwnerRef := AOwner;
end;

{ TTlsClientConfigBuilder }

function TTlsClientConfigBuilder.WithCipherSuites(
  const ARegistry: ICipherSuiteRegistry): ITlsClientConfigBuilder;
begin
  FOwner.WithCipherSuites(ARegistry);
  Result := Self;
end;

function TTlsClientConfigBuilder.WithCipherSuiteList(
  const ASuites: TArray<UInt16>): ITlsClientConfigBuilder;
begin
  FOwner.WithCipherSuiteList(ASuites);
  Result := Self;
end;

function TTlsClientConfigBuilder.WithSignatureSchemes(
  const ARegistry: ISignatureSchemeRegistry): ITlsClientConfigBuilder;
begin
  FOwner.WithSignatureSchemes(ARegistry);
  Result := Self;
end;

function TTlsClientConfigBuilder.WithNamedGroups(
  const ARegistry: INamedGroupRegistry): ITlsClientConfigBuilder;
begin
  FOwner.WithNamedGroups(ARegistry);
  Result := Self;
end;

function TTlsClientConfigBuilder.WithSupportedVersions(
  const AVersions: TArray<UInt16>): ITlsClientConfigBuilder;
begin
  FOwner.WithSupportedVersions(AVersions);
  Result := Self;
end;

function TTlsClientConfigBuilder.WithPreferredGroups(
  const AGroups: TArray<UInt16>): ITlsClientConfigBuilder;
begin
  FOwner.WithPreferredGroups(AGroups);
  Result := Self;
end;

function TTlsClientConfigBuilder.WithAlpnProtocols(
  const AProtocols: TArray<TBytes>): ITlsClientConfigBuilder;
begin
  FOwner.WithAlpnProtocols(AProtocols);
  Result := Self;
end;

function TTlsClientConfigBuilder.WithRecordSizeLimit(
  ALimit: Int32): ITlsClientConfigBuilder;
begin
  FOwner.WithRecordSizeLimit(ALimit);
  Result := Self;
end;

function TTlsClientConfigBuilder.WithCertificateChainLimits(
  const ALimits: TCertificateChainLimits): ITlsClientConfigBuilder;
begin
  FOwner.WithCertificateChainLimits(ALimits);
  Result := Self;
end;

function TTlsClientConfigBuilder.WithCredential(
  const ACredential: TTlsCredential): ITlsClientConfigBuilder;
begin
  FOwner.WithCredential(ACredential);
  Result := Self;
end;

function TTlsClientConfigBuilder.WithCertificatePinning(
  const APins: TArray<TBytes>): ITlsClientConfigBuilder;
begin
  FOwner.WithCertificatePinning(APins);
  Result := Self;
end;

function TTlsClientConfigBuilder.WithDangerousDisableServerNameCheck: ITlsClientConfigBuilder;
begin
  FOwner.WithDangerousDisableServerNameCheck;
  Result := Self;
end;

function TTlsClientConfigBuilder.WithServerNameIndication(
  AMode: TServerNameIndication): ITlsClientConfigBuilder;
begin
  FOwner.WithServerNameIndication(AMode);
  Result := Self;
end;

function TTlsClientConfigBuilder.WithOcspStaplingRequest(
  AEnabled: Boolean): ITlsClientConfigBuilder;
begin
  FOwner.WithOcspStaplingRequest(AEnabled);
  Result := Self;
end;

function TTlsClientConfigBuilder.WithServerVerification(
  const AVerification: IServerVerification): ITlsClientConfigBuilder;
begin
  FOwner.WithServerVerification(AVerification);
  Result := Self;
end;

function TTlsClientConfigBuilder.WithAsyncCertificateVerdict(
  ADeadlineMs: Cardinal): ITlsClientConfigBuilder;
begin
  FOwner.WithAsyncCertificateVerdict(ADeadlineMs);
  Result := Self;
end;

function TTlsClientConfigBuilder.WithLiveRevocationVerdict(
  ADeadlineMs: Cardinal): ITlsClientConfigBuilder;
begin
  FOwner.WithLiveRevocationVerdict(ADeadlineMs);
  Result := Self;
end;

function TTlsClientConfigBuilder.WithCertificateVerifyCallback(
  const ACallback: TTlsCertificateVerifyCallback): ITlsClientConfigBuilder;
begin
  FOwner.WithCertificateVerifyCallback(ACallback);
  Result := Self;
end;

function TTlsClientConfigBuilder.WithSessionCache(
  const ACache: ISessionCache): ITlsClientConfigBuilder;
begin
  FOwner.WithSessionCache(ACache);
  Result := Self;
end;

function TTlsClientConfigBuilder.WithResumptionScope(
  const AScope: TBytes): ITlsClientConfigBuilder;
begin
  FOwner.WithSessionScope(AScope);
  Result := Self;
end;

function TTlsClientConfigBuilder.WithResumeVerification(
  AMode: TResumeVerification): ITlsClientConfigBuilder;
begin
  FOwner.WithResumeVerification(AMode);
  Result := Self;
end;

function TTlsClientConfigBuilder.WithGrease(AEnable: Boolean): ITlsClientConfigBuilder;
begin
  FOwner.WithGrease(AEnable);
  Result := Self;
end;

function TTlsClientConfigBuilder.WithClock(
  const AClock: ITlsClock): ITlsClientConfigBuilder;
begin
  FOwner.WithClock(AClock);
  Result := Self;
end;

function TTlsClientConfigBuilder.WithMonotonicClock(
  const AClock: ITlsMonotonicClock): ITlsClientConfigBuilder;
begin
  FOwner.WithMonotonicClock(AClock);
  Result := Self;
end;

function TTlsClientConfigBuilder.WithDangerousKeyLog(
  const AKeyLog: IKeyLog): ITlsClientConfigBuilder;
begin
  FOwner.WithDangerousKeyLog(AKeyLog);
  Result := Self;
end;

function TTlsClientConfigBuilder.WithResumption(
  AEnabled: Boolean): ITlsClientConfigBuilder;
begin
  FOwner.WithResumption(AEnabled);
  Result := Self;
end;

function TTlsClientConfigBuilder.Tls13: ITls13ClientConfigFacet;
begin
  Result := FOwner.Client13;
end;

function TTlsClientConfigBuilder.Tls12: ITls12ClientConfigFacet;
begin
  Result := FOwner.Client12;
end;

function TTlsClientConfigBuilder.Build: ITlsClientConfig;
begin
  Result := FOwner.BuildClient;
end;

{ TTlsServerConfigBuilder }

function TTlsServerConfigBuilder.WithCipherSuites(
  const ARegistry: ICipherSuiteRegistry): ITlsServerConfigBuilder;
begin
  FOwner.WithCipherSuites(ARegistry);
  Result := Self;
end;

function TTlsServerConfigBuilder.WithCipherSuiteList(
  const ASuites: TArray<UInt16>): ITlsServerConfigBuilder;
begin
  FOwner.WithCipherSuiteList(ASuites);
  Result := Self;
end;

function TTlsServerConfigBuilder.WithSignatureSchemes(
  const ARegistry: ISignatureSchemeRegistry): ITlsServerConfigBuilder;
begin
  FOwner.WithSignatureSchemes(ARegistry);
  Result := Self;
end;

function TTlsServerConfigBuilder.WithNamedGroups(
  const ARegistry: INamedGroupRegistry): ITlsServerConfigBuilder;
begin
  FOwner.WithNamedGroups(ARegistry);
  Result := Self;
end;

function TTlsServerConfigBuilder.WithSupportedVersions(
  const AVersions: TArray<UInt16>): ITlsServerConfigBuilder;
begin
  FOwner.WithSupportedVersions(AVersions);
  Result := Self;
end;

function TTlsServerConfigBuilder.WithPreferredGroups(
  const AGroups: TArray<UInt16>): ITlsServerConfigBuilder;
begin
  FOwner.WithPreferredGroups(AGroups);
  Result := Self;
end;

function TTlsServerConfigBuilder.WithAlpnProtocols(
  const AProtocols: TArray<TBytes>): ITlsServerConfigBuilder;
begin
  FOwner.WithAlpnProtocols(AProtocols);
  Result := Self;
end;

function TTlsServerConfigBuilder.WithRecordSizeLimit(
  ALimit: Int32): ITlsServerConfigBuilder;
begin
  FOwner.WithRecordSizeLimit(ALimit);
  Result := Self;
end;

function TTlsServerConfigBuilder.WithServerNameAcknowledgement(
  ASend: Boolean): ITlsServerConfigBuilder;
begin
  FOwner.WithServerNameAcknowledgement(ASend);
  Result := Self;
end;

function TTlsServerConfigBuilder.WithCipherSuitePreference(
  APreference: TServerCipherPreference): ITlsServerConfigBuilder;
begin
  FOwner.WithCipherSuitePreference(APreference);
  Result := Self;
end;

function TTlsServerConfigBuilder.WithAlpnRejection(
  AReject: Boolean): ITlsServerConfigBuilder;
begin
  FOwner.WithAlpnRejection(AReject);
  Result := Self;
end;

function TTlsServerConfigBuilder.WithClientCertificateAuthorities(
  const AAuthorities: TArray<TBytes>): ITlsServerConfigBuilder;
begin
  FOwner.WithClientCertificateAuthorities(AAuthorities);
  Result := Self;
end;

function TTlsServerConfigBuilder.WithCertificateChainLimits(
  const ALimits: TCertificateChainLimits): ITlsServerConfigBuilder;
begin
  FOwner.WithCertificateChainLimits(ALimits);
  Result := Self;
end;

function TTlsServerConfigBuilder.WithCredential(
  const ACredential: TTlsCredential): ITlsServerConfigBuilder;
begin
  FOwner.WithCredential(ACredential);
  Result := Self;
end;

function TTlsServerConfigBuilder.WithSniCredential(const AHost: string;
  const ACredential: TTlsCredential): ITlsServerConfigBuilder;
begin
  FOwner.WithSniCredential(AHost, ACredential);
  Result := Self;
end;

function TTlsServerConfigBuilder.WithCredentialResolver(
  const AResolver: ITlsServerCredentialResolver): ITlsServerConfigBuilder;
begin
  FOwner.WithCredentialResolver(AResolver);
  Result := Self;
end;

function TTlsServerConfigBuilder.WithPeerAuth(
  AMode: TClientAuthMode): ITlsServerConfigBuilder;
begin
  FOwner.WithPeerAuth(AMode);
  Result := Self;
end;

function TTlsServerConfigBuilder.WithCertificatePinning(
  const APins: TArray<TBytes>): ITlsServerConfigBuilder;
begin
  FOwner.WithCertificatePinning(APins);
  Result := Self;
end;

function TTlsServerConfigBuilder.WithClientVerification(
  const AVerification: IClientVerification): ITlsServerConfigBuilder;
begin
  FOwner.WithClientVerification(AVerification);
  Result := Self;
end;

function TTlsServerConfigBuilder.WithCertificateVerifyCallback(
  const ACallback: TTlsCertificateVerifyCallback): ITlsServerConfigBuilder;
begin
  FOwner.WithCertificateVerifyCallback(ACallback);
  Result := Self;
end;

function TTlsServerConfigBuilder.WithAsyncCertificateVerdict(
  ADeadlineMs: Cardinal): ITlsServerConfigBuilder;
begin
  FOwner.WithAsyncCertificateVerdict(ADeadlineMs);
  Result := Self;
end;

function TTlsServerConfigBuilder.WithLiveRevocationVerdict(
  ADeadlineMs: Cardinal): ITlsServerConfigBuilder;
begin
  FOwner.WithLiveRevocationVerdict(ADeadlineMs);
  Result := Self;
end;

function TTlsServerConfigBuilder.WithSessionStore(
  const AStore: ISessionStore): ITlsServerConfigBuilder;
begin
  FOwner.WithSessionStore(AStore);
  Result := Self;
end;

function TTlsServerConfigBuilder.WithSessionTicketKeys(
  const AKeys: ISessionTicketKeyManager): ITlsServerConfigBuilder;
begin
  FOwner.WithSessionTicketKeys(AKeys);
  Result := Self;
end;

function TTlsServerConfigBuilder.WithResumptionScope(
  const AScope: TBytes): ITlsServerConfigBuilder;
begin
  FOwner.WithResumptionScope(AScope);
  Result := Self;
end;

function TTlsServerConfigBuilder.WithDefaultSessionTicketKeys: ITlsServerConfigBuilder;
begin
  FOwner.WithDefaultSessionTicketKeys;
  Result := Self;
end;

function TTlsServerConfigBuilder.WithClock(
  const AClock: ITlsClock): ITlsServerConfigBuilder;
begin
  FOwner.WithClock(AClock);
  Result := Self;
end;

function TTlsServerConfigBuilder.WithMonotonicClock(
  const AClock: ITlsMonotonicClock): ITlsServerConfigBuilder;
begin
  FOwner.WithMonotonicClock(AClock);
  Result := Self;
end;

function TTlsServerConfigBuilder.WithDangerousKeyLog(
  const AKeyLog: IKeyLog): ITlsServerConfigBuilder;
begin
  FOwner.WithDangerousKeyLog(AKeyLog);
  Result := Self;
end;

function TTlsServerConfigBuilder.WithTicketLifetime(
  ASeconds: UInt32): ITlsServerConfigBuilder;
begin
  FOwner.WithTicketLifetime(ASeconds);
  Result := Self;
end;

function TTlsServerConfigBuilder.WithResumption(
  AEnabled: Boolean): ITlsServerConfigBuilder;
begin
  FOwner.WithResumption(AEnabled);
  Result := Self;
end;

function TTlsServerConfigBuilder.Tls13: ITls13ServerConfigFacet;
begin
  Result := FOwner.Server13;
end;

function TTlsServerConfigBuilder.Tls12: ITls12ServerConfigFacet;
begin
  Result := FOwner.Server12;
end;

function TTlsServerConfigBuilder.Build: ITlsServerConfig;
begin
  Result := FOwner.BuildServer;
end;

{ TTls13ClientConfigFacet }

function TTls13ClientConfigFacet.WithExternalPreSharedKeys(
  const APsks: TArray<TExternalPsk>): ITls13ClientConfigFacet;
begin
  FOwner.WithExternalPreSharedKeys(APsks);
  Result := Self;
end;

function TTls13ClientConfigFacet.WithExternalPskRequired(
  AEnabled: Boolean): ITls13ClientConfigFacet;
begin
  FOwner.WithExternalPskRequired(AEnabled);
  Result := Self;
end;

function TTls13ClientConfigFacet.WithCertificateDecompressors(
  const ADecompressors: TArray<ICertificateDecompressor>): ITls13ClientConfigFacet;
begin
  FOwner.WithCertificateDecompressors(ADecompressors);
  Result := Self;
end;

function TTls13ClientConfigFacet.WithCertificateCompressors(
  const ACompressors: TArray<ICertificateCompressor>): ITls13ClientConfigFacet;
begin
  FOwner.WithCertificateCompressors(ACompressors);
  Result := Self;
end;

function TTls13ClientConfigFacet.WithCertificateCompressionCache(
  const ACache: ICertificateCompressionCache): ITls13ClientConfigFacet;
begin
  FOwner.WithCertificateCompressionCache(ACache);
  Result := Self;
end;

function TTls13ClientConfigFacet.WithEarlyData(
  AEnabled: Boolean): ITls13ClientConfigFacet;
begin
  FOwner.WithClientEarlyData(AEnabled);
  Result := Self;
end;

function TTls13ClientConfigFacet.WithEch(
  const AMode: IEchClientMode): ITls13ClientConfigFacet;
begin
  FOwner.WithEch(AMode);
  Result := Self;
end;

function TTls13ClientConfigFacet.Tls12: ITls12ClientConfigFacet;
begin
  Result := FOwner.Client12;
end;

function TTls13ClientConfigFacet.Build: ITlsClientConfig;
begin
  Result := FOwner.BuildClient;
end;

{ TTls12ClientConfigFacet }

function TTls12ClientConfigFacet.WithExtendedMasterSecret(
  ARequire: Boolean): ITls12ClientConfigFacet;
begin
  FOwner.WithExtendedMasterSecret(ARequire);
  Result := Self;
end;

function TTls12ClientConfigFacet.WithPreSharedKey(
  const APsk: TTls12Psk): ITls12ClientConfigFacet;
begin
  FOwner.WithTls12PreSharedKeys(TArray<TTls12Psk>.Create(APsk));
  Result := Self;
end;

function TTls12ClientConfigFacet.WithPreSharedKeyRequired(
  AEnabled: Boolean): ITls12ClientConfigFacet;
begin
  FOwner.WithTls12PreSharedKeyRequired(AEnabled);
  Result := Self;
end;

function TTls12ClientConfigFacet.Tls13: ITls13ClientConfigFacet;
begin
  Result := FOwner.Client13;
end;

function TTls12ClientConfigFacet.Build: ITlsClientConfig;
begin
  Result := FOwner.BuildClient;
end;

{ TTls13ServerConfigFacet }

function TTls13ServerConfigFacet.WithExternalPreSharedKeys(
  const APsks: TArray<TExternalPsk>): ITls13ServerConfigFacet;
begin
  FOwner.WithExternalPreSharedKeys(APsks);
  Result := Self;
end;

function TTls13ServerConfigFacet.WithTicketCount(ACount: Int32): ITls13ServerConfigFacet;
begin
  FOwner.WithTicketCount(ACount);
  Result := Self;
end;

function TTls13ServerConfigFacet.WithCertificateDecompressors(
  const ADecompressors: TArray<ICertificateDecompressor>): ITls13ServerConfigFacet;
begin
  FOwner.WithCertificateDecompressors(ADecompressors);
  Result := Self;
end;

function TTls13ServerConfigFacet.WithCertificateCompressors(
  const ACompressors: TArray<ICertificateCompressor>): ITls13ServerConfigFacet;
begin
  FOwner.WithCertificateCompressors(ACompressors);
  Result := Self;
end;

function TTls13ServerConfigFacet.WithCertificateCompressionCache(
  const ACache: ICertificateCompressionCache): ITls13ServerConfigFacet;
begin
  FOwner.WithCertificateCompressionCache(ACache);
  Result := Self;
end;

function TTls13ServerConfigFacet.WithEarlyData(
  AMaxBytes: UInt32): ITls13ServerConfigFacet;
begin
  FOwner.WithServerEarlyData(AMaxBytes);
  Result := Self;
end;

function TTls13ServerConfigFacet.WithAntiReplay(
  const AStrategy: IAntiReplayStrategy): ITls13ServerConfigFacet;
begin
  FOwner.WithAntiReplay(AStrategy);
  Result := Self;
end;

function TTls13ServerConfigFacet.WithEchKeyStore(
  const AKeyStore: IEchServerKeyStore): ITls13ServerConfigFacet;
begin
  FOwner.WithEchKeyStore(AKeyStore);
  Result := Self;
end;

function TTls13ServerConfigFacet.WithEchKeyStore(const AKeyStore: IEchServerKeyStore;
  ATrialDecrypt: Boolean): ITls13ServerConfigFacet;
begin
  FOwner.WithEchKeyStore(AKeyStore, ATrialDecrypt);
  Result := Self;
end;

function TTls13ServerConfigFacet.WithEchBackend: ITls13ServerConfigFacet;
begin
  FOwner.WithEchBackend;
  Result := Self;
end;

function TTls13ServerConfigFacet.Tls12: ITls12ServerConfigFacet;
begin
  Result := FOwner.Server12;
end;

function TTls13ServerConfigFacet.Build: ITlsServerConfig;
begin
  Result := FOwner.BuildServer;
end;

{ TTls12ServerConfigFacet }

function TTls12ServerConfigFacet.WithExtendedMasterSecret(
  ARequire: Boolean): ITls12ServerConfigFacet;
begin
  FOwner.WithExtendedMasterSecret(ARequire);
  Result := Self;
end;

function TTls12ServerConfigFacet.WithNonEmsResumption(
  AMode: TNonEmsResumption): ITls12ServerConfigFacet;
begin
  FOwner.WithNonEmsResumption(AMode);
  Result := Self;
end;

function TTls12ServerConfigFacet.WithPreSharedKeys(
  const APsks: TArray<TTls12Psk>): ITls12ServerConfigFacet;
begin
  FOwner.WithTls12PreSharedKeys(APsks);
  Result := Self;
end;

function TTls12ServerConfigFacet.WithPreSharedKeyIdentityHint(
  const AHint: TBytes): ITls12ServerConfigFacet;
begin
  FOwner.WithTls12PskIdentityHint(AHint);
  Result := Self;
end;

function TTls12ServerConfigFacet.Tls13: ITls13ServerConfigFacet;
begin
  Result := FOwner.Server13;
end;

function TTls12ServerConfigFacet.Build: ITlsServerConfig;
begin
  Result := FOwner.BuildServer;
end;

{ TTlsConfigBuilder }

class function TTlsConfigProfile.Default: TTlsConfigProfile;
begin
  Result.CipherSuites := nil;
  Result.SignatureSchemes := nil;
  Result.NamedGroups := nil;
  Result.SupportedVersions := nil;
  Result.PreferredGroups := nil;
  Result.CertificateChainLimits := TCertificateChainLimits.Defaults;
  Result.RequestOcspStapling := False;
  Result.Resumption := True;
end;

class function TTlsConfigBuilder.CreateFromProfile(const ACryptoProvider: ICryptoProvider;
  const APkixProvider: IPkixProvider;
  const AProfile: TTlsConfigProfile): ITlsConfigBuilder;
begin
  Result := TTlsConfigBuilder.Create(ACryptoProvider, APkixProvider, AProfile);
end;

constructor TTlsConfigBuilder.Create(const ACryptoProvider: ICryptoProvider;
  const APkixProvider: IPkixProvider; const AProfile: TTlsConfigProfile);
begin
  inherited Create;
  if ACryptoProvider = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilCryptoProvider);
  if APkixProvider = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilPkixProvider);
  FCrypto := ACryptoProvider;
  FPkix := APkixProvider;
  FFrozen := False;
  FBaseline := AProfile;
  FHasCredential := False;
  FCheckServerName := True;
  FServerNameIndication := TServerNameIndication.Send;
  // the client does not offer status_request unless asked: an unsolicited staple is rejected
  FRequestOcspStapling := False;
  // soft-fail revocation is the default posture (stapled OCSP, RFC 6066 8 /
  // RFC 9846 4.5.1.1; must-staple RFC 7633); presets may harden it
  FRevocationPosture := TRevocationPosture.Soft;
  FChainLimits := TCertificateChainLimits.Defaults;
  FStrengthPolicy := TCertificateStrengthPolicy.Defaults;
  // certificate compression is on by default (RFC 8879) with the built-in zlib backend;
  // seeded directly, so it does not mark the 1.3 facet as explicitly configured
  FCertificateCompressors := TZlibCertificateCompression.DefaultCompressors;
  FCertificateDecompressors := TZlibCertificateCompression.DefaultDecompressors;
  // the cross-connection compression cache is opt-in (like the session store): nil until a
  // caller supplies one via WithCertificateCompressionCache, so a stable body re-deflates on
  // every connection until one is set
  // resumption is engaged by default (a preset may turn it off): a server then resumes out of the
  // box, minting a default STEK at build time unless explicit ticket keys or a session store were
  // supplied; a client still needs a session cache to retain the tickets it is offered
  FResumption := True;
  // a client sends GREASE (RFC 8701) and a server acknowledges a received server_name
  // (RFC 6066) by default; both are optional and a caller may turn them off
  FGrease := True;
  FServerNameAck := True;
  // server-preference cipher selection by default; a caller may opt into honoring the client's order
  FCipherPreference := TServerCipherPreference.ServerOrder;
  // a TLS 1.2 server never resumes a session set up without extended_master_secret by default
  // (RFC 7627 5.3); an operator serving legacy clients opts into Resume
  FNonEmsResumption := TNonEmsResumption.Decline;
  // configuring an external PSK is an explicit "authenticate with this key" statement, so a
  // non-PSK server response is refused by default; a caller may opt into a certificate fallback
  FExternalPskRequired := True;
  FTls12PskRequired := True;
  FTicketLifetimeSeconds := DefaultTicketLifetimeSeconds;
  FTicketCount := DefaultTicketCount;
  // the endpoint reads the real system clock unless a caller injects one via WithClock
  FClock := TSystemClock.Create;
  FMonotonicClock := TSystemMonotonicClock.Create;
  // apply the profile through the same mutators the presets call, so every Build-time validation
  // runs: registries only when supplied, lists only when non-empty, the scalars always
  if AProfile.CipherSuites <> nil then
    WithCipherSuites(AProfile.CipherSuites);
  if AProfile.SignatureSchemes <> nil then
    WithSignatureSchemes(AProfile.SignatureSchemes);
  if AProfile.NamedGroups <> nil then
    WithNamedGroups(AProfile.NamedGroups);
  if System.Length(AProfile.SupportedVersions) > 0 then
    WithSupportedVersions(AProfile.SupportedVersions);
  if System.Length(AProfile.PreferredGroups) > 0 then
    WithPreferredGroups(AProfile.PreferredGroups);
  WithCertificateChainLimits(AProfile.CertificateChainLimits);
  WithOcspStaplingRequest(AProfile.RequestOcspStapling);
  WithResumption(AProfile.Resumption);
end;

procedure TTlsConfigBuilder.GuardMutable;
begin
  if FFrozen then
    raise EInvalidOperationTlsLibException.CreateRes(@SBuilderFrozen);
end;

function TTlsConfigBuilder.Tls13FacetConfigured: Boolean;
begin
  Result := (System.Length(FExternalPsks) > 0) or (not FExternalPskRequired) or
    FClientEarlyData or (FMaxEarlyData > 0) or (FTicketCount <> DefaultTicketCount) or
    (FAntiReplay <> nil) or (FEchMode <> nil) or (FEchServerPolicy <> nil) or
    FCompressorsSet or FDecompressorsSet or (FCertificateCompressionCache <> nil);
end;

function TTlsConfigBuilder.Tls12FacetConfigured: Boolean;
begin
  Result := (System.Length(FTls12Psks) > 0) or (not FTls12PskRequired) or
    (System.Length(FTls12PskIdentityHint) > 0) or FRequireExtendedMasterSecret or
    (FNonEmsResumption <> TNonEmsResumption.Decline);
end;

procedure TTlsConfigBuilder.ValidateExternalPskOfferFits;
var
  LI: Int32;
  LHello: Int64;
begin
  if System.Length(FExternalPsks) = 0 then
    Exit;
  LHello := ClientHelloOtherExtensionsBytes;
  // the ALPN extension: its header, list length and each name with its length byte
  if System.Length(FAlpnProtocols) > 0 then
  begin
    Inc(LHello, 4 + 2);
    for LI := 0 to System.High(FAlpnProtocols) do
      Inc(LHello, 1 + System.Length(FAlpnProtocols[LI]));
  end;
  if FResumption and (FSessionCache <> nil) then
    Inc(LHello, CachedTicketOfferBytes);
  Inc(LHello, 4 + TExternalPskImporter.OfferedExtensionLength(FExternalPsks, TlsWireVersionTls13));
  // the inner hello rides in the outer ECH payload beside an outer hello of the same shape
  if (FEchMode <> nil) and (not FEchMode.IsGrease) then
    LHello := 2 * LHello + EchOverheadBytes;
  if LHello > MaxClientHelloExtensionsBytes then
    raise EInvalidOperationTlsLibException.CreateRes(@SExternalPskOfferTooLarge);
end;

procedure TTlsConfigBuilder.ValidateVersionScoping;
begin
  // a raw builder that never called WithSupportedVersions has none; a machine cannot be built
  // without an offered version (RFC 9846 4.3.1; the factory only builds TLS 1.3 and 1.2)
  if System.Length(FSupportedVersions) = 0 then
    raise EInvalidOperationTlsLibException.CreateRes(@SNoSupportedVersions);
  if Tls13FacetConfigured and not (TArrayUtilities.Contains<UInt16>(FSupportedVersions,
    TlsWireVersionTls13)) then
    raise EInvalidOperationTlsLibException.CreateRes(@STls13NotOffered);
  if Tls12FacetConfigured and not (TArrayUtilities.Contains<UInt16>(FSupportedVersions,
    TlsWireVersionTls12)) then
    raise EInvalidOperationTlsLibException.CreateRes(@STls12NotOffered);
end;

procedure TTlsConfigBuilder.ValidatePskOnlyClientSettings;
begin
  // the server never requests a client certificate in a PSK handshake (RFC 9846 4.4.2)
  if FHasCredential then
    raise EInvalidOperationTlsLibException.CreateResFmt(@SPskOnlyClientSetting,
      ['WithCredential']);
  if System.Length(FCertificatePins) > 0 then
    raise EInvalidOperationTlsLibException.CreateResFmt(@SPskOnlyClientSetting,
      ['WithCertificatePinning']);
  if Assigned(FDangerousTrust.VerifyCallback) then
    raise EInvalidOperationTlsLibException.CreateResFmt(@SPskOnlyClientSetting,
      ['WithCertificateVerifyCallback']);
  if FAsyncVerdict.Deferral <> TVerdictDeferral.None then
    raise EInvalidOperationTlsLibException.CreateResFmt(@SPskOnlyClientSetting,
      ['WithAsyncCertificateVerdict and WithLiveRevocationVerdict']);
  if not (FChainLimits = FBaseline.CertificateChainLimits) then
    raise EInvalidOperationTlsLibException.CreateResFmt(@SPskOnlyClientSetting,
      ['WithCertificateChainLimits']);
  if FRequestOcspStapling <> FBaseline.RequestOcspStapling then
    raise EInvalidOperationTlsLibException.CreateResFmt(@SPskOnlyClientSetting,
      ['WithOcspStaplingRequest']);
  if not FCheckServerName then
    raise EInvalidOperationTlsLibException.CreateResFmt(@SPskOnlyClientSetting,
      ['WithDangerousDisableServerNameCheck']);
  if FDecompressorsSet and (System.Length(FCertificateDecompressors) > 0) then
    raise EInvalidOperationTlsLibException.CreateResFmt(@SPskOnlyClientSetting,
      ['Tls13.WithCertificateDecompressors']);
  if FResumeVerification = TResumeVerification.Reverify then
    raise EInvalidOperationTlsLibException.CreateResFmt(@SPskOnlyClientSetting,
      ['WithResumeVerification(Reverify)']);
end;

procedure TTlsConfigBuilder.ValidateTicketCountZeroSettings;
begin
  if (FTicketCount <> 0) or (not FResumption) then
    Exit;
  // a shared store or key manager can still resume tickets another server issued, early data included
  if (FMaxEarlyData > 0) and (FSessionStore = nil) and (FSessionTicketKeys = nil) then
    raise EInvalidOperationTlsLibException.CreateRes(@SServerEarlyDataNeedsTickets);
  // the default keys and the lifetime shape only the tickets this server issues, and TLS 1.2 still issues
  if not (TArrayUtilities.Contains<UInt16>(FSupportedVersions, TlsWireVersionTls12)) and
    (FWantDefaultSessionTicketKeys or (FTicketLifetimeSeconds <> DefaultTicketLifetimeSeconds)) then
    raise EInvalidOperationTlsLibException.CreateRes(@SServerSettingNeedsTickets);
end;

procedure TTlsConfigBuilder.ValidateClientCertificateAuthoritiesFit;
var
  LI: Int32;
  LNames: Int32;
  LRoom: Int32;
begin
  if (System.Length(FClientCertificateAuthorities) = 0) or
    not (TArrayUtilities.Contains<UInt16>(FSupportedVersions, TlsWireVersionTls13)) then
    Exit;
  LNames := 0;
  for LI := 0 to System.High(FClientCertificateAuthorities) do
    Inc(LNames, 2 + System.Length(FClientCertificateAuthorities[LI]));
  // each extension adds a 4-byte header and its list length (2, 1, 2 bytes); a scheme or algorithm is 2
  LRoom := MaxCertificateRequestExtensionsBytes - (4 + 2 + 2 * System.Length(FSignatureSchemes.Items)) -
    (4 + 2);
  if System.Length(FCertificateDecompressors) > 0 then
    Dec(LRoom, 4 + 1 + 2 * System.Length(FCertificateDecompressors));
  if LNames > LRoom then
    raise EInvalidOperationTlsLibException.CreateResFmt(@SCertificateAuthoritiesNeedRoom,
      [LNames, LRoom]);
end;

function TTlsConfigBuilder.WithCipherSuites(
  const ARegistry: ICipherSuiteRegistry): TTlsConfigBuilder;
begin
  GuardMutable;
  FCipherSuites := ARegistry;
  Result := Self;
end;

function TTlsConfigBuilder.WithCipherSuiteList(
  const ASuites: TArray<UInt16>): TTlsConfigBuilder;
begin
  GuardMutable;
  // an empty list would read as "no list", silently leaving the preset's full set in force
  if System.Length(ASuites) = 0 then
    raise EArgumentTlsLibException.CreateRes(@SCipherSuiteListEmpty);
  FCipherSuiteList := System.Copy(ASuites);
  Result := Self;
end;

function TTlsConfigBuilder.WithSignatureSchemes(
  const ARegistry: ISignatureSchemeRegistry): TTlsConfigBuilder;
begin
  GuardMutable;
  FSignatureSchemes := ARegistry;
  Result := Self;
end;

function TTlsConfigBuilder.WithNamedGroups(
  const ARegistry: INamedGroupRegistry): TTlsConfigBuilder;
begin
  GuardMutable;
  FNamedGroups := ARegistry;
  Result := Self;
end;

function TTlsConfigBuilder.WithSupportedVersions(
  const AVersions: TArray<UInt16>): TTlsConfigBuilder;
var
  LI, LJ: Int32;
begin
  GuardMutable;
  // the offered set is a non-empty, duplicate-free preference list of negotiable versions; the
  // factory only builds TLS 1.3/1.2, so anything else would silently fall through to a nil-registry
  // 1.2 machine (RFC 9846 4.3.1)
  if System.Length(AVersions) = 0 then
    raise EArgumentTlsLibException.CreateRes(@SNoSupportedVersions);
  for LI := 0 to System.High(AVersions) do
  begin
    if (AVersions[LI] <> TlsWireVersionTls13) and (AVersions[LI] <> TlsWireVersionTls12) then
      raise EArgumentTlsLibException.CreateResFmt(@SUnsupportedVersion, [AVersions[LI]]);
    for LJ := LI + 1 to System.High(AVersions) do
      if AVersions[LJ] = AVersions[LI] then
        raise EArgumentTlsLibException.CreateRes(@SDuplicateVersion);
  end;
  FSupportedVersions := System.Copy(AVersions);
  Result := Self;
end;

function TTlsConfigBuilder.WithPreferredGroups(
  const AGroups: TArray<UInt16>): TTlsConfigBuilder;
var
  LI, LJ: Int32;
begin
  GuardMutable;
  // supported_groups must not repeat a group (RFC 9846 4.3.7)
  for LI := 0 to System.High(AGroups) do
    for LJ := LI + 1 to System.High(AGroups) do
      if AGroups[LJ] = AGroups[LI] then
        raise EArgumentTlsLibException.CreateRes(@SDuplicatePreferredGroup);
  // copy so a caller mutating its array after Build cannot alter the frozen config
  FPreferredGroups := System.Copy(AGroups);
  Result := Self;
end;

function TTlsConfigBuilder.WithAlpnProtocols(
  const AProtocols: TArray<TBytes>): TTlsConfigBuilder;
var
  LI, LJ, LWireLength: Int32;
begin
  GuardMutable;
  LWireLength := 0;
  // an empty list offers no ALPN; otherwise each name is one non-empty ProtocolName<1..2^8-1> (RFC
  // 7301 3.1) and a duplicate is refused as a misconfiguration - so we never offer a list our own
  // decoder would refuse
  for LI := 0 to System.High(AProtocols) do
  begin
    if System.Length(AProtocols[LI]) = 0 then
      raise EArgumentTlsLibException.CreateRes(@SAlpnProtocolEmpty);
    if System.Length(AProtocols[LI]) > 255 then
      raise EArgumentTlsLibException.CreateRes(@SAlpnProtocolTooLong);
    // the list shares the one 64 KiB extensions block of the ClientHello with the key shares,
    // groups, signature schemes and any resumption ticket, so it is held well below that; each
    // name costs its length byte too
    Inc(LWireLength, 1 + System.Length(AProtocols[LI]));
    if LWireLength > MaxAlpnListBytes then
      raise EArgumentTlsLibException.CreateRes(@SAlpnListTooLong);
    for LJ := LI + 1 to System.High(AProtocols) do
      if TArrayUtilities.AreEqual(AProtocols[LJ], AProtocols[LI]) then
        raise EArgumentTlsLibException.CreateRes(@SAlpnProtocolDuplicate);
  end;
  // the names are copied so a caller reusing its arrays cannot change a frozen config
  FAlpnProtocols := TArrayUtilities.DeepCopy<Byte>(AProtocols);
  Result := Self;
end;

function TTlsConfigBuilder.WithRecordSizeLimit(ALimit: Int32): TTlsConfigBuilder;
begin
  GuardMutable;
  // 0 offers nothing; 16384 is the library's cap, so one bound is legal under both TLS 1.3
  // (2^14+1, counted as TLSInnerPlaintext) and 1.2 (2^14) in a dual-version config (RFC 8449 4)
  if (ALimit <> 0) and ((ALimit < 64) or (ALimit > 16384)) then
    raise EArgumentTlsLibException.CreateRes(@SRecordSizeLimitRange);
  FRecordSizeLimit := ALimit;
  Result := Self;
end;

function TTlsConfigBuilder.HasAnchorRoots: Boolean;
var
  LStore: ITrustAnchorStore;
begin
  // fail closed: no store, or a composed store left with no anchor (a distrusted root is not one),
  // counts as no source
  LStore := ComposeTrustStore;
  Result := (LStore <> nil) and (LStore.AnchorCount > 0);
end;

function TTlsConfigBuilder.SignatureSchemesDifferFromBaseline: Boolean;
var
  LBase, LCurrent: TArray<UInt16>;
  LI: Int32;
begin
  Result := False;
  if (FBaseline.SignatureSchemes = nil) or (FSignatureSchemes = nil) then
    Exit;
  LBase := TSignatureSchemeCodes.FromRegistry(FBaseline.SignatureSchemes);
  LCurrent := TSignatureSchemeCodes.FromRegistry(FSignatureSchemes);
  if System.Length(LBase) <> System.Length(LCurrent) then
    Exit(True);
  for LI := 0 to System.High(LBase) do
    if LBase[LI] <> LCurrent[LI] then
      Exit(True);
end;

function TTlsConfigBuilder.ComposeTrustStore: ITrustAnchorStore;
begin
  if System.Length(FAnchorStores) = 0 then
    Exit(nil);
  if FComposedTrust = nil then
    FComposedTrust := TTrustAnchorStore.Union(FAnchorStores);
  Result := FComposedTrust;
end;

procedure TTlsConfigBuilder.ValidateAnchorRoots;
var
  LI, LJ: Int32;
  LRoots: TArray<TBytes>;
begin
  for LI := 0 to System.High(FAnchorStores) do
  begin
    if FAnchorStores[LI] = nil then
      Continue;
    LRoots := FAnchorStores[LI].RootCertificates;
    for LJ := 0 to System.High(LRoots) do
      if not FPkix.Certificates.IsWellFormed(LRoots[LJ]) then
        raise EInvalidOperationTlsLibException.CreateResFmt(@SMalformedTrustAnchor, [LJ, LI]);
  end;
end;

function TTlsConfigBuilder.WithCertificateChainLimits(
  const ALimits: TCertificateChainLimits): TTlsConfigBuilder;
begin
  GuardMutable;
  // a resource budget, not a trust input, but a broken one (non-positive, per-cert above the whole
  // message, a total past the 24-bit handshake-message ceiling that would wrap the derived
  // reassembly cap, or an entry count outside 1..255) is a misconfiguration, refused at build time
  if (ALimits.MaxCertificateLength <= 0) or (ALimits.MaxTotalChainLength <= 0) or
    (ALimits.MaxCertificateLength > ALimits.MaxTotalChainLength) or
    (ALimits.MaxTotalChainLength > $FFFFFF) or
    (ALimits.MaxChainCertificates < 1) or (ALimits.MaxChainCertificates > 255) then
    raise EArgumentTlsLibException.CreateRes(@SInvalidChainLimits);
  FChainLimits := ALimits;
  Result := Self;
end;

class function TTlsConfigBuilder.CloneCredential(
  const ACredential: TTlsCredential): TTlsCredential;
begin
  Result := ACredential;
  Result.CertificateChain := TArrayUtilities.DeepCopy<Byte>(ACredential.CertificateChain);
  Result.OcspStaple := System.Copy(ACredential.OcspStaple);
end;

class function TTlsConfigBuilder.CloneExternalPsks(
  const APsks: TArray<TExternalPsk>): TArray<TExternalPsk>;
var
  LI: Int32;
begin
  Result := System.Copy(APsks);
  for LI := 0 to System.High(Result) do
  begin
    Result[LI].Identity := System.Copy(APsks[LI].Identity);
    Result[LI].Context := System.Copy(APsks[LI].Context);
  end;
end;

function TTlsConfigBuilder.WithCredential(
  const ACredential: TTlsCredential): TTlsConfigBuilder;
begin
  GuardMutable;
  FCredential := TTlsConfigBuilder.CloneCredential(ACredential);
  FHasCredential := True;
  Result := Self;
end;

function TTlsConfigBuilder.WithSniCredential(const AHost: string;
  const ACredential: TTlsCredential): TTlsConfigBuilder;
var
  LEntry: TSniCredentialEntry;
begin
  GuardMutable;
  LEntry.Host := AHost;
  LEntry.Credential := TTlsConfigBuilder.CloneCredential(ACredential);
  TArrayUtilities.Append<TSniCredentialEntry>(FSniCredentialEntries, LEntry);
  Result := Self;
end;

function TTlsConfigBuilder.WithCredentialResolver(
  const AResolver: ITlsServerCredentialResolver): TTlsConfigBuilder;
begin
  GuardMutable;
  FCredentialResolver := AResolver;
  Result := Self;
end;

procedure TTlsConfigBuilder.ValidateSniEntryCoversHost(const AHost: string;
  const ACredential: TTlsCredential);
var
  LSans: TArray<string>;
  LOk: Boolean;
  LI: Integer;
begin
  if System.Length(ACredential.CertificateChain) = 0 then
    raise EInvalidOperationTlsLibException.CreateResFmt(@SSniCertMissing, [AHost]);
  LSans := FPkix.Certificates.DnsNames(ACredential.CertificateChain[0]);
  if Pos('*', AHost) = 0 then
    // an exact host must be covered by the leaf's dNSName SANs (RFC 9525)
    LOk := TEndpointIdentity.Matches(TServerName.DnsName(AHost), LSans, nil)
  else
  begin
    // only a runtime-matchable pattern is accepted - a single left-most-label wildcard that
    // leaves at least two labels below it (never *.com), the same rule the matcher enforces, so
    // a registered pattern and name verification can never disagree (RFC 9525)
    if not TEndpointIdentity.IsMatchableDnsPattern(AHost) then
      raise EInvalidOperationTlsLibException.CreateResFmt(@SSniWildcardMalformed, [AHost]);
    // a wildcard entry needs the leaf to carry that same wildcard SAN
    LOk := False;
    for LI := 0 to System.High(LSans) do
      if SameText(LSans[LI], AHost) then
      begin
        LOk := True;
        Break;
      end;
  end;
  if not LOk then
    raise EInvalidOperationTlsLibException.CreateResFmt(@SSniCertMismatch, [AHost]);
end;

procedure TTlsConfigBuilder.ValidateCredentialConsistency(
  const ACredential: TTlsCredential);
var
  LLeaf, LKeyPublicKeyInfo: TBytes;
  LSchemes: TArray<TSignatureScheme>;
begin
  // an empty chain would emit an empty certificate_list (RFC 9846 4.5.1) and a missing key
  // cannot sign, so either is refused here rather than failing mid-handshake
  if System.Length(ACredential.CertificateChain) = 0 then
    raise EInvalidOperationTlsLibException.CreateRes(@SCredentialChainEmpty);
  if ACredential.PrivateKey = nil then
    raise EInvalidOperationTlsLibException.CreateRes(@SCredentialKeyMissing);
  LLeaf := ACredential.CertificateChain[0];
  // a definite No means the leaf may not sign a CertificateVerify; an absent or unreadable
  // keyUsage passes (the peer-side signing-policy check is the backstop)
  if FPkix.Certificates.KeyUsagePermits(LLeaf, TCertKeyUsage.DigitalSignature) = TCertAnswer.No
  then
    raise EInvalidOperationTlsLibException.CreateRes(@SCredentialLeafCannotSign);
  // an id-RSASSA-PSS leaf key pairs only with rsa_pss_pss_*, which this library does not offer,
  // so it is unusable even when the private key matches it (the key-value match below would pass)
  LSchemes := ACredential.PrivateKey.CapableSchemes;
  if (System.Length(LSchemes) > 0) and (LSchemes[0].KeyKind = TSignatureKeyKind.Rsa) and
    (FPkix.Certificates.KeyIsRsaPss(LLeaf) = TCertAnswer.Yes) then
    raise EInvalidOperationTlsLibException.CreateRes(@SCredentialLeafRsaPssUnsupported);
  // the private key must own the leaf: match the key's public half against the leaf's, with no
  // signing operation. A key that cannot export its public half fails closed. The value compare
  // also catches a mis-ordered chain whose first certificate is not the one that pairs with the key
  LKeyPublicKeyInfo := ACredential.PrivateKey.PublicKeyInfo;
  if System.Length(LKeyPublicKeyInfo) = 0 then
    raise EInvalidOperationTlsLibException.CreateRes(@SCredentialKeyNotExportable);
  if FPkix.Certificates.SamePublicKey(FPkix.Certificates.PublicKeyInfo(LLeaf),
    LKeyPublicKeyInfo) <> TCertAnswer.Yes then
    raise EInvalidOperationTlsLibException.CreateRes(@SCredentialKeyLeafMismatch);
end;

function TTlsConfigBuilder.ComposeCredentialResolver: ITlsServerCredentialResolver;
var
  LI, LJ: Integer;
begin
  if FCredentialResolver <> nil then
  begin
    // a custom resolver takes full control; mixing it with the built-in map is a config error
    if FHasCredential or (System.Length(FSniCredentialEntries) > 0) then
      raise EInvalidOperationTlsLibException.CreateRes(@SSniResolverConflict);
    Exit(FCredentialResolver);
  end;
  // a PSK-only server presents no certificate, so it needs no resolver
  if (System.Length(FSniCredentialEntries) = 0) and (not FHasCredential) then
    Exit(nil);
  for LI := 0 to System.High(FSniCredentialEntries) do
  begin
    for LJ := 0 to LI - 1 do
      if SameText(FSniCredentialEntries[LJ].Host, FSniCredentialEntries[LI].Host) then
        raise EInvalidOperationTlsLibException.CreateResFmt(@SSniDuplicateHost,
          [FSniCredentialEntries[LI].Host]);
    ValidateSniEntryCoversHost(FSniCredentialEntries[LI].Host,
      FSniCredentialEntries[LI].Credential);
    // name the offending host, since a server may carry several SNI credentials
    try
      ValidateCredentialConsistency(FSniCredentialEntries[LI].Credential);
    except
      on E: EInvalidOperationTlsLibException do
        raise EInvalidOperationTlsLibException.CreateResFmt(@SSniCredentialInvalid,
          [FSniCredentialEntries[LI].Host, E.Message]);
    end;
  end;
  // the single credential (WithCredential), if any, is the no-SNI / no-match default
  if FHasCredential then
  begin
    ValidateCredentialConsistency(FCredential);
    Result := TSniCredentialResolver.Create(FSniCredentialEntries, FCredential)
      as ITlsServerCredentialResolver;
  end
  else
    Result := TSniCredentialResolver.Create(FSniCredentialEntries)
      as ITlsServerCredentialResolver;
end;

function TTlsConfigBuilder.ComposeServerVerifierSource: IServerCertificateVerifierSource;
begin
  // a custom source (the OS delegate) wins; else a whole-verifier instance wrapped as a
  // source; else the built-in PKIX source
  if FServerVerifierSource <> nil then
    Exit(FServerVerifierSource);
  if FServerCertVerifier <> nil then
    Exit(TInstanceServerVerifierSource.Create(FServerCertVerifier)
      as IServerCertificateVerifierSource);
  Result := TBuiltInServerVerifierSource.Create as IServerCertificateVerifierSource;
end;

function TTlsConfigBuilder.ComposeClientVerifierSource: IClientCertificateVerifierSource;
begin
  // a custom source (the OS delegate over the client-CA anchors) wins; else a whole-verifier
  // instance wrapped as a source; else the built-in PKIX source
  if FClientVerifierSource <> nil then
    Exit(FClientVerifierSource);
  if FClientCertVerifier <> nil then
    Exit(TInstanceClientVerifierSource.Create(FClientCertVerifier)
      as IClientCertificateVerifierSource);
  Result := TBuiltInClientVerifierSource.Create as IClientCertificateVerifierSource;
end;

function TTlsConfigBuilder.WithCertificateCompressors(
  const ACompressors: TArray<ICertificateCompressor>): TTlsConfigBuilder;
begin
  GuardMutable;
  TCertificateCompression.ValidateCompressors(ACompressors);
  // copy so a caller mutating its array after Build cannot alter the frozen config
  FCertificateCompressors := System.Copy(ACompressors);
  FCompressorsSet := True;
  Result := Self;
end;

function TTlsConfigBuilder.WithCertificateDecompressors(
  const ADecompressors: TArray<ICertificateDecompressor>): TTlsConfigBuilder;
begin
  GuardMutable;
  TCertificateCompression.ValidateDecompressors(ADecompressors);
  FCertificateDecompressors := System.Copy(ADecompressors);
  FDecompressorsSet := True;
  Result := Self;
end;

function TTlsConfigBuilder.WithEch(const AMode: IEchClientMode): TTlsConfigBuilder;
begin
  GuardMutable;
  if AMode = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilEchMode);
  FEchMode := AMode;
  Result := Self;
end;

function TTlsConfigBuilder.WithCertificateCompressionCache(
  const ACache: ICertificateCompressionCache): TTlsConfigBuilder;
begin
  GuardMutable;
  FCertificateCompressionCache := ACache;
  Result := Self;
end;

function TTlsConfigBuilder.WithExtendedMasterSecret(
  ARequire: Boolean): TTlsConfigBuilder;
begin
  GuardMutable;
  FRequireExtendedMasterSecret := ARequire;
  Result := Self;
end;

function TTlsConfigBuilder.WithNonEmsResumption(
  AMode: TNonEmsResumption): TTlsConfigBuilder;
begin
  GuardMutable;
  FNonEmsResumption := AMode;
  Result := Self;
end;

function TTlsConfigBuilder.WithServerNameAcknowledgement(
  ASend: Boolean): TTlsConfigBuilder;
begin
  GuardMutable;
  FServerNameAck := ASend;
  Result := Self;
end;

function TTlsConfigBuilder.WithCipherSuitePreference(
  APreference: TServerCipherPreference): TTlsConfigBuilder;
begin
  GuardMutable;
  FCipherPreference := APreference;
  Result := Self;
end;

function TTlsConfigBuilder.WithAlpnRejection(AReject: Boolean): TTlsConfigBuilder;
begin
  GuardMutable;
  FAlpnRejectAll := AReject;
  Result := Self;
end;

function TTlsConfigBuilder.WithClientCertificateAuthorities(
  const AAuthorities: TArray<TBytes>): TTlsConfigBuilder;
var
  LI: Int32;
  LWireLength: Int32;
begin
  GuardMutable;
  LWireLength := 0;
  // a name over the list cap also overflows its own 2-byte length, so there is no per-name bound
  for LI := 0 to System.High(AAuthorities) do
  begin
    if System.Length(AAuthorities[LI]) = 0 then
      raise EArgumentTlsLibException.CreateRes(@SCertificateAuthorityEmpty);
    if System.Length(AAuthorities[LI]) > MaxCertificateAuthoritiesBytes - LWireLength - 2 then
      raise EArgumentTlsLibException.CreateRes(@SCertificateAuthoritiesTooLong);
    Inc(LWireLength, 2 + System.Length(AAuthorities[LI]));
  end;
  FClientCertificateAuthorities := TArrayUtilities.DeepCopy<Byte>(AAuthorities);
  Result := Self;
end;

function TTlsConfigBuilder.WithGrease(AEnable: Boolean): TTlsConfigBuilder;
begin
  GuardMutable;
  FGrease := AEnable;
  Result := Self;
end;

function TTlsConfigBuilder.WithDangerousDisableServerNameCheck: TTlsConfigBuilder;
begin
  GuardMutable;
  FCheckServerName := False;
  Result := Self;
end;

function TTlsConfigBuilder.WithServerNameIndication(
  AMode: TServerNameIndication): TTlsConfigBuilder;
begin
  GuardMutable;
  FServerNameIndication := AMode;
  Result := Self;
end;

function TTlsConfigBuilder.WithOcspStaplingRequest(
  AEnabled: Boolean): TTlsConfigBuilder;
begin
  GuardMutable;
  FRequestOcspStapling := AEnabled;
  Result := Self;
end;

function TTlsConfigBuilder.WithPeerAuth(AMode: TClientAuthMode): TTlsConfigBuilder;
begin
  GuardMutable;
  FClientAuth := AMode;
  Result := Self;
end;

function TTlsConfigBuilder.WithCertificatePinning(
  const APins: TArray<TBytes>): TTlsConfigBuilder;
var
  LI: Int32;
begin
  GuardMutable;
  // a pin is a SHA-256 SubjectPublicKeyInfo digest (32 bytes); a wrong-width value can never
  // match, so it is a misconfiguration refused here rather than failing every handshake silently
  for LI := 0 to System.High(APins) do
    if System.Length(APins[LI]) <> 32 then
      raise EArgumentTlsLibException.CreateRes(@SInvalidCertificatePin);
  FCertificatePins := TArrayUtilities.DeepCopy<Byte>(APins);
  Result := Self;
end;

function TTlsConfigBuilder.WithServerVerification(
  const AVerification: IServerVerification): TTlsConfigBuilder;
begin
  GuardMutable;
  if AVerification = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilVerification);
  FServerVerification := AVerification;
  Result := Self;
end;

function TTlsConfigBuilder.WithClientVerification(
  const AVerification: IClientVerification): TTlsConfigBuilder;
begin
  GuardMutable;
  if AVerification = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilVerification);
  FClientVerification := AVerification;
  Result := Self;
end;

procedure TTlsConfigBuilder.ApplyTrustData(const AVerification: ITrustVerification);
var
  LBlob, LCert: TBytes;
begin
  // derived afresh on every Build, so a Build that failed can be corrected and retried
  FAnchorStores := AVerification.AnchorStores;
  for LBlob in AVerification.AnchorData do
    TArrayUtilities.Append<ITrustAnchorStore>(FAnchorStores,
      TTrustAnchorStore.Create(FPkix.Certificates.LoadChain(LBlob)) as ITrustAnchorStore);
  FComposedTrust := nil;
  FIntermediateCertificates := nil;
  for LBlob in AVerification.IntermediateData do
    for LCert in FPkix.Certificates.LoadChain(LBlob) do
      TArrayUtilities.Append<TBytes>(FIntermediateCertificates, LCert);
  FStrengthPolicy := AVerification.StrengthPolicy;
  FRevocationPosture := AVerification.RevocationPosture;
  FDangerousTrust.InsecureSkipVerify := AVerification.Kind = TVerificationKind.DangerousSkip;
  FServerCertVerifier := nil;
  FServerVerifierSource := nil;
  FClientCertVerifier := nil;
  FClientVerifierSource := nil;
  // an injected verifier does not apply the posture, so Hard needs the live verdict
  if (AVerification.Kind = TVerificationKind.Custom) and
    (AVerification.RevocationPosture = TRevocationPosture.Hard) and
    (FAsyncVerdict.Deferral <> TVerdictDeferral.LiveRevocation) then
    raise EInvalidOperationTlsLibException.CreateRes(@SCustomHardNeedsLiveVerdict);
end;

function TTlsConfigBuilder.WithCertificateVerifyCallback(
  const ACallback: TTlsCertificateVerifyCallback): TTlsConfigBuilder;
begin
  GuardMutable;
  FDangerousTrust.VerifyCallback := ACallback;
  Result := Self;
end;

function TTlsConfigBuilder.WithAsyncCertificateVerdict(
  ADeadlineMs: Cardinal): TTlsConfigBuilder;
begin
  GuardMutable;
  if FAsyncVerdict.Deferral = TVerdictDeferral.LiveRevocation then
    raise EInvalidOperationTlsLibException.CreateRes(@SVerdictSlotConflict);
  FAsyncVerdict.Deferral := TVerdictDeferral.HostDecision;
  FAsyncVerdict.DeadlineMs := ADeadlineMs;
  Result := Self;
end;

function TTlsConfigBuilder.WithLiveRevocationVerdict(
  ADeadlineMs: Cardinal): TTlsConfigBuilder;
begin
  GuardMutable;
  if FAsyncVerdict.Deferral = TVerdictDeferral.HostDecision then
    raise EInvalidOperationTlsLibException.CreateRes(@SVerdictSlotConflict);
  FAsyncVerdict.Deferral := TVerdictDeferral.LiveRevocation;
  FAsyncVerdict.DeadlineMs := ADeadlineMs;
  Result := Self;
end;

function TTlsConfigBuilder.WithResumption(AEnabled: Boolean): TTlsConfigBuilder;
begin
  GuardMutable;
  FResumption := AEnabled;
  Result := Self;
end;

function TTlsConfigBuilder.WithResumeVerification(
  AMode: TResumeVerification): TTlsConfigBuilder;
begin
  GuardMutable;
  FResumeVerification := AMode;
  Result := Self;
end;

function TTlsConfigBuilder.WithSessionCache(
  const ACache: ISessionCache): TTlsConfigBuilder;
begin
  GuardMutable;
  // the scope is set independently (WithSessionScope), so this never clears it: the two setters are
  // order-insensitive and BuildClient mints a fresh scope only when none was pinned
  FSessionCache := ACache;
  Result := Self;
end;

function TTlsConfigBuilder.WithSessionScope(
  const AScope: TBytes): TTlsConfigBuilder;
begin
  GuardMutable;
  if System.Length(AScope) > MaxResumptionScopeLength then
    raise EArgumentTlsLibException.CreateRes(@SResumptionScopeTooLong);
  FSessionScope := System.Copy(AScope);
  Result := Self;
end;

function TTlsConfigBuilder.WithClock(
  const AClock: ITlsClock): TTlsConfigBuilder;
begin
  GuardMutable;
  if AClock = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilClock);
  FClock := AClock;
  Result := Self;
end;

function TTlsConfigBuilder.WithMonotonicClock(
  const AClock: ITlsMonotonicClock): TTlsConfigBuilder;
begin
  GuardMutable;
  if AClock = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilMonotonicClock);
  FMonotonicClock := AClock;
  Result := Self;
end;

function TTlsConfigBuilder.WithDangerousKeyLog(
  const AKeyLog: IKeyLog): TTlsConfigBuilder;
begin
  GuardMutable;
  FKeyLog := AKeyLog;
  Result := Self;
end;

function TTlsConfigBuilder.WithExternalPreSharedKeys(
  const APsks: TArray<TExternalPsk>): TTlsConfigBuilder;
begin
  GuardMutable;
  ValidateExternalPsks(APsks);
  // copy so a caller mutating its arrays after Build cannot alter the frozen config (matches the
  // frozen ExternalPsks accessor); the PSK secrets are ISecretBuffer, shared by reference
  FExternalPsks := TTlsConfigBuilder.CloneExternalPsks(APsks);
  Result := Self;
end;

function TTlsConfigBuilder.WithExternalPskRequired(
  AEnabled: Boolean): TTlsConfigBuilder;
begin
  GuardMutable;
  FExternalPskRequired := AEnabled;
  Result := Self;
end;

class function TTlsConfigBuilder.CloneTls12Psks(
  const APsks: TArray<TTls12Psk>): TArray<TTls12Psk>;
var
  LI: Int32;
begin
  Result := System.Copy(APsks);
  for LI := 0 to System.High(Result) do
    Result[LI].Identity := System.Copy(APsks[LI].Identity);
end;

class procedure TTlsConfigBuilder.ValidatePskEntry(const AIdentity: TBytes;
  const ASecret: ISecretBuffer);
begin
  if (System.Length(AIdentity) = 0) or (System.Length(AIdentity) > High(UInt16)) then
    raise EArgumentTlsLibException.CreateRes(@SPskIdentityLength);
  if (ASecret = nil) or (ASecret.Len = 0) then
    raise EArgumentTlsLibException.CreateRes(@SPskSecretEmpty);
end;

class procedure TTlsConfigBuilder.ValidateTls12Psks(const APsks: TArray<TTls12Psk>);
var
  LI, LJ: Int32;
begin
  for LI := 0 to System.High(APsks) do
  begin
    ValidatePskEntry(APsks[LI].Identity, APsks[LI].Secret);
    if APsks[LI].Secret.Len > High(UInt16) then
      raise EArgumentTlsLibException.CreateRes(@STls12PskSecretLength);
    for LJ := 0 to LI - 1 do
      if TArrayUtilities.AreEqual(APsks[LI].Identity, APsks[LJ].Identity) then
        raise EArgumentTlsLibException.CreateRes(@STls12PskDuplicateIdentity);
  end;
end;

class procedure TTlsConfigBuilder.ValidateExternalPsks(const APsks: TArray<TExternalPsk>);
var
  LI, LJ: Int32;
begin
  for LI := 0 to System.High(APsks) do
  begin
    ValidatePskEntry(APsks[LI].Identity, APsks[LI].Secret);
    // an imported identity that cannot be encoded would fail every accept and every offer
    if (System.Length(APsks[LI].Context) > High(UInt16)) or
      (System.Length(TExternalPskImporter.ImportedIdentity(APsks[LI].Identity,
      APsks[LI].Context, TlsWireVersionTls13, 0)) > High(UInt16)) then
      raise EArgumentTlsLibException.CreateRes(@SExternalPskIdentityTooLong);
    // RFC 9258 5.1: the context is part of the imported identity, so only both together collide
    for LJ := 0 to LI - 1 do
      if TArrayUtilities.AreEqual(APsks[LI].Identity, APsks[LJ].Identity) and
        TArrayUtilities.AreEqual(APsks[LI].Context, APsks[LJ].Context) then
        raise EArgumentTlsLibException.CreateRes(@SExternalPskDuplicateIdentity);
  end;
end;

function TTlsConfigBuilder.WithTls12PskSuites(
  const ABase: ICipherSuiteRegistry): ICipherSuiteRegistry;
var
  LPsk, LSuite: TTlsCipherSuite;
  LJoined: ICipherSuiteRegistryBuilder;
begin
  Result := ABase;
  if System.Length(FTls12Psks) = 0 then
    Exit;
  // the TLS 1.3 suites, then the PSK suites, then the TLS 1.2 certificate suites: the PSK suites
  // lead the TLS 1.2 order, as a matching PSK outranks the certificate in TLS 1.3 too
  LJoined := TCipherSuiteRegistryBuilder.Create as ICipherSuiteRegistryBuilder;
  for LSuite in ABase.Items do
    if LSuite.Protocol = TSuiteProtocol.Tls13 then
      LJoined.Add(LSuite);
  for LPsk in TCipherSuiteRegistry.CreateTls12Psk(FCrypto).Items do
    LJoined.Add(LPsk);
  for LSuite in ABase.Items do
    if LSuite.Protocol = TSuiteProtocol.Tls12 then
      LJoined.Add(LSuite);
  Result := LJoined.Build;
end;

function TTlsConfigBuilder.WithTls12PreSharedKeys(
  const APsks: TArray<TTls12Psk>): TTlsConfigBuilder;
begin
  GuardMutable;
  ValidateTls12Psks(APsks);
  // copied so a caller mutating its arrays after Build cannot alter the frozen config; the
  // secrets are ISecretBuffer, shared by reference
  FTls12Psks := TTlsConfigBuilder.CloneTls12Psks(APsks);
  Result := Self;
end;

function TTlsConfigBuilder.WithTls12PskIdentityHint(
  const AHint: TBytes): TTlsConfigBuilder;
begin
  GuardMutable;
  if System.Length(AHint) > High(UInt16) then
    raise EArgumentTlsLibException.CreateRes(@STls12PskHintLength);
  FTls12PskIdentityHint := System.Copy(AHint);
  Result := Self;
end;

function TTlsConfigBuilder.WithTls12PreSharedKeyRequired(
  AEnabled: Boolean): TTlsConfigBuilder;
begin
  GuardMutable;
  FTls12PskRequired := AEnabled;
  Result := Self;
end;

function TTlsConfigBuilder.WithSessionStore(
  const AStore: ISessionStore): TTlsConfigBuilder;
begin
  GuardMutable;
  FSessionStore := AStore;
  Result := Self;
end;

function TTlsConfigBuilder.WithSessionTicketKeys(
  const AKeys: ISessionTicketKeyManager): TTlsConfigBuilder;
begin
  GuardMutable;
  if (AKeys <> nil) and FWantDefaultSessionTicketKeys then
    raise EInvalidOperationTlsLibException.CreateRes(@SDefaultKeysBesideExplicitKeys);
  FSessionTicketKeys := AKeys;
  Result := Self;
end;

function TTlsConfigBuilder.WithResumptionScope(
  const AScope: TBytes): TTlsConfigBuilder;
begin
  GuardMutable;
  if System.Length(AScope) > MaxResumptionScopeLength then
    raise EArgumentTlsLibException.CreateRes(@SResumptionScopeTooLong);
  FResumptionScope := System.Copy(AScope);
  Result := Self;
end;

function TTlsConfigBuilder.WithDefaultSessionTicketKeys: TTlsConfigBuilder;
begin
  GuardMutable;
  if FSessionTicketKeys <> nil then
    raise EInvalidOperationTlsLibException.CreateRes(@SDefaultKeysBesideExplicitKeys);
  // request a default STEK minted from THIS builder's provider + clock at BuildServer time
  FWantDefaultSessionTicketKeys := True;
  Result := Self;
end;

function TTlsConfigBuilder.WithTicketLifetime(ASeconds: UInt32): TTlsConfigBuilder;
begin
  GuardMutable;
  if ASeconds > MaxTicketLifetimeSeconds then
    raise EArgumentTlsLibException.CreateRes(@STicketLifetimeTooLong);
  FTicketLifetimeSeconds := ASeconds;
  Result := Self;
end;

function TTlsConfigBuilder.WithTicketCount(ACount: Int32): TTlsConfigBuilder;
begin
  GuardMutable;
  if (ACount < 0) or (ACount > MaxTicketCount) then
    raise EArgumentTlsLibException.CreateRes(@STicketCountOutOfRange);
  FTicketCount := ACount;
  Result := Self;
end;

function TTlsConfigBuilder.WithClientEarlyData(AEnabled: Boolean): TTlsConfigBuilder;
begin
  GuardMutable;
  FClientEarlyData := AEnabled;
  Result := Self;
end;

function TTlsConfigBuilder.WithServerEarlyData(AMaxBytes: UInt32): TTlsConfigBuilder;
begin
  GuardMutable;
  if AMaxBytes >= MaxServerEarlyData then
    raise EArgumentTlsLibException.CreateRes(@SServerEarlyDataTooLarge);
  FMaxEarlyData := AMaxBytes;
  Result := Self;
end;

function TTlsConfigBuilder.WithAntiReplay(
  const AStrategy: IAntiReplayStrategy): TTlsConfigBuilder;
begin
  GuardMutable;
  FAntiReplay := AStrategy;
  Result := Self;
end;

function TTlsConfigBuilder.WithEchKeyStore(
  const AKeyStore: IEchServerKeyStore): TTlsConfigBuilder;
begin
  Result := WithEchKeyStore(AKeyStore, False);
end;

function TTlsConfigBuilder.WithEchKeyStore(const AKeyStore: IEchServerKeyStore;
  ATrialDecrypt: Boolean): TTlsConfigBuilder;
begin
  GuardMutable;
  // a split-mode backend holds no ECH keys, and a keyed (client-facing / shared-mode) server never
  // accepts an inner-type ech: the two roles are mutually exclusive (RFC 9849 sec. 7)
  if (FEchServerPolicy <> nil) and (FEchServerPolicy.Role = TEchServerRole.Backend) then
    raise EInvalidOperationTlsLibException.CreateRes(@SEchBackendWithKeyStore);
  FEchServerPolicy := TEchServerPolicy.Keyed(FCrypto, AKeyStore, ATrialDecrypt);
  Result := Self;
end;

function TTlsConfigBuilder.WithEchBackend: TTlsConfigBuilder;
begin
  GuardMutable;
  if (FEchServerPolicy <> nil) and (FEchServerPolicy.Role = TEchServerRole.Keyed) then
    raise EInvalidOperationTlsLibException.CreateRes(@SEchBackendWithKeyStore);
  FEchServerPolicy := TEchServerPolicy.Backend;
  Result := Self;
end;

function TTlsConfigBuilder.Client13: ITls13ClientConfigFacet;
begin
  Result := TTls13ClientConfigFacet.Create(Self);
end;

function TTlsConfigBuilder.Client12: ITls12ClientConfigFacet;
begin
  Result := TTls12ClientConfigFacet.Create(Self);
end;

function TTlsConfigBuilder.Server13: ITls13ServerConfigFacet;
begin
  Result := TTls13ServerConfigFacet.Create(Self);
end;

function TTlsConfigBuilder.Server12: ITls12ServerConfigFacet;
begin
  Result := TTls12ServerConfigFacet.Create(Self);
end;

function TTlsConfigBuilder.Client: ITlsClientConfigBuilder;
begin
  // one builder configures one endpoint: the other view's settings would be silently dropped
  if FServerViewTaken then
    raise EInvalidOperationTlsLibException.CreateRes(@SBuilderOneEndpoint);
  FClientViewTaken := True;
  Result := TTlsClientConfigBuilder.Create(Self);
end;

function TTlsConfigBuilder.Server: ITlsServerConfigBuilder;
begin
  if FClientViewTaken then
    raise EInvalidOperationTlsLibException.CreateRes(@SBuilderOneEndpoint);
  FServerViewTaken := True;
  Result := TTlsServerConfigBuilder.Create(Self);
end;

function TTlsConfigBuilder.EffectiveCipherSuites: ICipherSuiteRegistry;
var
  LBase: ICipherSuiteRegistry;
  LNarrowed: ICipherSuiteRegistryBuilder;
  LProtocol: TSuiteProtocol;
  LSuite: TTlsCipherSuite;
  LNamed, LOffered: Boolean;
  LVersion: UInt16;
  LI: Int32;
begin
  // a configured TLS 1.2 PSK brings its suites in; a list may then name them like any other
  LBase := WithTls12PskSuites(FCipherSuites);
  if System.Length(FCipherSuiteList) = 0 then
    Exit(LBase);
  LOffered := False;
  for LI := 0 to System.High(FCipherSuiteList) do
  begin
    if not LBase.TryGet(FCipherSuiteList[LI], LSuite) then
      raise EArgumentTlsLibException.CreateResFmt(@SCipherSuiteNotConfigured,
        [TCipherSuiteCatalog.Name(FCipherSuiteList[LI])]);
    for LVersion in FSupportedVersions do
      if TNegotiationPolicy.ProtocolOf(LVersion) = LSuite.Protocol then
        LOffered := True;
  end;
  // a mixed list is a host's shared list, but one with nothing for the offered versions is dead
  if not LOffered then
    raise EArgumentTlsLibException.CreateRes(@SCipherSuiteListNotOffered);
  LNarrowed := TCipherSuiteRegistryBuilder.Create as ICipherSuiteRegistryBuilder;
  for LProtocol := TSuiteProtocol.Tls13 downto TSuiteProtocol.Tls12 do
  begin
    LNamed := False;
    for LI := 0 to System.High(FCipherSuiteList) do
      if LBase.TryGet(FCipherSuiteList[LI], LSuite) and (LSuite.Protocol = LProtocol) then
      begin
        LNamed := True;
        LNarrowed.Add(LSuite);
      end;
    if not LNamed then
      for LSuite in LBase.Items do
        if LSuite.Protocol = LProtocol then
          LNarrowed.Add(LSuite);
  end;
  Result := LNarrowed.Build;
end;

procedure TTlsConfigBuilder.ValidateOfferedVersionsHaveSuites(const ASuites: ICipherSuiteRegistry);
var
  LI: Int32;
  LName: string;
  LSuite: TTlsCipherSuite;
  LHasPskSuite: Boolean;
begin
  for LI := 0 to System.High(FSupportedVersions) do
    if System.Length(TNegotiationPolicy.SuiteOrder(ASuites,
      TNegotiationPolicy.ProtocolOf(FSupportedVersions[LI]))) = 0 then
    begin
      if FSupportedVersions[LI] = TlsWireVersionTls13 then
        LName := 'TLS 1.3'
      else
        LName := 'TLS 1.2';
      raise EArgumentTlsLibException.CreateResFmt(@SNoSuiteForVersion, [LName, LName]);
    end;
  // a cipher-suite list that names no PSK suite leaves a configured TLS 1.2 PSK unusable
  if System.Length(FTls12Psks) > 0 then
  begin
    LHasPskSuite := False;
    for LSuite in ASuites.Items do
      if LSuite.Auth = TAuthMethod.Psk then
        LHasPskSuite := True;
    if not LHasPskSuite then
      raise EArgumentTlsLibException.CreateRes(@STls12PskNeedsSuite);
  end;
end;

procedure TTlsConfigBuilder.ValidateRequiredCollaborators;
var
  LI: Int32;
  LGroup: INamedGroup;
  LAnyRegistered, LEcdheRegistered: Boolean;
begin
  if (FCipherSuites = nil) or (FSignatureSchemes = nil) or (FNamedGroups = nil) then
    raise EArgumentTlsLibException.CreateRes(@SNilNegotiationRegistry);
  ValidateOfferedVersionsHaveSuites(EffectiveCipherSuites);
  if System.Length(FPreferredGroups) = 0 then
    raise EArgumentTlsLibException.CreateRes(@SNoPreferredGroups);
  // a preferred group the registry lacks is skipped (the registry is authoritative, so a pruned
  // registry may keep a wider preference list), but with none registered no group could ever be
  // selected and every handshake would fail
  LAnyRegistered := False;
  LEcdheRegistered := False;
  for LI := 0 to System.High(FPreferredGroups) do
    if FNamedGroups.TryGet(FPreferredGroups[LI], LGroup) then
    begin
      LAnyRegistered := True;
      if LGroup.Kind = TNamedGroupKind.Ecdhe then
        LEcdheRegistered := True;
    end;
  if not LAnyRegistered then
    raise EArgumentTlsLibException.CreateRes(@SNoRegisteredPreferredGroup);
  // TLS 1.2 key exchange is classical ECDHE only (KEM and hybrid groups are 1.3-only)
  if (not LEcdheRegistered) and
    (TArrayUtilities.Contains<UInt16>(FSupportedVersions, TlsWireVersionTls12)) then
    raise EArgumentTlsLibException.CreateRes(@SNoClassicalEcdheGroup);
end;

function TTlsConfigBuilder.BuildClient: ITlsClientConfig;
var
  LConfig: TFrozenClientConfig;
  LEchPolicy: IEchClientPolicy;
  LHasTrust: Boolean;
begin
  // a builder is single-use
  GuardMutable;
  // a client-authentication credential, if set, must be self-consistent (key owns its leaf)
  if FHasCredential then
    ValidateCredentialConsistency(FCredential);
  if FServerVerification <> nil then
  begin
    ApplyTrustData(FServerVerification);
    if FServerVerification.Kind = TVerificationKind.Custom then
      FServerCertVerifier := FServerVerification.Verifier
    else if FServerVerification.Kind = TVerificationKind.VerifierSource then
      FServerVerifierSource := FServerVerification.Source;
  end;
  ValidateAnchorRoots;
  // a client authenticates the server by its certificate (anchor ROOTS, a whole-verifier, or a
  // verifier source), by an out-of-band external PSK (RFC 9258), or by explicitly skipping
  // verification (the loud dangerous toggle); at least one is required (no silent-insecure). A
  // store with no roots is not a source - it would "verify" against nothing.
  LHasTrust := HasAnchorRoots or (FServerCertVerifier <> nil) or
    (FServerVerifierSource <> nil);
  if (not LHasTrust) and (System.Length(FExternalPsks) = 0) and
    (System.Length(FTls12Psks) = 0) and (not FDangerousTrust.InsecureSkipVerify) then
  begin
    // a supplied-but-empty store is a distinct misconfiguration (trust believed present but absent)
    if System.Length(FAnchorStores) > 0 then
      raise EInvalidOperationTlsLibException.CreateRes(@SEmptyTrustStore);
    raise EInvalidOperationTlsLibException.CreateRes(@SNoTrustStore);
  end;
  // a PSK-only client (external PSKs, no trust source) can verify no certificate, so it must
  // never be steered onto the certificate path: the PSK has to be required (a non-PSK ServerHello
  // is then fatal) and only TLS 1.3 may be offered - a 1.2 selection would reach the certificate
  // path with nothing to verify against (RFC 9258 external PSKs are TLS 1.3-only). A skip-verify
  // client is not PSK-only: its certificate path exists and deliberately verifies nothing.
  if (not LHasTrust) and (not FDangerousTrust.InsecureSkipVerify) then
  begin
    // each version the client offers needs a PSK of that version, required, or it would reach a
    // certificate path with nothing to verify against
    if TArrayUtilities.Contains<UInt16>(FSupportedVersions, TlsWireVersionTls13) then
    begin
      if System.Length(FExternalPsks) = 0 then
        raise EInvalidOperationTlsLibException.CreateRes(@SPskOnlyClientNeedsTls12Only);
      if not FExternalPskRequired then
        raise EInvalidOperationTlsLibException.CreateRes(@SPskOnlyClientNeedsPskRequired);
    end;
    if TArrayUtilities.Contains<UInt16>(FSupportedVersions, TlsWireVersionTls12) then
    begin
      if System.Length(FTls12Psks) = 0 then
        raise EInvalidOperationTlsLibException.CreateRes(@SPskOnlyClientNeedsTls13Only);
      if not FTls12PskRequired then
        raise EInvalidOperationTlsLibException.CreateRes(@SPskOnlyClientNeedsTls12PskRequired);
    end;
    ValidatePskOnlyClientSettings;
  end;
  // a TLS 1.2 PSK is unusable without TLS 1.2
  if (System.Length(FTls12Psks) > 0) and
    not (TArrayUtilities.Contains<UInt16>(FSupportedVersions, TlsWireVersionTls12)) then
    raise EInvalidOperationTlsLibException.CreateRes(@STls12PskNeedsTls12);
  if System.Length(FTls12Psks) > 1 then
    raise EInvalidOperationTlsLibException.CreateRes(@STls12PskClientHoldsOne);
  // a Hard revocation posture rejects a peer whose certificate carries no stapled OCSP response
  // (missing staple -> Indeterminate -> reject), so it silently always-rejects unless the client
  // obtains revocation status some way: by requesting a staple, or by a live OCSP/CRL verdict
  // resolver (the async-verdict seam). Fail fast at Build rather than reject every connection.
  if (FRevocationPosture = TRevocationPosture.Hard) and (not FRequestOcspStapling) and
    (FAsyncVerdict.Deferral <> TVerdictDeferral.LiveRevocation) then
    raise EInvalidOperationTlsLibException.CreateRes(@SHardRevocationUnusable);
  // external PSKs are TLS 1.3-only (RFC 9258); a client that offers them without 1.3 could never
  // use them. The PSK-only path above is stricter (1.3 only); this also catches PSKs alongside trust.
  if (System.Length(FExternalPsks) > 0) and
    not (TArrayUtilities.Contains<UInt16>(FSupportedVersions, TlsWireVersionTls13)) then
    raise EInvalidOperationTlsLibException.CreateRes(@SExternalPskNeedsTls13);
  // only the client sends every imported variant in one extension; a server just matches one
  ValidateExternalPskOfferFits;
  // 0-RTT rides a resumed handshake, so it needs resumption on and a cache to hold the ticket it
  // resumes from; without both the client can never send early data (an external PSK carries no
  // early-data budget here)
  if FClientEarlyData and ((not FResumption) or (FSessionCache = nil)) then
    raise EInvalidOperationTlsLibException.CreateRes(@SEarlyDataNeedsResumption);
  // re-verifying a resumed peer is inert unless this config can actually resume (resumption on and
  // a cache to resume from)
  if (FResumeVerification = TResumeVerification.Reverify) and
    ((not FResumption) or (FSessionCache = nil)) then
    raise EInvalidOperationTlsLibException.CreateRes(@SResumeVerifyNeedsCache);
  // a reverified resume carries no staple, so Hard could never be satisfied without a live verdict
  if (FResumeVerification = TResumeVerification.Reverify) and
    TRevocationDecision.HardNeedsLiveRevocation(FRevocationPosture,
    FAsyncVerdict.Deferral = TVerdictDeferral.LiveRevocation) then
    raise EInvalidOperationTlsLibException.CreateRes(@SReverifyHardNeedsLiveVerdict);
  // a deferred verdict resolves after the server flight, so no early data could precede it
  if FClientEarlyData and (FResumeVerification = TResumeVerification.Reverify) and
    (FAsyncVerdict.Deferral <> TVerdictDeferral.None) then
    raise EInvalidOperationTlsLibException.CreateRes(@SEarlyDataReverifyAsyncVerdict);
  // the client compresses only a client certificate it sends; an empty list is the off switch
  if ((FCompressorsSet and (System.Length(FCertificateCompressors) > 0)) or
    (FCertificateCompressionCache <> nil)) and (not FHasCredential) then
    raise EInvalidOperationTlsLibException.CreateRes(@SClientCompressionNeedsCredential);
  if (FCertificateCompressionCache <> nil) and FCompressorsSet and
    (System.Length(FCertificateCompressors) = 0) then
    raise EInvalidOperationTlsLibException.CreateRes(@SCompressionCacheNeedsCompressor);
  // a cache or scope the caller supplied is inert with resumption off, like the guards above
  if (not FResumption) and ((FSessionCache <> nil) or (System.Length(FSessionScope) > 0)) then
    raise EInvalidOperationTlsLibException.CreateRes(@SClientResumptionSettingNeedsResumption);
  // a scope keys the cached sessions, so it is inert without a cache
  if (System.Length(FSessionScope) > 0) and (FSessionCache = nil) then
    raise EInvalidOperationTlsLibException.CreateRes(@SClientScopeNeedsCache);
  ValidateVersionScoping;
  // "optional" is a statement about a PSK, so it needs one
  if (not FExternalPskRequired) and (System.Length(FExternalPsks) = 0) then
    raise EInvalidOperationTlsLibException.CreateRes(@SExternalPskRequiredNeedsPsk);
  if (not FTls12PskRequired) and (System.Length(FTls12Psks) = 0) then
    raise EInvalidOperationTlsLibException.CreateRes(@STls12PskRequiredNeedsPsk);
  LEchPolicy := nil;
  if FEchMode <> nil then
  begin
    // the inner hello never offers TLS 1.2 (RFC 9849 sec. 6.1), so a real offer needs 1.3 only
    if (not FEchMode.IsGrease) and
      (TArrayUtilities.Contains<UInt16>(FSupportedVersions, TlsWireVersionTls12)) then
      raise EInvalidOperationTlsLibException.CreateRes(@SEchNeedsTls13Only);
    // skipped verification authenticates nothing, so retry_configs are untrustworthy (sec. 6.1.6)
    if (not FEchMode.IsGrease) and FDangerousTrust.InsecureSkipVerify then
      raise EInvalidOperationTlsLibException.CreateRes(@SEchNeedsVerification);
    LEchPolicy := TEchClientPolicy.Create(FCrypto, FEchMode.ConfigList, FEchMode.IsGrease,
      FEchMode.IsRetry) as IEchClientPolicy;
  end;
  ValidateRequiredCollaborators;
  LConfig := TFrozenClientConfig.Create;
  Result := LConfig;
  LConfig.FCrypto := FCrypto;
  LConfig.FPkix := FPkix;
  LConfig.FCipherSuites := EffectiveCipherSuites;
  LConfig.FSignatureSchemes := FSignatureSchemes;
  LConfig.FNamedGroups := FNamedGroups;
  LConfig.FSupportedVersions := FSupportedVersions;
  LConfig.FPreferredGroups := FPreferredGroups;
  LConfig.FAlpnProtocols := FAlpnProtocols;
  LConfig.FRecordSizeLimit := FRecordSizeLimit;
  LConfig.FCertificateCompressors := FCertificateCompressors;
  LConfig.FCertificateDecompressors := FCertificateDecompressors;
  // the shared instance carries over uncopied: connections share one cache
  LConfig.FCertificateCompressionCache := FCertificateCompressionCache;
  LConfig.FCredential := FCredential;
  LConfig.FTrustStore := ComposeTrustStore;
  LConfig.FChainLimits := FChainLimits;
  LConfig.FStrengthPolicy := FStrengthPolicy;
  LConfig.FRevocationPosture := FRevocationPosture;
  LConfig.FCertificatePins := FCertificatePins;
  LConfig.FIntermediateCertificates := FIntermediateCertificates;
  LConfig.FDangerousTrust := FDangerousTrust;
  LConfig.FAsyncVerdict := FAsyncVerdict;
  LConfig.FRequireExtendedMasterSecret := FRequireExtendedMasterSecret;
  LConfig.FGrease := FGrease;
  LConfig.FResumption := FResumption;
  LConfig.FExternalPsks := FExternalPsks;
  LConfig.FTls12Psks := FTls12Psks;
  // a PSK-only client has no certificate to match a host against
  LConfig.FCheckServerName := FCheckServerName and (LHasTrust or FDangerousTrust.InsecureSkipVerify);
  LConfig.FServerNameIndication := FServerNameIndication;
  LConfig.FServerVerifierSource := ComposeServerVerifierSource;
  LConfig.FRequestOcspStapling := FRequestOcspStapling;
  LConfig.FSessionCache := FSessionCache;
  // partition this configuration's sessions inside a possibly shared cache: an explicit scope opts
  // into sharing with configurations given the same one, otherwise each build gets a fresh scope so
  // trust never leaks across configurations
  if FSessionCache = nil then
    LConfig.FSessionScope := nil
  else if System.Length(FSessionScope) > 0 then
    LConfig.FSessionScope := System.Copy(FSessionScope)
  else
    LConfig.FSessionScope := FCrypto.Primitives.GetRandom.GenerateBytes(SessionScopeLength);
  LConfig.FResumeVerification := FResumeVerification;
  LConfig.FClock := FClock;
  LConfig.FMonotonicClock := FMonotonicClock;
  LConfig.FKeyLog := FKeyLog;
  LConfig.FEarlyData := FClientEarlyData;
  LConfig.FExternalPskRequired := FExternalPskRequired;
  LConfig.FTls12PskRequired := FTls12PskRequired;
  LConfig.FEchPolicy := LEchPolicy;
  FFrozen := True;
end;

function TTlsConfigBuilder.BuildServer: ITlsServerConfig;
var
  LConfig: TFrozenServerConfig;
begin
  // a builder is single-use
  GuardMutable;
  // a server authenticates with a certificate or an out-of-band external PSK (RFC 9258);
  // at least one must be configured (a PSK-only server presents no certificate)
  if (not FHasCredential) and (System.Length(FSniCredentialEntries) = 0) and
    (FCredentialResolver = nil) and (System.Length(FExternalPsks) = 0) and
    (System.Length(FTls12Psks) = 0) then
    raise EInvalidOperationTlsLibException.CreateRes(@SNoCredential);
  if FClientVerification <> nil then
  begin
    ApplyTrustData(FClientVerification);
    if FClientVerification.Kind = TVerificationKind.Custom then
      FClientCertVerifier := FClientVerification.Verifier
    else if FClientVerification.Kind = TVerificationKind.VerifierSource then
      FClientVerifierSource := FClientVerification.Source;
  end;
  ValidateAnchorRoots;
  // external PSKs are TLS 1.3-only (RFC 9258): a server that accepts them without offering 1.3
  // could never use one, and would otherwise fail every connection that presents one
  if (System.Length(FExternalPsks) > 0) and
    not (TArrayUtilities.Contains<UInt16>(FSupportedVersions, TlsWireVersionTls13)) then
    raise EInvalidOperationTlsLibException.CreateRes(@SExternalPskNeedsTls13);
  // a TLS 1.2 PSK is unusable without TLS 1.2
  if (System.Length(FTls12Psks) > 0) and
    not (TArrayUtilities.Contains<UInt16>(FSupportedVersions, TlsWireVersionTls12)) then
    raise EInvalidOperationTlsLibException.CreateRes(@STls12PskNeedsTls12);
  // a hint with no PSK would be silently ignored
  if (System.Length(FTls12PskIdentityHint) > 0) and (System.Length(FTls12Psks) = 0) then
    raise EInvalidOperationTlsLibException.CreateRes(@STls12PskHintNeedsPsk);
  // a server with no certificate can serve only the version it holds a PSK for: a version without
  // one would fail every handshake that reached it
  if (not FHasCredential) and (System.Length(FSniCredentialEntries) = 0) and
    (FCredentialResolver = nil) then
  begin
    if (TArrayUtilities.Contains<UInt16>(FSupportedVersions, TlsWireVersionTls12)) and
      (System.Length(FTls12Psks) = 0) then
      raise EInvalidOperationTlsLibException.CreateRes(@SPskOnlyServerNeedsTls13Only);
    if (TArrayUtilities.Contains<UInt16>(FSupportedVersions, TlsWireVersionTls13)) and
      (System.Length(FExternalPsks) = 0) then
      raise EInvalidOperationTlsLibException.CreateRes(@SPskOnlyServerNeedsTls12Only);
    if FClientAuth <> TClientAuthMode.None then
      raise EInvalidOperationTlsLibException.CreateRes(@SPskOnlyServerPeerAuth);
    if (FCompressorsSet and (System.Length(FCertificateCompressors) > 0)) or
      (FCertificateCompressionCache <> nil) then
      raise EInvalidOperationTlsLibException.CreateRes(@SServerCompressionNeedsCertificate);
  end;
  if (FCertificateCompressionCache <> nil) and FCompressorsSet and
    (System.Length(FCertificateCompressors) = 0) then
    raise EInvalidOperationTlsLibException.CreateRes(@SCompressionCacheNeedsCompressor);
  // client-certificate trust inputs act only when the server requests a client certificate; set
  // without WithPeerAuth they would be accepted and silently ignored, and the server would admit
  // clients unauthenticated
  if (FClientAuth = TClientAuthMode.None) and
    ((System.Length(FAnchorStores) > 0) or (FClientCertVerifier <> nil) or
    (FClientVerifierSource <> nil) or (System.Length(FCertificatePins) > 0) or
    (System.Length(FIntermediateCertificates) > 0) or
    (System.Length(FClientCertificateAuthorities) > 0) or
    Assigned(FDangerousTrust.VerifyCallback) or FDangerousTrust.InsecureSkipVerify or
    (FAsyncVerdict.Deferral <> TVerdictDeferral.None) or
    (FRevocationPosture = TRevocationPosture.Hard)) then
    raise EInvalidOperationTlsLibException.CreateRes(@SServerTrustNeedsPeerAuth);
  // the limits and decompressors act only on a requested client certificate
  if (FClientAuth = TClientAuthMode.None) and
    not (FChainLimits = FBaseline.CertificateChainLimits) then
    raise EInvalidOperationTlsLibException.CreateRes(@SServerChainLimitsNeedPeerAuth);
  // the server signs per its key, so the registry acts only on a requested client certificate
  if (FClientAuth = TClientAuthMode.None) and SignatureSchemesDifferFromBaseline then
    raise EInvalidOperationTlsLibException.CreateRes(@SServerSchemesNeedPeerAuth);
  if (FClientAuth = TClientAuthMode.None) and FDecompressorsSet and
    (System.Length(FCertificateDecompressors) > 0) then
    raise EInvalidOperationTlsLibException.CreateRes(@SServerDecompressorsNeedPeerAuth);
  // client authentication verifies the peer chain against a trust source: anchor ROOTS, a
  // whole-verifier, or an explicit skip-verify. A verifier source is NOT a source on its own - it
  // consumes the client-CA anchors as its exclusive root, so it needs roots too. Without one the
  // server would only fail closed at handshake time, so reject it at build (fail fast)
  if (FClientAuth <> TClientAuthMode.None) and (not HasAnchorRoots) and
    (FClientCertVerifier = nil) and (not FDangerousTrust.InsecureSkipVerify) then
  begin
    // a source with no roots to consume: the most specific misconfiguration, named first (whether
    // the anchor set is absent or supplied-but-empty, the fix is the same - add a root)
    if FClientVerifierSource <> nil then
      raise EInvalidOperationTlsLibException.CreateRes(@SClientVerifierSourceNeedsAnchors);
    // a supplied-but-empty store is a distinct misconfiguration (trust believed present but absent)
    if System.Length(FAnchorStores) > 0 then
      raise EInvalidOperationTlsLibException.CreateRes(@SEmptyTrustStore);
    raise EInvalidOperationTlsLibException.CreateRes(@SNoClientAuthTrustStore);
  end;
  // a Hard revocation posture on the client certificate rejects a client whose cert carries no
  // definite non-revoked status. A client cannot staple, so the only status source is a live
  // OCSP/CRL verdict resolver; without one, Hard would reject every client. Fail fast at Build
  // (only meaningful when client authentication is actually requested).
  if (FClientAuth <> TClientAuthMode.None) and
    (FRevocationPosture = TRevocationPosture.Hard) and
    (FAsyncVerdict.Deferral <> TVerdictDeferral.LiveRevocation) then
    raise EInvalidOperationTlsLibException.CreateRes(@SHardServerRevocationUnusable);
  // a ticket-key manager or session store is the one thing an operator can share across
  // configurations, and a resumed handshake reuses the original client authentication without
  // re-verifying it (inferred from RFC 9846 2.2): an mTLS configuration that supplies one must
  // partition its tickets with an explicit scope, or a ticket minted under another
  // configuration's client-CA trust would resume here as an authenticated identity. The
  // per-config default STEK is exempt (it is never shared), so the common case builds unchanged.
  if FResumption and (FClientAuth <> TClientAuthMode.None) and
    ((FSessionTicketKeys <> nil) or (FSessionStore <> nil)) and
    (System.Length(FResumptionScope) = 0) then
    raise EInvalidOperationTlsLibException.CreateRes(@SMtlsSharedResumptionNeedsScope);
  // 0-RTT early data is offered only on a resumed session; a limit with resumption off is inert
  if (FMaxEarlyData > 0) and (not FResumption) then
    raise EInvalidOperationTlsLibException.CreateRes(@SServerEarlyDataNeedsResumption);
  // the strategy is read only when early data is accepted
  if (FAntiReplay <> nil) and (FMaxEarlyData = 0) then
    raise EInvalidOperationTlsLibException.CreateRes(@SAntiReplayNeedsEarlyData);
  // every other resumption setting is equally inert with resumption off; a ticket lifetime or count
  // counts only when it differs from its default, like any other setting
  if (not FResumption) and ((FSessionStore <> nil) or (FSessionTicketKeys <> nil) or
    FWantDefaultSessionTicketKeys or (FTicketLifetimeSeconds <> DefaultTicketLifetimeSeconds) or
    ((FTicketCount <> DefaultTicketCount) and (FTicketCount <> 0)) or
    (System.Length(FResumptionScope) > 0) or
    (FAntiReplay <> nil) or (FNonEmsResumption <> TNonEmsResumption.Decline)) then
    raise EInvalidOperationTlsLibException.CreateRes(@SServerResumptionSettingNeedsResumption);
  // rejecting every ALPN offer and listing protocols to select from contradict each other
  if FAlpnRejectAll and (System.Length(FAlpnProtocols) > 0) then
    raise EInvalidOperationTlsLibException.CreateRes(@SAlpnRejectionWithProtocols);
  // an explicit (shareable) ticket-key manager with only the per-config default strike register
  // lets a ticket be replayed across instances; a session store makes tickets single-use
  if (FMaxEarlyData > 0) and (FSessionTicketKeys <> nil) and (FSessionStore = nil) and
    (FAntiReplay = nil) then
    raise EInvalidOperationTlsLibException.CreateRes(@SExplicitStekEarlyDataNeedsAntiReplay);
  // requiring the extension rejects every non-EMS client, so no non-EMS resumption mode can apply
  if FRequireExtendedMasterSecret and (FNonEmsResumption <> TNonEmsResumption.Decline) then
    raise EInvalidOperationTlsLibException.CreateRes(@SNonEmsResumeWithRequiredEms);
  // RFC 9846 4.7.1: a lifetime of 0 tells the client to discard the ticket at once
  if FResumption and (FTicketLifetimeSeconds = 0) then
    raise EInvalidOperationTlsLibException.CreateRes(@STicketLifetimeZero);
  ValidateTicketCountZeroSettings;
  ValidateVersionScoping;
  ValidateRequiredCollaborators;
  ValidateClientCertificateAuthoritiesFit;
  LConfig := TFrozenServerConfig.Create;
  Result := LConfig;
  LConfig.FCrypto := FCrypto;
  LConfig.FPkix := FPkix;
  LConfig.FCipherSuites := EffectiveCipherSuites;
  LConfig.FSignatureSchemes := FSignatureSchemes;
  LConfig.FNamedGroups := FNamedGroups;
  LConfig.FSupportedVersions := FSupportedVersions;
  LConfig.FPreferredGroups := FPreferredGroups;
  LConfig.FAlpnProtocols := FAlpnProtocols;
  LConfig.FRecordSizeLimit := FRecordSizeLimit;
  LConfig.FCertificateCompressors := FCertificateCompressors;
  LConfig.FCertificateDecompressors := FCertificateDecompressors;
  // the shared instance carries over uncopied: connections share one cache (server path)
  LConfig.FCertificateCompressionCache := FCertificateCompressionCache;
  LConfig.FCredential := FCredential;
  LConfig.FTrustStore := ComposeTrustStore;
  LConfig.FChainLimits := FChainLimits;
  LConfig.FStrengthPolicy := FStrengthPolicy;
  LConfig.FRevocationPosture := FRevocationPosture;
  LConfig.FCertificatePins := FCertificatePins;
  LConfig.FIntermediateCertificates := FIntermediateCertificates;
  LConfig.FDangerousTrust := FDangerousTrust;
  LConfig.FAsyncVerdict := FAsyncVerdict;
  LConfig.FRequireExtendedMasterSecret := FRequireExtendedMasterSecret;
  LConfig.FServerNameAck := FServerNameAck;
  LConfig.FCipherPreference := FCipherPreference;
  LConfig.FNonEmsResumption := FNonEmsResumption;
  LConfig.FAlpnRejectAll := FAlpnRejectAll;
  LConfig.FClientCertificateAuthorities := FClientCertificateAuthorities;
  LConfig.FResumption := FResumption;
  LConfig.FExternalPsks := FExternalPsks;
  LConfig.FTls12Psks := FTls12Psks;
  LConfig.FClock := FClock;
  LConfig.FMonotonicClock := FMonotonicClock;
  LConfig.FKeyLog := FKeyLog;
  LConfig.FClientAuth := FClientAuth;
  LConfig.FClientVerifierSource := ComposeClientVerifierSource;
  LConfig.FSessionStore := FSessionStore;
  LConfig.FResumptionScope := System.Copy(FResumptionScope);
  LConfig.FCredentialResolver := ComposeCredentialResolver;
  // explicit keys always win; otherwise mint the default STEK from THIS builder's injected
  // provider + clock (never a concrete default provider), scoped to the config's life and rotating
  // on the advertised ticket lifetime. With resumption on and neither ticket keys nor a session
  // store configured, the STEK is minted so a server resumes out of the box rather than silently
  // issuing nothing; a store-only (stateful) server and WithResumption(False) both opt out.
  if FSessionTicketKeys <> nil then
    LConfig.FSessionTicketKeys := FSessionTicketKeys
  else if FWantDefaultSessionTicketKeys or (FResumption and (FSessionStore = nil)) then
    LConfig.FSessionTicketKeys := TStekTicketKeyManager.CreateDefault(FCrypto, FClock,
      FTicketLifetimeSeconds);
  // one register per config, shared across every connection so a replayed 0-RTT offer is
  // detected across connections (RFC 9846 8)
  if FAntiReplay <> nil then
    LConfig.FAntiReplay := FAntiReplay
  else if (FMaxEarlyData > 0) and FResumption then
    LConfig.FAntiReplay := TStrikeRegisterAntiReplay.Create as IAntiReplayStrategy;
  LConfig.FTicketLifetimeSeconds := FTicketLifetimeSeconds;
  LConfig.FTicketCount := FTicketCount;
  LConfig.FTls12PskIdentityHint := FTls12PskIdentityHint;
  LConfig.FMaxEarlyData := FMaxEarlyData;
  LConfig.FEchServerPolicy := FEchServerPolicy;
  FFrozen := True;
end;

end.
