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
  TlpINamedGroup,
  TlpINegotiation,
  TlpNegotiationTypes,
  TlpICertificateTrust,
  TlpCertificateVerifier,
  TlpICertificateCompression,
  TlpICertificateCompressionCache,
  TlpZlibCertificateCompression,
  TlpCertificateLimits,
  TlpTrustPolicy,
  TlpTlsCredential,
  TlpITlsCredentialResolver,
  TlpCredentialResolvers,
  TlpEndpointIdentity,
  TlpISession,
  TlpIClock,
  TlpClock,
  TlpSession,
  TlpSessionTicketKeys,
  TlpITlsConfig,
  TlpITlsConfigBuilder;

type
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
    FProvider: ICryptoProvider;
    FCipherSuites: ICipherSuiteRegistry;
    FSignatureSchemes: ISignatureSchemeRegistry;
    FNamedGroups: INamedGroupRegistry;
    FSupportedVersions: TArray<UInt16>;
    FPreferredGroups: TArray<UInt16>;
    FAlpnProtocols: TArray<string>;
    // anchor contributions accumulate (union); a whole-verifier is exclusive of them
    FAnchorStores: TArray<ITrustAnchorStore>;
    FCertificateVerifier: ICertificateVerifier;
    FVerifierCount: Int32;
    FCheckServerName: Boolean;
    FRequestOcspStapling: Boolean;
    FChainLimits: TCertificateChainLimits;
    FCredential: TTlsCredential;
    FHasCredential: Boolean;
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
    FServerNameAck: Boolean;
    FCipherPreference: TServerCipherPreference;
    FAlpnRejectAll: Boolean;
    FClientCertificateAuthorities: TArray<TBytes>;
    FGrease: Boolean;
    FResumption: Boolean;
    FExternalPsks: TArray<TExternalPsk>;
    FExternalPskRequired: Boolean;
    FSessionCache: ISessionCache;
    FClock: ITlsClock;
    FClientEarlyData: Boolean;
    FSessionStore: ISessionStore;
    FSessionTicketKeys: ISessionTicketKeyManager;
    FWantDefaultSessionTicketKeys: Boolean;
    FAntiReplay: IAntiReplayStrategy;
    FTicketLifetimeSeconds: UInt32;
    FTicketCount: Int32;
    FMaxEarlyData: UInt32;
    // whether a version's facet was explicitly configured, so a build can refuse a
    // version that is not offered (defaults are seeded directly, not through a facet)
    FTls13Configured: Boolean;
    FTls12Configured: Boolean;
    FClient: ITlsClientConfigBuilder;
    FServer: ITlsServerConfigBuilder;
    FClient13: ITls13ClientConfigFacet;
    FClient12: ITls12ClientConfigFacet;
    FServer13: ITls13ServerConfigFacet;
    FServer12: ITls12ServerConfigFacet;
    procedure GuardMutable;
    /// <summary>Refuses a version facet that was configured for a version not offered.</summary>
    procedure ValidateVersionScoping;
    /// <summary>Composes the accumulated anchor sources into one store: nil for none, the
    /// single store for one, else a union. nil when a whole-verifier is used instead.</summary>
    function ComposeTrustStore: ITrustAnchorStore;
    /// <summary>Enforces the trust-composition rule at build: a whole-verifier is exclusive
    /// of any anchor source and of a second verifier (typed error).</summary>
    procedure ValidateTrustComposition;
    /// <summary>Composes the server credential resolver at build: a custom resolver (exclusive
    /// of the built-in map/credential), else the SNI map plus the single credential as the
    /// default fallback, else nil for a PSK-only server.</summary>
    function ComposeCredentialResolver: ITlsServerCredentialResolver;
    /// <summary>Fails the build (typed error) when an SNI entry's certificate does not cover
    /// its host, so a swapped cert/host mapping is caught up front, not per handshake.</summary>
    procedure ValidateSniEntryCoversHost(const AHost: string;
      const ACredential: TTlsCredential);
  public
    constructor Create(const AProvider: ICryptoProvider);

    // the single-source-of-truth mutators (endpoint views, facets and presets call these)
    function WithCipherSuites(const ARegistry: ICipherSuiteRegistry): TTlsConfigBuilder;
    function WithSignatureSchemes(const ARegistry: ISignatureSchemeRegistry): TTlsConfigBuilder;
    function WithNamedGroups(const ARegistry: INamedGroupRegistry): TTlsConfigBuilder;
    function WithSupportedVersions(const AVersions: TArray<UInt16>): TTlsConfigBuilder;
    function WithPreferredGroups(const AGroups: TArray<UInt16>): TTlsConfigBuilder;
    function WithAlpnProtocols(const AProtocols: TArray<string>): TTlsConfigBuilder;
    function WithTrustStore(const AStore: ITrustAnchorStore): TTlsConfigBuilder;
    function WithTrustAnchors(const AData: TBytes): TTlsConfigBuilder;
    function WithCertificateVerifier(
      const AVerifier: ICertificateVerifier): TTlsConfigBuilder;
    function WithCertificateChainLimits(
      const ALimits: TCertificateChainLimits): TTlsConfigBuilder;
    function WithCredential(const ACredential: TTlsCredential): TTlsConfigBuilder; overload;
    function WithCredential(const ACertificateChainData,
      APrivateKeyData: TBytes): TTlsConfigBuilder; overload;
    function WithCredential(const ACertificateChainData, APrivateKeyData: TBytes;
      const APassword: string): TTlsConfigBuilder; overload;
    function WithCredentialPkcs12(const AData: TBytes;
      const APassword: string): TTlsConfigBuilder;
    function WithSniCredential(const AHost: string;
      const ACredential: TTlsCredential): TTlsConfigBuilder; overload;
    function WithSniCredential(const AHost: string; const ACertificateChainData,
      APrivateKeyData: TBytes): TTlsConfigBuilder; overload;
    function WithSniCredential(const AHost: string; const ACertificateChainData,
      APrivateKeyData: TBytes; const APassword: string): TTlsConfigBuilder; overload;
    function WithCredentialResolver(
      const AResolver: ITlsServerCredentialResolver): TTlsConfigBuilder;
    function WithCertificateCompressors(
      const ACompressors: TArray<ICertificateCompressor>): TTlsConfigBuilder;
    function WithCertificateDecompressors(
      const ADecompressors: TArray<ICertificateDecompressor>): TTlsConfigBuilder;
    function WithCertificateCompressionCache(
      const ACache: ICertificateCompressionCache): TTlsConfigBuilder;
    function WithExtendedMasterSecret(ARequire: Boolean): TTlsConfigBuilder;
    function WithServerNameAcknowledgement(ASend: Boolean): TTlsConfigBuilder;
    function WithCipherSuitePreference(APreference: TServerCipherPreference): TTlsConfigBuilder;
    function WithAlpnRejection(AReject: Boolean): TTlsConfigBuilder;
    function WithClientCertificateAuthorities(const AAuthorities: TArray<TBytes>): TTlsConfigBuilder;
    function WithGrease(AEnable: Boolean): TTlsConfigBuilder;
    function WithNameCheck(AEnabled: Boolean): TTlsConfigBuilder;
    function WithOcspStaplingRequest(AEnabled: Boolean): TTlsConfigBuilder;
    function WithPeerAuth(AMode: TClientAuthMode): TTlsConfigBuilder;
    function WithRevocation(APosture: TRevocationPosture): TTlsConfigBuilder;
    function WithCertificatePinning(const APins: TArray<TBytes>): TTlsConfigBuilder;
    function WithIntermediateCertificates(const AData: TBytes): TTlsConfigBuilder;
    function WithDangerousInsecureSkipVerify(AEnabled: Boolean): TTlsConfigBuilder;
    function WithCertificateVerifyCallback(
      const ACallback: TTlsCertificateVerifyCallback): TTlsConfigBuilder;
    function WithAsyncCertificateVerdict(AEnabled: Boolean;
      ADeadlineMs: Cardinal): TTlsConfigBuilder;
    function WithResumption(AEnabled: Boolean): TTlsConfigBuilder;
    function WithExternalPreSharedKeys(
      const APsks: TArray<TExternalPsk>): TTlsConfigBuilder;
    function WithExternalPskRequired(AEnabled: Boolean): TTlsConfigBuilder;
    function WithSessionCache(const ACache: ISessionCache): TTlsConfigBuilder;
    function WithClock(const AClock: ITlsClock): TTlsConfigBuilder;
    function WithSessionStore(const AStore: ISessionStore): TTlsConfigBuilder;
    function WithSessionTicketKeys(const AKeys: ISessionTicketKeyManager): TTlsConfigBuilder;
    function WithDefaultSessionTicketKeys: TTlsConfigBuilder;
    function WithTicketLifetime(ASeconds: UInt32): TTlsConfigBuilder;
    function WithTicketCount(ACount: Int32): TTlsConfigBuilder;
    function WithClientEarlyData(AEnabled: Boolean): TTlsConfigBuilder;
    function WithServerEarlyData(AMaxBytes: UInt32): TTlsConfigBuilder;
    function WithAntiReplay(const AStrategy: IAntiReplayStrategy): TTlsConfigBuilder;

    // the version facet instances (returned by the endpoint views and cross-accessors)
    function Client13: ITls13ClientConfigFacet;
    function Client12: ITls12ClientConfigFacet;
    function Server13: ITls13ServerConfigFacet;
    function Server12: ITls12ServerConfigFacet;

    // ITlsConfigBuilder
    function Client: ITlsClientConfigBuilder;
    function Server: ITlsServerConfigBuilder;

    /// <summary>Freezes and returns the client config; raises without a trust source.</summary>
    function BuildClient: ITlsClientConfig;
    /// <summary>Freezes and returns the server config; raises without a credential.</summary>
    function BuildServer: ITlsServerConfig;
  end;

implementation

resourcestring
  SBuilderFrozen = 'the configuration has been built and can no longer be changed';
  SNoTrustStore = 'a client configuration requires a trust source (no silent-insecure)';
  SNoCredential = 'a server configuration requires a certificate credential';
  SNoClientAuthTrustStore = 'client authentication requires a trust source for the client certificate chain';
  SSniCertMissing = 'the SNI credential for host "%s" has no certificate chain';
  SSniCertMismatch = 'the certificate mapped to SNI host "%s" does not cover it: its ' +
    'SubjectAltName dNSName entries do not match the host';
  SSniResolverConflict = 'a custom WithCredentialResolver cannot be combined with ' +
    'WithCredential or WithSniCredential; supply one or the other';
  SClientSideServerCredential = 'WithSniCredential and WithCredentialResolver select a server ' +
    'certificate by SNI and cannot be used on a client configuration';
  SSniDuplicateHost = 'the SNI host "%s" is mapped by more than one WithSniCredential entry';
  SSniWildcardMalformed = 'the SNI host "%s" is not a supported wildcard; only a single ' +
    'left-most label wildcard (*.example.com) is allowed';
  SVerifierAnchorConflict = 'a custom certificate verifier is exclusive; it cannot be combined with any trust anchor source';
  SDualVerifier = 'only one custom certificate verifier may be configured';
  STls13NotOffered = 'TLS 1.3 settings were configured but TLS 1.3 is not in the offered versions';
  STls12NotOffered = 'TLS 1.2 settings were configured but TLS 1.2 is not in the offered versions';
  SHardRevocationUnusable = 'a Hard revocation posture rejects a peer whose certificate has no ' +
    'stapled OCSP response, so it always-rejects unless the client obtains revocation status: ' +
    'call WithOcspStaplingRequest(True) to request a staple, or configure a live OCSP/CRL verdict ' +
    'resolver (WithAsyncCertificateVerdict)';
  SHardServerRevocationUnusable = 'a Hard revocation posture rejects a client whose certificate ' +
    'has no revocation status; a server cannot request a client OCSP staple, so Hard ' +
    'client-certificate revocation requires a live OCSP/CRL verdict resolver ' +
    '(WithAsyncCertificateVerdict)';
  STicketLifetimeTooLong = 'the session-ticket lifetime must not exceed 604800 seconds ' +
    '(7 days), the maximum a server may advertise (RFC 8446 4.6.1)';

const
  DefaultTicketLifetimeSeconds = UInt32(7200);
  DefaultTicketCount = Int32(2);

type
  /// <summary>The immutable common settings, shared by the client and server config.</summary>
  TFrozenCommonConfig = class(TInterfacedObject)
  protected
  var
    FProvider: ICryptoProvider;
    FCipherSuites: ICipherSuiteRegistry;
    FSignatureSchemes: ISignatureSchemeRegistry;
    FNamedGroups: INamedGroupRegistry;
    FSupportedVersions: TArray<UInt16>;
    FPreferredGroups: TArray<UInt16>;
    FAlpnProtocols: TArray<string>;
    FCertificateCompressors: TArray<ICertificateCompressor>;
    FCertificateDecompressors: TArray<ICertificateDecompressor>;
    FCertificateCompressionCache: ICertificateCompressionCache;
    FCredential: TTlsCredential;
    FTrustStore: ITrustAnchorStore;
    FCertificateVerifier: ICertificateVerifier;
    FChainLimits: TCertificateChainLimits;
    FRevocationPosture: TRevocationPosture;
    FCertificatePins: TArray<TBytes>;
    FIntermediateCertificates: TArray<TBytes>;
    FDangerousTrust: TDangerousTrust;
    FAsyncVerdict: TAsyncCertificateVerdict;
    FRequireExtendedMasterSecret: Boolean;
    FServerNameAck: Boolean;
    FCipherPreference: TServerCipherPreference;
    FAlpnRejectAll: Boolean;
    FClientCertificateAuthorities: TArray<TBytes>;
    FGrease: Boolean;
    FResumption: Boolean;
    FExternalPsks: TArray<TExternalPsk>;
    FClock: ITlsClock;
  public
    function Provider: ICryptoProvider;
    function CipherSuites: ICipherSuiteRegistry;
    function SignatureSchemes: ISignatureSchemeRegistry;
    function NamedGroups: INamedGroupRegistry;
    function SupportedVersions: TArray<UInt16>;
    function PreferredGroups: TArray<UInt16>;
    function AlpnProtocols: TArray<string>;
    function CertificateCompressors: TArray<ICertificateCompressor>;
    function CertificateDecompressors: TArray<ICertificateDecompressor>;
    function CertificateCompressionCache: ICertificateCompressionCache;
    function Credential: TTlsCredential;
    function TrustStore: ITrustAnchorStore;
    function CertificateVerifier: ICertificateVerifier;
    function CertificateChainLimits: TCertificateChainLimits;
    function RevocationPosture: TRevocationPosture;
    function CertificatePins: TArray<TBytes>;
    function IntermediateCertificates: TArray<TBytes>;
    function DangerousTrust: TDangerousTrust;
    function AsyncCertificateVerdict: TAsyncCertificateVerdict;
    function RequireExtendedMasterSecret: Boolean;
    function ServerNameAcknowledgement: Boolean;
    function CipherSuitePreference: TServerCipherPreference;
    function AlpnRejectAll: Boolean;
    function ClientCertificateAuthorities: TArray<TBytes>;
    function Grease: Boolean;
    function Resumption: Boolean;
    function ExternalPsks: TArray<TExternalPsk>;
    function Clock: ITlsClock;
  end;

  TFrozenClientConfig = class sealed(TFrozenCommonConfig, ITlsClientConfig)
  private
  var
    FCheckServerName: Boolean;
    FRequestOcspStapling: Boolean;
    FSessionCache: ISessionCache;
    FEarlyData: Boolean;
    FExternalPskRequired: Boolean;
  public
    function CheckServerName: Boolean;
    function RequestOcspStapling: Boolean;
    function SessionCache: ISessionCache;
    function EarlyData: Boolean;
    function ExternalPskRequired: Boolean;
  end;

  TFrozenServerConfig = class sealed(TFrozenCommonConfig, ITlsServerConfig)
  private
  var
    FClientAuth: TClientAuthMode;
    FSessionStore: ISessionStore;
    FSessionTicketKeys: ISessionTicketKeyManager;
    FCredentialResolver: ITlsServerCredentialResolver;
    FAntiReplay: IAntiReplayStrategy;
    FTicketLifetimeSeconds: UInt32;
    FTicketCount: Int32;
    FMaxEarlyData: UInt32;
  public
    function ClientAuth: TClientAuthMode;
    function SessionStore: ISessionStore;
    function SessionTicketKeys: ISessionTicketKeyManager;
    function CredentialResolver: ITlsServerCredentialResolver;
    function AntiReplay: IAntiReplayStrategy;
    function TicketLifetimeSeconds: UInt32;
    function TicketCount: Int32;
    function MaxEarlyData: UInt32;
  end;

  /// <summary>Shared view plumbing: a raw back-reference to the owning builder whose
  /// mutators the view forwards to. The reference is raw so the view does not keep the
  /// builder alive (the builder owns the view).</summary>
  TTlsConfigViewBase = class(TInterfacedObject)
  strict protected
  var
    FOwner: TTlsConfigBuilder;
  public
    constructor Create(const AOwner: TTlsConfigBuilder);
  end;

  TTlsClientConfigBuilder = class sealed(TTlsConfigViewBase, ITlsClientConfigBuilder)
  public
    function WithCipherSuites(const ARegistry: ICipherSuiteRegistry): ITlsClientConfigBuilder;
    function WithSignatureSchemes(const ARegistry: ISignatureSchemeRegistry): ITlsClientConfigBuilder;
    function WithNamedGroups(const ARegistry: INamedGroupRegistry): ITlsClientConfigBuilder;
    function WithSupportedVersions(const AVersions: TArray<UInt16>): ITlsClientConfigBuilder;
    function WithPreferredGroups(const AGroups: TArray<UInt16>): ITlsClientConfigBuilder;
    function WithAlpnProtocols(const AProtocols: TArray<string>): ITlsClientConfigBuilder;
    function WithGrease(AEnable: Boolean): ITlsClientConfigBuilder;
    function WithTrustStore(const AStore: ITrustAnchorStore): ITlsClientConfigBuilder;
    function WithTrustAnchors(const AData: TBytes): ITlsClientConfigBuilder;
    function WithCertificateVerifier(
      const AVerifier: ICertificateVerifier): ITlsClientConfigBuilder;
    function WithCertificateChainLimits(
      const ALimits: TCertificateChainLimits): ITlsClientConfigBuilder;
    function WithCredential(const ACredential: TTlsCredential): ITlsClientConfigBuilder; overload;
    function WithCredential(const ACertificateChainData,
      APrivateKeyData: TBytes): ITlsClientConfigBuilder; overload;
    function WithCredential(const ACertificateChainData, APrivateKeyData: TBytes;
      const APassword: string): ITlsClientConfigBuilder; overload;
    function WithCredentialPkcs12(const AData: TBytes;
      const APassword: string): ITlsClientConfigBuilder;
    /// <summary>The certificate revocation posture. Soft (default) accepts an indeterminate
    /// status; Off skips revocation. Hard REQUIRES a definite not-revoked status and rejects a
    /// peer certificate with no stapled OCSP response - so Hard is only usable together with
    /// WithOcspStaplingRequest(True) or a live OCSP/CRL verdict resolver
    /// (WithAsyncCertificateVerdict); Build rejects a Hard client that has neither.</summary>
    function WithRevocation(APosture: TRevocationPosture): ITlsClientConfigBuilder;
    function WithCertificatePinning(
      const APins: TArray<TBytes>): ITlsClientConfigBuilder;
    function WithIntermediateCertificates(
      const AData: TBytes): ITlsClientConfigBuilder;
    function WithNameCheck(AEnabled: Boolean): ITlsClientConfigBuilder;
    function WithOcspStaplingRequest(AEnabled: Boolean): ITlsClientConfigBuilder;
    function WithDangerousInsecureSkipVerify(
      AEnabled: Boolean): ITlsClientConfigBuilder;
    function WithCertificateVerifyCallback(
      const ACallback: TTlsCertificateVerifyCallback): ITlsClientConfigBuilder;
    function WithAsyncCertificateVerdict(AEnabled: Boolean;
      ADeadlineMs: Cardinal): ITlsClientConfigBuilder;
    function WithSessionCache(const ACache: ISessionCache): ITlsClientConfigBuilder;
    function WithClock(const AClock: ITlsClock): ITlsClientConfigBuilder;
    function WithExternalPreSharedKeys(
      const APsks: TArray<TExternalPsk>): ITlsClientConfigBuilder;
    function WithExternalPskRequired(AEnabled: Boolean): ITlsClientConfigBuilder;
    function WithResumption(AEnabled: Boolean): ITlsClientConfigBuilder;
    function Tls13: ITls13ClientConfigFacet;
    function Tls12: ITls12ClientConfigFacet;
    function Build: ITlsClientConfig;
  end;

  TTlsServerConfigBuilder = class sealed(TTlsConfigViewBase, ITlsServerConfigBuilder)
  public
    function WithCipherSuites(const ARegistry: ICipherSuiteRegistry): ITlsServerConfigBuilder;
    function WithSignatureSchemes(const ARegistry: ISignatureSchemeRegistry): ITlsServerConfigBuilder;
    function WithNamedGroups(const ARegistry: INamedGroupRegistry): ITlsServerConfigBuilder;
    function WithSupportedVersions(const AVersions: TArray<UInt16>): ITlsServerConfigBuilder;
    function WithPreferredGroups(const AGroups: TArray<UInt16>): ITlsServerConfigBuilder;
    function WithAlpnProtocols(const AProtocols: TArray<string>): ITlsServerConfigBuilder;
    function WithServerNameAcknowledgement(ASend: Boolean): ITlsServerConfigBuilder;
    function WithCipherSuitePreference(APreference: TServerCipherPreference): ITlsServerConfigBuilder;
    function WithAlpnRejection(AReject: Boolean): ITlsServerConfigBuilder;
    function WithClientCertificateAuthorities(const AAuthorities: TArray<TBytes>): ITlsServerConfigBuilder;
    function WithTrustStore(const AStore: ITrustAnchorStore): ITlsServerConfigBuilder;
    function WithTrustAnchors(const AData: TBytes): ITlsServerConfigBuilder;
    function WithCertificateVerifier(
      const AVerifier: ICertificateVerifier): ITlsServerConfigBuilder;
    function WithCertificateChainLimits(
      const ALimits: TCertificateChainLimits): ITlsServerConfigBuilder;
    function WithCredential(const ACredential: TTlsCredential): ITlsServerConfigBuilder; overload;
    function WithCredential(const ACertificateChainData,
      APrivateKeyData: TBytes): ITlsServerConfigBuilder; overload;
    function WithCredential(const ACertificateChainData, APrivateKeyData: TBytes;
      const APassword: string): ITlsServerConfigBuilder; overload;
    function WithCredentialPkcs12(const AData: TBytes;
      const APassword: string): ITlsServerConfigBuilder;
    function WithSniCredential(const AHost: string;
      const ACredential: TTlsCredential): ITlsServerConfigBuilder; overload;
    function WithSniCredential(const AHost: string; const ACertificateChainData,
      APrivateKeyData: TBytes): ITlsServerConfigBuilder; overload;
    function WithSniCredential(const AHost: string; const ACertificateChainData,
      APrivateKeyData: TBytes; const APassword: string): ITlsServerConfigBuilder; overload;
    function WithCredentialResolver(
      const AResolver: ITlsServerCredentialResolver): ITlsServerConfigBuilder;
    function WithPeerAuth(AMode: TClientAuthMode): ITlsServerConfigBuilder;
    /// <summary>The revocation posture for the CLIENT certificate under mutual TLS (RFC 8446
    /// 4.4.2). Soft (default) accepts an indeterminate status; Off skips revocation. Hard REQUIRES
    /// a definite not-revoked status - and since a client cannot be asked to staple an OCSP
    /// response, Hard client-certificate revocation is satisfiable ONLY by a live OCSP/CRL verdict
    /// resolver (WithAsyncCertificateVerdict + TTlsStream.SetCertificateVerdictResolver); Build
    /// rejects a Hard, client-authenticating server that has no resolver. Governs nothing when
    /// client authentication is not requested.</summary>
    function WithRevocation(APosture: TRevocationPosture): ITlsServerConfigBuilder;
    function WithCertificatePinning(
      const APins: TArray<TBytes>): ITlsServerConfigBuilder;
    function WithIntermediateCertificates(
      const AData: TBytes): ITlsServerConfigBuilder;
    function WithDangerousInsecureSkipVerify(
      AEnabled: Boolean): ITlsServerConfigBuilder;
    function WithCertificateVerifyCallback(
      const ACallback: TTlsCertificateVerifyCallback): ITlsServerConfigBuilder;
    function WithAsyncCertificateVerdict(AEnabled: Boolean;
      ADeadlineMs: Cardinal): ITlsServerConfigBuilder;
    function WithExternalPreSharedKeys(
      const APsks: TArray<TExternalPsk>): ITlsServerConfigBuilder;
    function WithSessionStore(const AStore: ISessionStore): ITlsServerConfigBuilder;
    function WithSessionTicketKeys(const AKeys: ISessionTicketKeyManager): ITlsServerConfigBuilder;
    function WithDefaultSessionTicketKeys: ITlsServerConfigBuilder;
    function WithClock(const AClock: ITlsClock): ITlsServerConfigBuilder;
    function WithTicketLifetime(ASeconds: UInt32): ITlsServerConfigBuilder;
    function WithTicketCount(ACount: Int32): ITlsServerConfigBuilder;
    function WithResumption(AEnabled: Boolean): ITlsServerConfigBuilder;
    function Tls13: ITls13ServerConfigFacet;
    function Tls12: ITls12ServerConfigFacet;
    function Build: ITlsServerConfig;
  end;

  TTls13ClientConfigFacet = class sealed(TTlsConfigViewBase, ITls13ClientConfigFacet)
  public
    function WithCertificateDecompressors(
      const ADecompressors: TArray<ICertificateDecompressor>): ITls13ClientConfigFacet;
    function WithCertificateCompressors(
      const ACompressors: TArray<ICertificateCompressor>): ITls13ClientConfigFacet;
    function WithEarlyData(AEnabled: Boolean): ITls13ClientConfigFacet;
    function Tls12: ITls12ClientConfigFacet;
    function Build: ITlsClientConfig;
  end;

  TTls12ClientConfigFacet = class sealed(TTlsConfigViewBase, ITls12ClientConfigFacet)
  public
    function WithExtendedMasterSecret(ARequire: Boolean): ITls12ClientConfigFacet;
    function Tls13: ITls13ClientConfigFacet;
    function Build: ITlsClientConfig;
  end;

  TTls13ServerConfigFacet = class sealed(TTlsConfigViewBase, ITls13ServerConfigFacet)
  public
    function WithCertificateDecompressors(
      const ADecompressors: TArray<ICertificateDecompressor>): ITls13ServerConfigFacet;
    function WithCertificateCompressors(
      const ACompressors: TArray<ICertificateCompressor>): ITls13ServerConfigFacet;
    function WithCertificateCompressionCache(
      const ACache: ICertificateCompressionCache): ITls13ServerConfigFacet;
    function WithEarlyData(AMaxBytes: UInt32): ITls13ServerConfigFacet;
    function WithAntiReplay(const AStrategy: IAntiReplayStrategy): ITls13ServerConfigFacet;
    function Tls12: ITls12ServerConfigFacet;
    function Build: ITlsServerConfig;
  end;

  TTls12ServerConfigFacet = class sealed(TTlsConfigViewBase, ITls12ServerConfigFacet)
  public
    function WithExtendedMasterSecret(ARequire: Boolean): ITls12ServerConfigFacet;
    function Tls13: ITls13ServerConfigFacet;
    function Build: ITlsServerConfig;
  end;

{ TFrozenCommonConfig }

function TFrozenCommonConfig.Provider: ICryptoProvider;
begin
  Result := FProvider;
end;

function TFrozenCommonConfig.CipherSuites: ICipherSuiteRegistry;
begin
  Result := FCipherSuites;
end;

function TFrozenCommonConfig.SignatureSchemes: ISignatureSchemeRegistry;
begin
  Result := FSignatureSchemes;
end;

function TFrozenCommonConfig.NamedGroups: INamedGroupRegistry;
begin
  Result := FNamedGroups;
end;

function TFrozenCommonConfig.SupportedVersions: TArray<UInt16>;
begin
  Result := System.Copy(FSupportedVersions);
end;

function TFrozenCommonConfig.PreferredGroups: TArray<UInt16>;
begin
  Result := System.Copy(FPreferredGroups);
end;

function TFrozenCommonConfig.AlpnProtocols: TArray<string>;
begin
  Result := System.Copy(FAlpnProtocols);
end;

function TFrozenCommonConfig.CertificateCompressors: TArray<ICertificateCompressor>;
begin
  Result := System.Copy(FCertificateCompressors);
end;

function TFrozenCommonConfig.CertificateDecompressors: TArray<ICertificateDecompressor>;
begin
  Result := System.Copy(FCertificateDecompressors);
end;

function TFrozenCommonConfig.CertificateCompressionCache: ICertificateCompressionCache;
begin
  // the shared instance, not a copy: every connection from this config memoizes into the
  // same cache - that cross-connection sharing is the whole point of this seam
  Result := FCertificateCompressionCache;
end;

function TFrozenCommonConfig.Credential: TTlsCredential;
begin
  Result := FCredential;
end;

function TFrozenCommonConfig.TrustStore: ITrustAnchorStore;
begin
  Result := FTrustStore;
end;

function TFrozenCommonConfig.CertificateVerifier: ICertificateVerifier;
begin
  Result := FCertificateVerifier;
end;

function TFrozenCommonConfig.CertificateChainLimits: TCertificateChainLimits;
begin
  Result := FChainLimits;
end;

function TFrozenCommonConfig.RevocationPosture: TRevocationPosture;
begin
  Result := FRevocationPosture;
end;

function TFrozenCommonConfig.CertificatePins: TArray<TBytes>;
var
  LI: Int32;
begin
  SetLength(Result, System.Length(FCertificatePins));
  for LI := 0 to System.High(FCertificatePins) do
    Result[LI] := System.Copy(FCertificatePins[LI]);
end;

function TFrozenCommonConfig.IntermediateCertificates: TArray<TBytes>;
var
  LI: Int32;
begin
  SetLength(Result, System.Length(FIntermediateCertificates));
  for LI := 0 to System.High(FIntermediateCertificates) do
    Result[LI] := System.Copy(FIntermediateCertificates[LI]);
end;

function TFrozenCommonConfig.DangerousTrust: TDangerousTrust;
begin
  Result := FDangerousTrust;
end;

function TFrozenCommonConfig.AsyncCertificateVerdict: TAsyncCertificateVerdict;
begin
  Result := FAsyncVerdict;
end;

function TFrozenCommonConfig.RequireExtendedMasterSecret: Boolean;
begin
  Result := FRequireExtendedMasterSecret;
end;

function TFrozenCommonConfig.ServerNameAcknowledgement: Boolean;
begin
  Result := FServerNameAck;
end;

function TFrozenCommonConfig.CipherSuitePreference: TServerCipherPreference;
begin
  Result := FCipherPreference;
end;

function TFrozenCommonConfig.AlpnRejectAll: Boolean;
begin
  Result := FAlpnRejectAll;
end;

function TFrozenCommonConfig.ClientCertificateAuthorities: TArray<TBytes>;
begin
  Result := FClientCertificateAuthorities;
end;

function TFrozenCommonConfig.Grease: Boolean;
begin
  Result := FGrease;
end;

function TFrozenCommonConfig.Resumption: Boolean;
begin
  Result := FResumption;
end;

function TFrozenCommonConfig.ExternalPsks: TArray<TExternalPsk>;
begin
  Result := System.Copy(FExternalPsks);
end;

function TFrozenCommonConfig.Clock: ITlsClock;
begin
  Result := FClock;
end;

{ TFrozenClientConfig }

function TFrozenClientConfig.CheckServerName: Boolean;
begin
  Result := FCheckServerName;
end;

function TFrozenClientConfig.RequestOcspStapling: Boolean;
begin
  Result := FRequestOcspStapling;
end;

function TFrozenClientConfig.SessionCache: ISessionCache;
begin
  Result := FSessionCache;
end;

function TFrozenClientConfig.EarlyData: Boolean;
begin
  Result := FEarlyData;
end;

function TFrozenClientConfig.ExternalPskRequired: Boolean;
begin
  Result := FExternalPskRequired;
end;

{ TFrozenServerConfig }

function TFrozenServerConfig.ClientAuth: TClientAuthMode;
begin
  Result := FClientAuth;
end;

function TFrozenServerConfig.SessionStore: ISessionStore;
begin
  Result := FSessionStore;
end;

function TFrozenServerConfig.SessionTicketKeys: ISessionTicketKeyManager;
begin
  Result := FSessionTicketKeys;
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

function TFrozenServerConfig.MaxEarlyData: UInt32;
begin
  Result := FMaxEarlyData;
end;

{ TTlsConfigViewBase }

constructor TTlsConfigViewBase.Create(const AOwner: TTlsConfigBuilder);
begin
  inherited Create;
  FOwner := AOwner;
end;

{ TTlsClientConfigBuilder }

function TTlsClientConfigBuilder.WithCipherSuites(
  const ARegistry: ICipherSuiteRegistry): ITlsClientConfigBuilder;
begin
  FOwner.WithCipherSuites(ARegistry);
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
  const AProtocols: TArray<string>): ITlsClientConfigBuilder;
begin
  FOwner.WithAlpnProtocols(AProtocols);
  Result := Self;
end;

function TTlsClientConfigBuilder.WithGrease(
  AEnable: Boolean): ITlsClientConfigBuilder;
begin
  FOwner.WithGrease(AEnable);
  Result := Self;
end;

function TTlsClientConfigBuilder.WithTrustStore(
  const AStore: ITrustAnchorStore): ITlsClientConfigBuilder;
begin
  FOwner.WithTrustStore(AStore);
  Result := Self;
end;

function TTlsClientConfigBuilder.WithTrustAnchors(
  const AData: TBytes): ITlsClientConfigBuilder;
begin
  FOwner.WithTrustAnchors(AData);
  Result := Self;
end;

function TTlsClientConfigBuilder.WithCertificateVerifier(
  const AVerifier: ICertificateVerifier): ITlsClientConfigBuilder;
begin
  FOwner.WithCertificateVerifier(AVerifier);
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

function TTlsClientConfigBuilder.WithCredential(const ACertificateChainData,
  APrivateKeyData: TBytes): ITlsClientConfigBuilder;
begin
  FOwner.WithCredential(ACertificateChainData, APrivateKeyData);
  Result := Self;
end;

function TTlsClientConfigBuilder.WithCredential(const ACertificateChainData,
  APrivateKeyData: TBytes; const APassword: string): ITlsClientConfigBuilder;
begin
  FOwner.WithCredential(ACertificateChainData, APrivateKeyData, APassword);
  Result := Self;
end;

function TTlsClientConfigBuilder.WithCredentialPkcs12(const AData: TBytes;
  const APassword: string): ITlsClientConfigBuilder;
begin
  FOwner.WithCredentialPkcs12(AData, APassword);
  Result := Self;
end;

function TTlsClientConfigBuilder.WithRevocation(
  APosture: TRevocationPosture): ITlsClientConfigBuilder;
begin
  FOwner.WithRevocation(APosture);
  Result := Self;
end;

function TTlsClientConfigBuilder.WithCertificatePinning(
  const APins: TArray<TBytes>): ITlsClientConfigBuilder;
begin
  FOwner.WithCertificatePinning(APins);
  Result := Self;
end;

function TTlsClientConfigBuilder.WithIntermediateCertificates(
  const AData: TBytes): ITlsClientConfigBuilder;
begin
  FOwner.WithIntermediateCertificates(AData);
  Result := Self;
end;

function TTlsClientConfigBuilder.WithNameCheck(
  AEnabled: Boolean): ITlsClientConfigBuilder;
begin
  FOwner.WithNameCheck(AEnabled);
  Result := Self;
end;

function TTlsClientConfigBuilder.WithOcspStaplingRequest(
  AEnabled: Boolean): ITlsClientConfigBuilder;
begin
  FOwner.WithOcspStaplingRequest(AEnabled);
  Result := Self;
end;

function TTlsClientConfigBuilder.WithDangerousInsecureSkipVerify(
  AEnabled: Boolean): ITlsClientConfigBuilder;
begin
  FOwner.WithDangerousInsecureSkipVerify(AEnabled);
  Result := Self;
end;

function TTlsClientConfigBuilder.WithAsyncCertificateVerdict(AEnabled: Boolean;
  ADeadlineMs: Cardinal): ITlsClientConfigBuilder;
begin
  FOwner.WithAsyncCertificateVerdict(AEnabled, ADeadlineMs);
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

function TTlsClientConfigBuilder.WithClock(
  const AClock: ITlsClock): ITlsClientConfigBuilder;
begin
  FOwner.WithClock(AClock);
  Result := Self;
end;

function TTlsClientConfigBuilder.WithExternalPreSharedKeys(
  const APsks: TArray<TExternalPsk>): ITlsClientConfigBuilder;
begin
  FOwner.WithExternalPreSharedKeys(APsks);
  Result := Self;
end;

function TTlsClientConfigBuilder.WithExternalPskRequired(
  AEnabled: Boolean): ITlsClientConfigBuilder;
begin
  FOwner.WithExternalPskRequired(AEnabled);
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
  const AProtocols: TArray<string>): ITlsServerConfigBuilder;
begin
  FOwner.WithAlpnProtocols(AProtocols);
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

function TTlsServerConfigBuilder.WithTrustStore(
  const AStore: ITrustAnchorStore): ITlsServerConfigBuilder;
begin
  FOwner.WithTrustStore(AStore);
  Result := Self;
end;

function TTlsServerConfigBuilder.WithTrustAnchors(
  const AData: TBytes): ITlsServerConfigBuilder;
begin
  FOwner.WithTrustAnchors(AData);
  Result := Self;
end;

function TTlsServerConfigBuilder.WithCertificateVerifier(
  const AVerifier: ICertificateVerifier): ITlsServerConfigBuilder;
begin
  FOwner.WithCertificateVerifier(AVerifier);
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

function TTlsServerConfigBuilder.WithCredential(const ACertificateChainData,
  APrivateKeyData: TBytes): ITlsServerConfigBuilder;
begin
  FOwner.WithCredential(ACertificateChainData, APrivateKeyData);
  Result := Self;
end;

function TTlsServerConfigBuilder.WithCredential(const ACertificateChainData,
  APrivateKeyData: TBytes; const APassword: string): ITlsServerConfigBuilder;
begin
  FOwner.WithCredential(ACertificateChainData, APrivateKeyData, APassword);
  Result := Self;
end;

function TTlsServerConfigBuilder.WithCredentialPkcs12(const AData: TBytes;
  const APassword: string): ITlsServerConfigBuilder;
begin
  FOwner.WithCredentialPkcs12(AData, APassword);
  Result := Self;
end;

function TTlsServerConfigBuilder.WithSniCredential(const AHost: string;
  const ACredential: TTlsCredential): ITlsServerConfigBuilder;
begin
  FOwner.WithSniCredential(AHost, ACredential);
  Result := Self;
end;

function TTlsServerConfigBuilder.WithSniCredential(const AHost: string;
  const ACertificateChainData, APrivateKeyData: TBytes): ITlsServerConfigBuilder;
begin
  FOwner.WithSniCredential(AHost, ACertificateChainData, APrivateKeyData);
  Result := Self;
end;

function TTlsServerConfigBuilder.WithSniCredential(const AHost: string;
  const ACertificateChainData, APrivateKeyData: TBytes;
  const APassword: string): ITlsServerConfigBuilder;
begin
  FOwner.WithSniCredential(AHost, ACertificateChainData, APrivateKeyData, APassword);
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

function TTlsServerConfigBuilder.WithRevocation(
  APosture: TRevocationPosture): ITlsServerConfigBuilder;
begin
  FOwner.WithRevocation(APosture);
  Result := Self;
end;

function TTlsServerConfigBuilder.WithCertificatePinning(
  const APins: TArray<TBytes>): ITlsServerConfigBuilder;
begin
  FOwner.WithCertificatePinning(APins);
  Result := Self;
end;

function TTlsServerConfigBuilder.WithIntermediateCertificates(
  const AData: TBytes): ITlsServerConfigBuilder;
begin
  FOwner.WithIntermediateCertificates(AData);
  Result := Self;
end;

function TTlsServerConfigBuilder.WithDangerousInsecureSkipVerify(
  AEnabled: Boolean): ITlsServerConfigBuilder;
begin
  FOwner.WithDangerousInsecureSkipVerify(AEnabled);
  Result := Self;
end;

function TTlsServerConfigBuilder.WithCertificateVerifyCallback(
  const ACallback: TTlsCertificateVerifyCallback): ITlsServerConfigBuilder;
begin
  FOwner.WithCertificateVerifyCallback(ACallback);
  Result := Self;
end;

function TTlsServerConfigBuilder.WithAsyncCertificateVerdict(AEnabled: Boolean;
  ADeadlineMs: Cardinal): ITlsServerConfigBuilder;
begin
  FOwner.WithAsyncCertificateVerdict(AEnabled, ADeadlineMs);
  Result := Self;
end;

function TTlsServerConfigBuilder.WithExternalPreSharedKeys(
  const APsks: TArray<TExternalPsk>): ITlsServerConfigBuilder;
begin
  FOwner.WithExternalPreSharedKeys(APsks);
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

function TTlsServerConfigBuilder.WithTicketLifetime(
  ASeconds: UInt32): ITlsServerConfigBuilder;
begin
  FOwner.WithTicketLifetime(ASeconds);
  Result := Self;
end;

function TTlsServerConfigBuilder.WithTicketCount(
  ACount: Int32): ITlsServerConfigBuilder;
begin
  FOwner.WithTicketCount(ACount);
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

function TTls13ClientConfigFacet.WithEarlyData(
  AEnabled: Boolean): ITls13ClientConfigFacet;
begin
  FOwner.WithClientEarlyData(AEnabled);
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

function TTls12ClientConfigFacet.Tls13: ITls13ClientConfigFacet;
begin
  Result := FOwner.Client13;
end;

function TTls12ClientConfigFacet.Build: ITlsClientConfig;
begin
  Result := FOwner.BuildClient;
end;

{ TTls13ServerConfigFacet }

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

function TTls12ServerConfigFacet.Tls13: ITls13ServerConfigFacet;
begin
  Result := FOwner.Server13;
end;

function TTls12ServerConfigFacet.Build: ITlsServerConfig;
begin
  Result := FOwner.BuildServer;
end;

{ TTlsConfigBuilder }

constructor TTlsConfigBuilder.Create(const AProvider: ICryptoProvider);
begin
  inherited Create;
  FProvider := AProvider;
  FFrozen := False;
  FHasCredential := False;
  FCheckServerName := True;
  // the client does not offer status_request unless asked: an unsolicited staple is rejected
  FRequestOcspStapling := False;
  // soft-fail revocation is the default posture (RFC 6960 stapled OCSP, honoring
  // must-staple); presets may harden it
  FRevocationPosture := TRevocationPosture.Soft;
  FChainLimits := TCertificateChainLimits.Defaults;
  // certificate compression is on by default (RFC 8879) with the built-in zlib backend;
  // seeded directly, so it does not mark the 1.3 facet as explicitly configured
  FCertificateCompressors := TZlibCertificateCompression.DefaultCompressors;
  FCertificateDecompressors := TZlibCertificateCompression.DefaultDecompressors;
  // the cross-connection compression cache is opt-in (like the session store): nil until a
  // caller supplies one via WithCertificateCompressionCache, so a stable body re-deflates
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
  // configuring an external PSK is an explicit "authenticate with this key" statement, so a
  // non-PSK server response is refused by default; a caller may opt into a certificate fallback
  FExternalPskRequired := True;
  FTicketLifetimeSeconds := DefaultTicketLifetimeSeconds;
  FTicketCount := DefaultTicketCount;
  // the endpoint reads the real system clock unless a caller injects one via WithClock
  FClock := TSystemClock.Create;
  FClient := TTlsClientConfigBuilder.Create(Self);
  FServer := TTlsServerConfigBuilder.Create(Self);
  FClient13 := TTls13ClientConfigFacet.Create(Self);
  FClient12 := TTls12ClientConfigFacet.Create(Self);
  FServer13 := TTls13ServerConfigFacet.Create(Self);
  FServer12 := TTls12ServerConfigFacet.Create(Self);
end;

procedure TTlsConfigBuilder.GuardMutable;
begin
  if FFrozen then
    raise EInvalidOperationTlsLibException.CreateRes(@SBuilderFrozen);
end;

procedure TTlsConfigBuilder.ValidateVersionScoping;
begin
  if FTls13Configured and not (TArrayUtilities.Contains<UInt16>(FSupportedVersions,
    TlsWireVersionTls13)) then
    raise EInvalidOperationTlsLibException.CreateRes(@STls13NotOffered);
  if FTls12Configured and not (TArrayUtilities.Contains<UInt16>(FSupportedVersions,
    TlsWireVersionTls12)) then
    raise EInvalidOperationTlsLibException.CreateRes(@STls12NotOffered);
end;

function TTlsConfigBuilder.WithCipherSuites(
  const ARegistry: ICipherSuiteRegistry): TTlsConfigBuilder;
begin
  GuardMutable;
  FCipherSuites := ARegistry;
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
begin
  GuardMutable;
  FSupportedVersions := AVersions;
  Result := Self;
end;

function TTlsConfigBuilder.WithPreferredGroups(
  const AGroups: TArray<UInt16>): TTlsConfigBuilder;
begin
  GuardMutable;
  FPreferredGroups := AGroups;
  Result := Self;
end;

function TTlsConfigBuilder.WithAlpnProtocols(
  const AProtocols: TArray<string>): TTlsConfigBuilder;
begin
  GuardMutable;
  FAlpnProtocols := AProtocols;
  Result := Self;
end;

function TTlsConfigBuilder.WithTrustStore(
  const AStore: ITrustAnchorStore): TTlsConfigBuilder;
begin
  GuardMutable;
  // anchor sources accumulate (union); a nil store is ignored
  if AStore <> nil then
    TArrayUtilities.Append<ITrustAnchorStore>(FAnchorStores, AStore);
  Result := Self;
end;

function TTlsConfigBuilder.WithTrustAnchors(const AData: TBytes): TTlsConfigBuilder;
begin
  GuardMutable;
  TArrayUtilities.Append<ITrustAnchorStore>(FAnchorStores,
    TTrustAnchorStore.Create(FProvider.LoadCertificateChain(AData))
    as ITrustAnchorStore);
  Result := Self;
end;

function TTlsConfigBuilder.WithCertificateVerifier(
  const AVerifier: ICertificateVerifier): TTlsConfigBuilder;
begin
  GuardMutable;
  if AVerifier <> nil then
  begin
    FCertificateVerifier := AVerifier;
    Inc(FVerifierCount);
  end;
  Result := Self;
end;

function TTlsConfigBuilder.ComposeTrustStore: ITrustAnchorStore;
begin
  case System.Length(FAnchorStores) of
    0:
      Result := nil;
    1:
      Result := FAnchorStores[0];
  else
    Result := TUnionTrustAnchorStore.Create(FAnchorStores);
  end;
end;

procedure TTlsConfigBuilder.ValidateTrustComposition;
begin
  if FVerifierCount > 1 then
    raise EInvalidOperationTlsLibException.CreateRes(@SDualVerifier);
  if (FVerifierCount = 1) and (System.Length(FAnchorStores) > 0) then
    raise EInvalidOperationTlsLibException.CreateRes(@SVerifierAnchorConflict);
end;

function TTlsConfigBuilder.WithCertificateChainLimits(
  const ALimits: TCertificateChainLimits): TTlsConfigBuilder;
begin
  GuardMutable;
  FChainLimits := ALimits;
  Result := Self;
end;

function TTlsConfigBuilder.WithCredential(
  const ACredential: TTlsCredential): TTlsConfigBuilder;
begin
  GuardMutable;
  FCredential := ACredential;
  FHasCredential := True;
  Result := Self;
end;

function TTlsConfigBuilder.WithCredential(const ACertificateChainData,
  APrivateKeyData: TBytes): TTlsConfigBuilder;
var
  LCredential: TTlsCredential;
begin
  GuardMutable;
  // a whole fresh record, so nothing (e.g. a staple) bleeds in from a prior credential
  LCredential.CertificateChain := FProvider.LoadCertificateChain(ACertificateChainData);
  LCredential.PrivateKey := FProvider.ImportSigningKey(APrivateKeyData);
  FCredential := LCredential;
  FHasCredential := True;
  Result := Self;
end;

function TTlsConfigBuilder.WithCredential(const ACertificateChainData,
  APrivateKeyData: TBytes; const APassword: string): TTlsConfigBuilder;
var
  LCredential: TTlsCredential;
begin
  GuardMutable;
  // a whole fresh record, so nothing (e.g. a staple) bleeds in from a prior credential
  LCredential.CertificateChain := FProvider.LoadCertificateChain(ACertificateChainData);
  LCredential.PrivateKey := FProvider.ImportSigningKey(APrivateKeyData, APassword);
  FCredential := LCredential;
  FHasCredential := True;
  Result := Self;
end;

function TTlsConfigBuilder.WithCredentialPkcs12(const AData: TBytes;
  const APassword: string): TTlsConfigBuilder;
begin
  GuardMutable;
  FCredential := FProvider.ImportPkcs12(AData, APassword);
  FHasCredential := True;
  Result := Self;
end;

function TTlsConfigBuilder.WithSniCredential(const AHost: string;
  const ACredential: TTlsCredential): TTlsConfigBuilder;
var
  LN: Integer;
begin
  GuardMutable;
  LN := System.Length(FSniCredentialEntries);
  System.SetLength(FSniCredentialEntries, LN + 1);
  FSniCredentialEntries[LN].Host := AHost;
  FSniCredentialEntries[LN].Credential := ACredential;
  Result := Self;
end;

function TTlsConfigBuilder.WithSniCredential(const AHost: string;
  const ACertificateChainData, APrivateKeyData: TBytes): TTlsConfigBuilder;
var
  LCredential: TTlsCredential;
begin
  GuardMutable;
  LCredential.CertificateChain := FProvider.LoadCertificateChain(ACertificateChainData);
  LCredential.PrivateKey := FProvider.ImportSigningKey(APrivateKeyData);
  Result := WithSniCredential(AHost, LCredential);
end;

function TTlsConfigBuilder.WithSniCredential(const AHost: string;
  const ACertificateChainData, APrivateKeyData: TBytes;
  const APassword: string): TTlsConfigBuilder;
var
  LCredential: TTlsCredential;
begin
  GuardMutable;
  LCredential.CertificateChain := FProvider.LoadCertificateChain(ACertificateChainData);
  LCredential.PrivateKey := FProvider.ImportSigningKey(APrivateKeyData, APassword);
  Result := WithSniCredential(AHost, LCredential);
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
  LSans := FProvider.CertificateDnsNames(ACredential.CertificateChain[0]);
  if Pos('*', AHost) = 0 then
    // an exact host must be covered by the leaf's dNSName SANs (RFC 6125/9525)
    LOk := TEndpointIdentity.Matches(AHost, LSans, nil)
  else
  begin
    // only a single left-most-label wildcard over a non-empty suffix is matchable at runtime
    // (RFC 6125); a wildcard anywhere else validates against a literal SAN yet never selects a host
    if (System.Length(AHost) < 3) or (System.Copy(AHost, 1, 2) <> '*.') or
      (Pos('*', System.Copy(AHost, 3, System.Length(AHost) - 2)) <> 0) then
      raise EInvalidOperationTlsLibException.CreateResFmt(@SSniWildcardMalformed, [AHost]);
    // a wildcard entry needs the leaf to carry that same wildcard SAN
    LOk := False;
    for LI := 0 to System.High(LSans) do
      if LowerCase(LSans[LI]) = LowerCase(AHost) then
      begin
        LOk := True;
        Break;
      end;
  end;
  if not LOk then
    raise EInvalidOperationTlsLibException.CreateResFmt(@SSniCertMismatch, [AHost]);
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
  end;
  // the single credential (WithCredential), if any, is the no-SNI / no-match default
  Result := TSniCredentialResolver.Create(FSniCredentialEntries, FHasCredential, FCredential)
    as ITlsServerCredentialResolver;
end;

function TTlsConfigBuilder.WithCertificateCompressors(
  const ACompressors: TArray<ICertificateCompressor>): TTlsConfigBuilder;
begin
  GuardMutable;
  FCertificateCompressors := ACompressors;
  FTls13Configured := True;
  Result := Self;
end;

function TTlsConfigBuilder.WithCertificateDecompressors(
  const ADecompressors: TArray<ICertificateDecompressor>): TTlsConfigBuilder;
begin
  GuardMutable;
  FCertificateDecompressors := ADecompressors;
  FTls13Configured := True;
  Result := Self;
end;

function TTlsConfigBuilder.WithCertificateCompressionCache(
  const ACache: ICertificateCompressionCache): TTlsConfigBuilder;
begin
  GuardMutable;
  FCertificateCompressionCache := ACache;
  FTls13Configured := True;
  Result := Self;
end;

function TTlsConfigBuilder.WithExtendedMasterSecret(
  ARequire: Boolean): TTlsConfigBuilder;
begin
  GuardMutable;
  FRequireExtendedMasterSecret := ARequire;
  FTls12Configured := True;
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
begin
  GuardMutable;
  FClientCertificateAuthorities := AAuthorities;
  Result := Self;
end;

function TTlsConfigBuilder.WithGrease(AEnable: Boolean): TTlsConfigBuilder;
begin
  GuardMutable;
  FGrease := AEnable;
  Result := Self;
end;

function TTlsConfigBuilder.WithNameCheck(AEnabled: Boolean): TTlsConfigBuilder;
begin
  GuardMutable;
  FCheckServerName := AEnabled;
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

function TTlsConfigBuilder.WithRevocation(
  APosture: TRevocationPosture): TTlsConfigBuilder;
begin
  GuardMutable;
  FRevocationPosture := APosture;
  Result := Self;
end;

function TTlsConfigBuilder.WithCertificatePinning(
  const APins: TArray<TBytes>): TTlsConfigBuilder;
begin
  GuardMutable;
  FCertificatePins := APins;
  Result := Self;
end;

function TTlsConfigBuilder.WithIntermediateCertificates(
  const AData: TBytes): TTlsConfigBuilder;
var
  LCerts: TArray<TBytes>;
  LI: Int32;
begin
  GuardMutable;
  // parse the bundle and accumulate, so successive calls add more intermediates
  LCerts := FProvider.LoadCertificateChain(AData);
  for LI := 0 to System.High(LCerts) do
    TArrayUtilities.Append<TBytes>(FIntermediateCertificates, LCerts[LI]);
  Result := Self;
end;

function TTlsConfigBuilder.WithDangerousInsecureSkipVerify(
  AEnabled: Boolean): TTlsConfigBuilder;
begin
  GuardMutable;
  FDangerousTrust.InsecureSkipVerify := AEnabled;
  Result := Self;
end;

function TTlsConfigBuilder.WithCertificateVerifyCallback(
  const ACallback: TTlsCertificateVerifyCallback): TTlsConfigBuilder;
begin
  GuardMutable;
  FDangerousTrust.VerifyCallback := ACallback;
  Result := Self;
end;

function TTlsConfigBuilder.WithAsyncCertificateVerdict(AEnabled: Boolean;
  ADeadlineMs: Cardinal): TTlsConfigBuilder;
begin
  GuardMutable;
  FAsyncVerdict.Enabled := AEnabled;
  FAsyncVerdict.DeadlineMs := ADeadlineMs;
  Result := Self;
end;

function TTlsConfigBuilder.WithResumption(AEnabled: Boolean): TTlsConfigBuilder;
begin
  GuardMutable;
  FResumption := AEnabled;
  Result := Self;
end;

function TTlsConfigBuilder.WithSessionCache(
  const ACache: ISessionCache): TTlsConfigBuilder;
begin
  GuardMutable;
  FSessionCache := ACache;
  Result := Self;
end;

function TTlsConfigBuilder.WithClock(
  const AClock: ITlsClock): TTlsConfigBuilder;
begin
  GuardMutable;
  FClock := AClock;
  Result := Self;
end;

function TTlsConfigBuilder.WithExternalPreSharedKeys(
  const APsks: TArray<TExternalPsk>): TTlsConfigBuilder;
begin
  GuardMutable;
  FExternalPsks := APsks;
  Result := Self;
end;

function TTlsConfigBuilder.WithExternalPskRequired(
  AEnabled: Boolean): TTlsConfigBuilder;
begin
  GuardMutable;
  FExternalPskRequired := AEnabled;
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
  FSessionTicketKeys := AKeys;
  Result := Self;
end;

function TTlsConfigBuilder.WithDefaultSessionTicketKeys: TTlsConfigBuilder;
begin
  GuardMutable;
  // request a default STEK minted from THIS builder's provider + clock at BuildServer time;
  // an explicit WithSessionTicketKeys always wins (resolved in BuildServer, order-insensitive)
  FWantDefaultSessionTicketKeys := True;
  Result := Self;
end;

function TTlsConfigBuilder.WithTicketLifetime(ASeconds: UInt32): TTlsConfigBuilder;
begin
  GuardMutable;
  if ASeconds > MaxTicketLifetimeSeconds then
    raise EInvalidOperationTlsLibException.CreateRes(@STicketLifetimeTooLong);
  FTicketLifetimeSeconds := ASeconds;
  Result := Self;
end;

function TTlsConfigBuilder.WithTicketCount(ACount: Int32): TTlsConfigBuilder;
begin
  GuardMutable;
  FTicketCount := ACount;
  Result := Self;
end;

function TTlsConfigBuilder.WithClientEarlyData(AEnabled: Boolean): TTlsConfigBuilder;
begin
  GuardMutable;
  FClientEarlyData := AEnabled;
  FTls13Configured := True;
  Result := Self;
end;

function TTlsConfigBuilder.WithServerEarlyData(AMaxBytes: UInt32): TTlsConfigBuilder;
begin
  GuardMutable;
  FMaxEarlyData := AMaxBytes;
  FTls13Configured := True;
  Result := Self;
end;

function TTlsConfigBuilder.WithAntiReplay(
  const AStrategy: IAntiReplayStrategy): TTlsConfigBuilder;
begin
  GuardMutable;
  FAntiReplay := AStrategy;
  FTls13Configured := True;
  Result := Self;
end;

function TTlsConfigBuilder.Client13: ITls13ClientConfigFacet;
begin
  Result := FClient13;
end;

function TTlsConfigBuilder.Client12: ITls12ClientConfigFacet;
begin
  Result := FClient12;
end;

function TTlsConfigBuilder.Server13: ITls13ServerConfigFacet;
begin
  Result := FServer13;
end;

function TTlsConfigBuilder.Server12: ITls12ServerConfigFacet;
begin
  Result := FServer12;
end;

function TTlsConfigBuilder.Client: ITlsClientConfigBuilder;
begin
  Result := FClient;
end;

function TTlsConfigBuilder.Server: ITlsServerConfigBuilder;
begin
  Result := FServer;
end;

function TTlsConfigBuilder.BuildClient: ITlsClientConfig;
var
  LConfig: TFrozenClientConfig;
begin
  // a builder is single-use
  GuardMutable;
  // SNI-keyed server credential selection has no meaning on a client; reject it rather than
  // silently dropping it (the raw builder exposes both facets)
  if (System.Length(FSniCredentialEntries) > 0) or (FCredentialResolver <> nil) then
    raise EInvalidOperationTlsLibException.CreateRes(@SClientSideServerCredential);
  ValidateTrustComposition;
  // a client authenticates the server by its certificate or by an out-of-band external PSK
  // (RFC 9258); at least one trust source or a configured external PSK is required (no
  // silent-insecure). A PSK-only client verifies no certificate.
  if (System.Length(FAnchorStores) = 0) and (FVerifierCount = 0) and
    (System.Length(FExternalPsks) = 0) then
    raise EInvalidOperationTlsLibException.CreateRes(@SNoTrustStore);
  // a Hard revocation posture rejects a peer whose certificate carries no stapled OCSP response
  // (missing staple -> Indeterminate -> reject), so it silently always-rejects unless the client
  // obtains revocation status some way: by requesting a staple, or by a live OCSP/CRL verdict
  // resolver (the async-verdict seam). Fail fast at Build rather than reject every connection.
  if (FRevocationPosture = TRevocationPosture.Hard) and (not FRequestOcspStapling) and
    (not FAsyncVerdict.Enabled) then
    raise EInvalidOperationTlsLibException.CreateRes(@SHardRevocationUnusable);
  ValidateVersionScoping;
  LConfig := TFrozenClientConfig.Create;
  LConfig.FProvider := FProvider;
  LConfig.FCipherSuites := FCipherSuites;
  LConfig.FSignatureSchemes := FSignatureSchemes;
  LConfig.FNamedGroups := FNamedGroups;
  LConfig.FSupportedVersions := FSupportedVersions;
  LConfig.FPreferredGroups := FPreferredGroups;
  LConfig.FAlpnProtocols := FAlpnProtocols;
  LConfig.FCertificateCompressors := FCertificateCompressors;
  LConfig.FCertificateDecompressors := FCertificateDecompressors;
  // the shared instance carries over uncopied: connections share one cache (server path)
  LConfig.FCertificateCompressionCache := FCertificateCompressionCache;
  LConfig.FCredential := FCredential;
  LConfig.FTrustStore := ComposeTrustStore;
  LConfig.FCertificateVerifier := FCertificateVerifier;
  LConfig.FChainLimits := FChainLimits;
  LConfig.FRevocationPosture := FRevocationPosture;
  LConfig.FCertificatePins := FCertificatePins;
  LConfig.FIntermediateCertificates := FIntermediateCertificates;
  LConfig.FDangerousTrust := FDangerousTrust;
  LConfig.FAsyncVerdict := FAsyncVerdict;
  LConfig.FRequireExtendedMasterSecret := FRequireExtendedMasterSecret;
  LConfig.FServerNameAck := FServerNameAck;
  LConfig.FCipherPreference := FCipherPreference;
  LConfig.FAlpnRejectAll := FAlpnRejectAll;
  LConfig.FClientCertificateAuthorities := FClientCertificateAuthorities;
  LConfig.FGrease := FGrease;
  LConfig.FResumption := FResumption;
  LConfig.FExternalPsks := FExternalPsks;
  LConfig.FCheckServerName := FCheckServerName;
  LConfig.FRequestOcspStapling := FRequestOcspStapling;
  LConfig.FSessionCache := FSessionCache;
  LConfig.FClock := FClock;
  LConfig.FEarlyData := FClientEarlyData;
  LConfig.FExternalPskRequired := FExternalPskRequired;
  FFrozen := True;
  Result := LConfig;
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
    (FCredentialResolver = nil) and (System.Length(FExternalPsks) = 0) then
    raise EInvalidOperationTlsLibException.CreateRes(@SNoCredential);
  ValidateTrustComposition;
  // client authentication verifies the peer chain against a trust source; without one the
  // server would only fail closed at handshake time, so reject it at build (fail fast)
  if (FClientAuth <> TClientAuthMode.None) and
    (System.Length(FAnchorStores) = 0) and (FVerifierCount = 0) then
    raise EInvalidOperationTlsLibException.CreateRes(@SNoClientAuthTrustStore);
  // a Hard revocation posture on the client certificate rejects a client whose cert carries no
  // definite non-revoked status. A client cannot staple, so the only status source is a live
  // OCSP/CRL verdict resolver; without one, Hard would reject every client. Fail fast at Build
  // (only meaningful when client authentication is actually requested).
  if (FClientAuth <> TClientAuthMode.None) and
    (FRevocationPosture = TRevocationPosture.Hard) and (not FAsyncVerdict.Enabled) then
    raise EInvalidOperationTlsLibException.CreateRes(@SHardServerRevocationUnusable);
  ValidateVersionScoping;
  LConfig := TFrozenServerConfig.Create;
  LConfig.FProvider := FProvider;
  LConfig.FCipherSuites := FCipherSuites;
  LConfig.FSignatureSchemes := FSignatureSchemes;
  LConfig.FNamedGroups := FNamedGroups;
  LConfig.FSupportedVersions := FSupportedVersions;
  LConfig.FPreferredGroups := FPreferredGroups;
  LConfig.FAlpnProtocols := FAlpnProtocols;
  LConfig.FCertificateCompressors := FCertificateCompressors;
  LConfig.FCertificateDecompressors := FCertificateDecompressors;
  // the shared instance carries over uncopied: connections share one cache (server path)
  LConfig.FCertificateCompressionCache := FCertificateCompressionCache;
  LConfig.FCredential := FCredential;
  LConfig.FTrustStore := ComposeTrustStore;
  LConfig.FCertificateVerifier := FCertificateVerifier;
  LConfig.FChainLimits := FChainLimits;
  LConfig.FRevocationPosture := FRevocationPosture;
  LConfig.FCertificatePins := FCertificatePins;
  LConfig.FIntermediateCertificates := FIntermediateCertificates;
  LConfig.FDangerousTrust := FDangerousTrust;
  LConfig.FAsyncVerdict := FAsyncVerdict;
  LConfig.FRequireExtendedMasterSecret := FRequireExtendedMasterSecret;
  LConfig.FServerNameAck := FServerNameAck;
  LConfig.FCipherPreference := FCipherPreference;
  LConfig.FAlpnRejectAll := FAlpnRejectAll;
  LConfig.FClientCertificateAuthorities := FClientCertificateAuthorities;
  LConfig.FGrease := FGrease;
  LConfig.FResumption := FResumption;
  LConfig.FExternalPsks := FExternalPsks;
  LConfig.FClock := FClock;
  LConfig.FClientAuth := FClientAuth;
  LConfig.FSessionStore := FSessionStore;
  LConfig.FCredentialResolver := ComposeCredentialResolver;
  // explicit keys always win; otherwise mint the default STEK from THIS builder's injected
  // provider + clock (never a concrete default provider), scoped to the config's life. With
  // resumption on and neither ticket keys nor a session store configured, the STEK is minted so
  // a server resumes out of the box rather than silently issuing nothing; a store-only (stateful)
  // server and WithResumption(False) both opt out.
  if FSessionTicketKeys <> nil then
    LConfig.FSessionTicketKeys := FSessionTicketKeys
  else if FWantDefaultSessionTicketKeys or (FResumption and (FSessionStore = nil)) then
    LConfig.FSessionTicketKeys := TStekTicketKeyManager.CreateDefault(FProvider, FClock);
  LConfig.FAntiReplay := FAntiReplay;
  LConfig.FTicketLifetimeSeconds := FTicketLifetimeSeconds;
  LConfig.FTicketCount := FTicketCount;
  LConfig.FMaxEarlyData := FMaxEarlyData;
  FFrozen := True;
  Result := LConfig;
end;

end.
