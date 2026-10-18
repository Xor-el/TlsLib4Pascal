{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpTls13ClientStateMachine;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpAlpnProtocols,
  TlpArrayUtilities,
  TlpTlsAlert,
  TlpTlsVersion,
  TlpTlsLibExceptions,
  TlpISecretBuffer,
  TlpICryptoProvider,
  TlpIPkixProvider,
  TlpINamedGroup,
  TlpIKeyExchangePrivateKey,
  TlpIKeySchedule,
  TlpTls13KeySchedule,
  TlpTls12KeySchedule,
  TlpITranscriptHash,
  TlpTranscriptHash,
  TlpCryptoDomainTypes,
  TlpNegotiationTypes,
  TlpINegotiation,
  TlpNegotiationPolicy,
  TlpWireReader,
  TlpExtensionVector,
  TlpIWireWriter,
  TlpWireWriter,
  TlpWireVectorMarker,
  TlpExtensionContext,
  TlpITlsExtension,
  TlpCoreExtensions,
  TlpGrease,
  TlpHandshakeMessage,
  TlpHandshakeMessages,
  TlpClientSessionPolicy,
  TlpCertificateCompression,
  TlpICertificateCompression,
  TlpICertificateCompressionCache,
  TlpCertificateVerify,
  TlpChainAlgorithmPolicy,
  TlpPeerAuthentication,
  TlpICertificateTrust,
  TlpCertificateLimits,
  TlpTrustTypes,
  TlpTrustPolicy,
  TlpServerName,
  TlpISigningKey,
  TlpTlsCredential,
  TlpISession,
  TlpIClock,
  TlpIKeyLog,
  TlpSession,
  TlpExternalPskImporter,
  TlpIEch,
  TlpEchConfig,
  TlpIEchClientOrchestrator,
  TlpEchClientOrchestrator,
  TlpITlsEngine,
  TlpHandshakeEffect,
  TlpTlsConnectionInfo,
  TlpIHandshakeMachine,
  TlpTls13HandshakeBase;

type
  /// <summary>The inputs a client handshake needs to build and drive its flight.</summary>
  TClientHandshakeParams = record
    Crypto: ICryptoProvider;
    Inspector: ICertificateInspector;
    Group: INamedGroup;
    GroupCode: UInt16;
    /// <summary>The supported_groups the client advertises (preference order). When
    /// it lists a group beyond the one it key-shares, the server may answer with a
    /// HelloRetryRequest for it. Empty defaults to just GroupCode.</summary>
    OfferedGroups: TArray<UInt16>;
    /// <summary>Builds the group for a HelloRetryRequest's requested code. Required
    /// only when OfferedGroups lists a group other than GroupCode.</summary>
    GroupRegistry: INamedGroupRegistry;
    CipherSuites: ICipherSuiteRegistry;
    ExtensionRegistry: IExtensionRegistry;
    OfferedSuites: TArray<UInt16>;
    OfferedSchemes: TArray<UInt16>;
    /// <summary>The ALPN protocols to offer (RFC 7301), in preference order; empty
    /// omits the extension.</summary>
    AlpnProtocols: TArray<TBytes>;
    /// <summary>The record_size_limit (RFC 8449) plaintext value to advertise, in
    /// [64, 2^14]; 0 leaves the extension unoffered.</summary>
    RecordSizeLimit: Int32;
    /// <summary>The certificate-compression algorithms the client can decompress
    /// (RFC 8879), in preference order; empty omits compress_certificate.</summary>
    CertificateDecompressors: TArray<ICertificateDecompressor>;
    /// <summary>The algorithms the client can compress its own Certificate with (RFC 8879),
    /// used when the server's CertificateRequest advertises a matching one; empty never
    /// compresses.</summary>
    CertificateCompressors: TArray<ICertificateCompressor>;
    /// <summary>Memoizes the compressed client Certificate across connections, so a stable
    /// certificate deflates once; nil compresses on every handshake.</summary>
    CertificateCompressionCache: ICertificateCompressionCache;
    /// <summary>Whether to sprinkle GREASE (RFC 8701) codepoints across the offers.</summary>
    Grease: Boolean;
    /// <summary>Whether the client offers the status_request (OCSP stapling) extension
    /// (RFC 6066). Off by default, so an unsolicited server staple is rejected.</summary>
    RequestOcspStapling: Boolean;
    /// <summary>When set, the ClientHello also offers TLS 1.2 (supported_versions gains
    /// 1.2 and extended_master_secret is offered) so one hello serves a dual-version
    /// handshake; OfferedSuites is expected to already carry the 1.2 suites.</summary>
    AlsoOfferTls12: Boolean;
    ClientRandom: TBytes;
    LegacySessionId: TBytes;
    ServerName: string;
    /// <summary>The peer-chain resource caps enforced at the Certificate decode boundary
    /// (before any verifier) and used to bound the inbound Certificate message.</summary>
    CertificateChainLimits: TCertificateChainLimits;
    /// <summary>Decides whether the server's certificate chain is trusted. Required:
    /// with none configured the handshake fails closed.</summary>
    CertificateVerifier: IServerCertificateVerifier;
    /// <summary>Verifies a resumed server's stored chain on reverify-on-resume: no Certificate
    /// and no fresh staple are on the wire, so must-staple never fires. nil falls back to
    /// CertificateVerifier (never looser than it).</summary>
    ResumeCertificateVerifier: IServerCertificateVerifier;
    /// <summary>Verifies the server certificate of an ECH reject, always matching public_name
    /// (RFC 9849 sec. 6.1.7) even when CertificateVerifier skips the name match. nil uses
    /// CertificateVerifier.</summary>
    EchRejectCertificateVerifier: IServerCertificateVerifier;
    /// <summary>The name the server certificate must be valid for (RFC 9525).</summary>
    ExpectedServerName: TServerName;
    /// <summary>The client's credential for mutual TLS: presented when the server sends
    /// a CertificateRequest and the credential can satisfy it. An empty chain sends an
    /// empty client Certificate (declining to authenticate).</summary>
    ClientCredential: TTlsCredential;
    /// <summary>When set, the client offers a cached resumption PSK (if one exists for
    /// the server) and caches the NewSessionTickets the server issues. Nil disables
    /// resumption.</summary>
    SessionCache: ISessionCache;
    /// <summary>An opaque tag folded into the cache identity so a shared cache does not resume
    /// across configurations; empty (the direct sans-IO default) leaves the identity unscoped.</summary>
    SessionScope: TBytes;
    /// <summary>How the client verifies a resumed server: ReuseOriginal (default) reuses the
    /// original authentication; Reverify checks the stored chain before offering the session and
    /// offers none whose chain fails.</summary>
    ResumeVerification: TResumeVerification;
    /// <summary>The clock read for a resumption PSK's obfuscated_ticket_age and ticket-lifetime
    /// expiry (RFC 9846 4.3.11 / 4.7.1). A required input: the factory supplies one from the
    /// config, and a direct sans-IO caller must set it.</summary>
    Clock: ITlsClock;
    /// <summary>The dangerous key-log sink; nil reports nothing.</summary>
    KeyLog: IKeyLog;
    /// <summary>The out-of-band external PSKs (RFC 9258) to import and offer, in preference
    /// order (each imported for every supported KDF hash), alongside any cached resumption
    /// session. Empty leaves external PSK off.</summary>
    ExternalPsks: TArray<TExternalPsk>;
    /// <summary>When set, the client requires the server to select one of its offered PSKs:
    /// a ServerHello that omits pre_shared_key is a fatal missing_extension rather than a
    /// fall-through to certificate authentication. Set for a PSK-only client (external PSKs
    /// configured with no certificate trust to fall back on).</summary>
    RequirePsk: Boolean;
    /// <summary>The cache key's server identity (e.g. host:port); empty falls back to
    /// ServerName.</summary>
    ServerIdentity: string;
    /// <summary>When set (with a resumption PSK whose ticket permits it), the client
    /// offers 0-RTT early data and installs the early write epoch. OFF by default.</summary>
    EarlyDataEnabled: Boolean;
    /// <summary>How a peer-certificate verdict is deferred out-of-band (see TVerdictDeferral):
    /// augment-only and fail-closed, None by default.</summary>
    Deferral: TVerdictDeferral;
    /// <summary>The configured revocation posture a parked verdict is decided at.</summary>
    RevocationPosture: TRevocationPosture;
    /// <summary>The Encrypted Client Hello policy (RFC 9849), or nil when ECH is not
    /// offered. When present the client builds the inner/outer ClientHello, seals the
    /// inner, and detects accept/reject from the ServerHello.</summary>
    EchPolicy: IEchClientPolicy;
  end;

  /// <summary>
  /// The TLS 1.3 client happy-path machine: it builds the ClientHello, then on the
  /// server flight installs the handshake keys, verifies the server certificate and
  /// Finished, sends its own Finished, and installs the application keys. It returns
  /// effects and never touches the record layer; the driver applies them. Certificate
  /// trust runs inline and fail-closed.
  /// </summary>
  TTls13ClientStateMachine = class sealed(TTls13HandshakeBase, ITls13ClientReplay)
  strict private
  type
    TPhase = (Initial, WaitServerHello, WaitEncryptedExtensions, WaitCertificate,
      WaitCertificateVerify, WaitServerFinished, WaitResumeVerdict, Connected);
  var
    FParams: TClientHandshakeParams;
    // ITls13ClientReplay: a supplied ClientHello emitted verbatim, empty otherwise
    FVerbatimClientHello: TBytes;
    FEphemeralPrivate: IKeyExchangePrivateKey;
    FEphemeralPublic: TBytes;
    FCurrentGroup: INamedGroup;
    FCurrentGroupCode: UInt16;
    // the client random and expected server identity actually in force: the outer FParams values,
    // or the ECH inner random / public_name once ECH is accepted / rejected. FParams stays
    // immutable (a caller-owned record copy); these carry the post-ECH swap instead.
    FActiveClientRandom: TBytes;
    FExpectedName: TServerName;
    FCookie: TBytes;
    FRetried: Boolean;
    /// <summary>The GREASE seed, chosen once for the first ClientHello and reused on a
    /// HelloRetryRequest retry so the retry's GREASE codepoints match the first exactly
    /// (RFC 9846 4.2.2 requires an otherwise-identical second ClientHello). -1 until chosen.</summary>
    FGreaseSeed: Int32;
    /// <summary>Whether the HelloRetryRequest requested a key_share group change. On a group
    /// change the retry sends a single key_share for the new group (no GREASE); a cookie-only
    /// retry keeps the first ClientHello's key_share unchanged (RFC 9846 4.2.2).</summary>
    FHrrChangedGroup: Boolean;
    /// <summary>Guards the single middlebox-compatibility change_cipher_spec so it is
    /// emitted at most once (RFC 9846 E.4).</summary>
    FMiddleboxCcsSent: Boolean;
    FOfferedExtensions: TArray<UInt16>;
    FCertificateChain: TArray<TBytes>;
    // held until the server's CertificateVerify verifies, which is when the verdict parks
    FPeerVerified: TVerifiedChain;
    // the server leaf parsed once for the well-formed gate, reused for the signing-policy
    // check and its SubjectPublicKeyInfo; released once the signature is verified
    FParsedServerLeaf: IInspectedCertificate;
    /// <summary>The stapled OCSP response the server delivered in the leaf CertificateEntry
    /// (RFC 9846 4.5.1.1); empty when none was stapled. Fed to the trust verdict.</summary>
    FReceivedOcspStaple: TBytes;
    /// <summary>A CertificateRequest was received, so the client owes a Certificate
    /// (and, when it has a usable credential, a CertificateVerify).</summary>
    FCertificateRequested: Boolean;
    FRequestContext: TBytes;
    FClientAuthSchemes: TArray<UInt16>;
    FClientAuthCertSchemes: TArray<UInt16>;
    /// <summary>The DER DistinguishedName certificate_authorities the server named in its
    /// CertificateRequest (RFC 9846 4.3.4); surfaced for read-only connection info.</summary>
    FRequestedCertificateAuthorities: TArray<TBytes>;
    /// <summary>The compress_certificate algorithms the server's CertificateRequest advertised
    /// (RFC 8879), used to pick a compressor for the client Certificate.</summary>
    FServerCertCompressionAlgorithms: TArray<UInt16>;
    /// <summary>The pre-shared keys this ClientHello offered, in offered order (empty when
    /// none): a single resumption PSK from the cache and/or the imported external PSKs (RFC
    /// 9258), one entry per (external PSK, supported KDF hash). The server's selected_identity
    /// indexes this list.</summary>
    FPskOffers: TArray<IPreSharedKey>;
    /// <summary>The offered PSK the server selected (nil when none was accepted).</summary>
    FAcceptedPsk: IPreSharedKey;
    // the peer chain the offered resumption session carried (empty for an external PSK)
    FResumptionPeerCertificates: TArray<TBytes>;
    FResumptionPskIdentity: TBytes;
    FResumptionPskBinding: TBytes;
    FResumptionPeerSignatureScheme: UInt16;
    // when this connection's chain was authenticated: the offered session's time on a resumption,
    // else the moment the server Finished verified; tickets received on it keep it
    FAuthenticatedAtMs: UInt64;
    /// <summary>The tickets this connection cached, which a fatal alert removes.</summary>
    FStoredSessions: TArray<IResumableSession>;
    FPeerSignatureScheme: UInt16;
    FResumedFromTicket: Boolean;
    // this handshake's PSK identity and binding, kept because the accepted PSK is released
    FSessionPskIdentity: TBytes;
    FSessionPskBinding: TBytes;
    // the path the offer-time re-check validated, surfaced to an async park so a live resolver
    // authenticates against the PKIX issuer rather than a re-guess
    FResumeValidatedPath: TArray<TBytes>;
    /// <summary>A cached TLS 1.2 session this dual-version ClientHello offers for 1.2
    /// resumption (nil otherwise), and the session id it put in legacy_session_id so a 1.2
    /// hand-off can match the server's abbreviated echo. A 1.3 server ignores both.</summary>
    FTls12ResumptionSession: ITls12ResumableSession;
    FTls12OfferedSessionId: TBytes;
    /// <summary>The legacy_session_id this ClientHello actually sent, which the server must
    /// echo (RFC 9846 4.2.3); normally the middlebox id, but the offered 1.2 session id when
    /// resuming 1.2.</summary>
    FSentLegacySessionId: TBytes;
    /// <summary>The exact first ClientHello bytes as sent (binder patched), kept so a
    /// HelloRetryRequest can synthesize message_hash under the retry-selected hash even when
    /// a single-PSK resumption pre-activated the transcript under a different hash.</summary>
    FSentClientHelloRaw: TBytes;
    /// <summary>Whether the ServerHello selected one of our offered PSKs (psk_dhe_ke).</summary>
    FPskAccepted: Boolean;
    /// <summary>Whether this ClientHello offered 0-RTT early data.</summary>
    FEarlyDataOffered: Boolean;
    FEarlyDataEverOffered: Boolean;
    FEarlyReasonAtOffer: TEarlyDataReason;
    /// <summary>Whether the server accepted the offered early data (EncryptedExtensions).</summary>
    FEarlyDataAccepted: Boolean;
    /// <summary>Whether the selected suite matches the resumption PSK's bound suite; 0-RTT
    /// is bound to the ticket's exact suite, so accepted early data under a different one
    /// is illegal (RFC 9846 4.3.10).</summary>
    FEarlySuiteMatched: Boolean;
    /// <summary>Whether a single offered PSK pre-activated the transcript at Start (so the
    /// binder and early keys ran under that PSK's hash), and the hash it was activated under.
    /// If the server then rejects the PSK and (without a HelloRetryRequest) selects a suite
    /// with a different hash - a 0-RTT reject that changes the PRF - the transcript must be
    /// rebuilt from the raw first ClientHello under the newly selected hash (RFC 9846 4.1).</summary>
    FTranscriptPreActivated: Boolean;
    FPreActivatedHash: THashAlgorithm;
    /// <summary>The ALPN protocol negotiated in EncryptedExtensions, stored on a ticket.</summary>
    FNegotiatedAlpn: TBytes;
    /// <summary>Encrypted Client Hello (RFC 9849): owns the per-connection ECH mechanics and
    /// state (the sealer, inner random/transcript, GREASE-PSK decoys, accept/reject verdict) and
    /// builds the outer / decides accept from data the machine feeds it. Always assigned;
    /// inactive when ECH is not offered.</summary>
    FEchOrch: IEchClientOrchestrator;
    FPhase: TPhase;
    /// <summary>Records the extension types the sent ClientHello carried, so a server
    /// response extension the client did not offer is rejected (RFC 9846 4.3).</summary>
    procedure RememberOffered(const AFramedClientHello: TBytes);
    /// <summary>Marks the recorded offered extension types on AContext.</summary>
    procedure ApplyOffered(const AContext: TExtensionContext);
    function BuildClientHello(const ARandom: TBytes;
      const AEchBody: TBytes): TBytes;
    /// <summary>The (server identity, SNI) key this client caches resumable sessions under.</summary>
    function CacheServerIdentity: string;
    /// <summary>The digest of AData under AHash (the per-PSK binder transcript on the first
    /// ClientHello, where the transcript is otherwise just this message).</summary>
    function HashUnder(AHash: THashAlgorithm; const AData: TBytes): TBytes;
    /// <summary>After a HelloRetryRequest fixes the cipher (hence hash), drops every offered
    /// PSK whose hash differs, so the second ClientHello offers only the still-eligible ones
    /// (RFC 9846 4.2.2). The server's selected_identity then indexes the pruned list.</summary>
    procedure PruneOffersToHash(AHash: THashAlgorithm);
    /// <summary>
    /// Back-patches the real PSK binders into the ClientHello tail: each binder MACs the
    /// message up to (excluding) the binders vector, computed under its own offered PSK and
    /// that PSK's hash (RFC 9846 4.3.11.2 / RFC 9258 5.2).
    /// </summary>
    procedure PatchBinder(var AClientHello: TBytes;
      const ATranscript: ITranscriptHash);
    /// <summary>The retry's ClientHelloOuter around AInner; an echoed cookie that overflows the
    /// outer wrapper aborts with internal_error rather than the encoder's error.</summary>
    function BuildRetryOuter(AMode: TEchChMode; const AInner: TBytes): TBytes;
    /// <summary>Consumes a post-handshake NewSessionTicket into an IResumableSession and
    /// caches it, returning the SessionTicketReceived effect (RFC 9846 4.7.1).</summary>
    function CacheNewSessionTicket(const AMessage: TTlsHandshakeMessage)
      : TArray<THandshakeEffect>;
    function ProcessServerHello(const AMessage: TTlsHandshakeMessage)
      : TArray<THandshakeEffect>;
    /// <summary>Replaces the transcript with a fresh one under the selected suite's hash and
    /// replays the raw first ClientHello into it, for a 0-RTT reject whose full handshake uses
    /// a different PRF hash than the pre-activated PSK (RFC 9846 4.1). Not a message_hash
    /// rebase (that is HelloRetryRequest-only); the full-handshake transcript is the plain
    /// ClientHello || ServerHello || ... under the new hash.</summary>
    procedure RebuildTranscriptUnderSelectedHash;
    /// <summary>Rejects a TLS 1.3 ServerHello that carries any extension other than
    /// supported_versions, key_share or pre_shared_key (RFC 9846 4.2.3).</summary>
    class procedure EnforceTls13ServerHelloExtensions(
      const AVector: TExtensionVector); static;
    /// <summary>Consumes EncryptedExtensions: validates the server's ALPN selection
    /// and applies the negotiated record_size_limit, surfacing both as effects.</summary>
    function ProcessEncryptedExtensions(const AMessage: TTlsHandshakeMessage)
      : TArray<THandshakeEffect>;
    /// <summary>Handles a HelloRetryRequest: validates the requested group, generates
    /// a fresh key_share for it, echoes the cookie, applies the message_hash
    /// transcript, and resends. A second HelloRetryRequest is fatal.</summary>
    function HandleHelloRetryRequest(const AHello: TTlsServerHello;
      const AMessage: TTlsHandshakeMessage): TArray<THandshakeEffect>;
    function ProcessCertificate(const AMessage: TTlsHandshakeMessage)
      : TArray<THandshakeEffect>;
    /// <summary>Decompresses a CompressedCertificate (RFC 8879) - bounded, bomb-guarded
    /// - and processes the recovered Certificate; the compressed message is what enters
    /// the transcript.</summary>
    function ProcessCompressedCertificate(const AMessage: TTlsHandshakeMessage)
      : TArray<THandshakeEffect>;
    /// <summary>Trust-verifies a decoded Certificate body and folds ATranscriptRaw in.</summary>
    function HandleCertificate(const ACertificateBody, ATranscriptRaw: TBytes)
      : TArray<THandshakeEffect>;
    procedure VerifyCertificateVerify(const AMessage: TTlsHandshakeMessage);
    /// <summary>Verifies the server's CertificateVerify, folds it into the transcript and, once
    /// the server has proved it holds the leaf key, parks for an out-of-band verdict when one is
    /// configured.</summary>
    function ProcessCertificateVerify(const AMessage: TTlsHandshakeMessage)
      : TArray<THandshakeEffect>;
    /// <summary>Records a CertificateRequest (RFC 9846 4.4.2): the request context and
    /// the server's accepted signature schemes, folding it into the transcript.</summary>
    procedure ProcessCertificateRequest(const AMessage: TTlsHandshakeMessage);
    /// <summary>True when any code is a known scheme usable for a TLS 1.3 handshake
    /// signature (RFC 9846 4.3.3).</summary>
    class function HasTls13UsableScheme(const ASchemes: TArray<UInt16>): Boolean; static;
    /// <summary>Frames the client Certificate for the request context (empty chain when
    /// no usable credential); appends the framed CertificateVerify when a chain is sent.</summary>
    procedure AppendClientAuthFlight(var AEffects: TArray<THandshakeEffect>);
    /// <summary>The one dummy change_cipher_spec, returned the first time it is needed
    /// and empty thereafter, so the caller prepends it to the flight that carries the
    /// client's second flight - the encrypted handshake, or the retry ClientHello.</summary>
    function MiddleboxCcs: TArray<THandshakeEffect>;
    /// <summary>The negotiation facts reported at completion.</summary>
    function Facts: TNegotiationFacts;
    /// <summary>Why this ClientHello offers or withholds 0-RTT (Accepted: it is offered); the first
    /// reason that applies, from disabled through the ticket's limits to its ALPN.</summary>
    function EarlyDataOfferReason(ASessionTaken: Boolean): TEarlyDataReason;
    /// <summary>Whether a resumed session under Reverify still owes an out-of-band verdict, which
    /// parks the handshake at the server Finished (a PSK session carries no chain to decide on).</summary>
    function ResumeVerdictOwed: Boolean;
    function ProcessServerFinished(const AMessage: TTlsHandshakeMessage)
      : TArray<THandshakeEffect>;
    /// <summary>The client's closing flight once the server Finished is verified and the
    /// application secrets derived: EndOfEarlyData (accepted 0-RTT), the client-auth flight
    /// (mutual TLS), the client Finished, the write/read application-key installs, the
    /// resumption-transcript capture, the ECH-reject branch, and completion. Shared by the
    /// inline path and the reverify-on-resume park's continuation.</summary>
    function BuildClientFinishedFlight: TArray<THandshakeEffect>;
    // ITls13ClientReplay
    procedure SetVerbatimClientHello(const AFramed: TBytes);
  strict protected
    function Route(const AMessage: TTlsHandshakeMessage)
      : TArray<THandshakeEffect>; override;
    function WriteDirection: TTlsDirection; override;
    function ReadDirection: TTlsDirection; override;
    function ContinueAfterVerdict: TArray<THandshakeEffect>; override;
  public
    constructor Create(const AParams: TClientHandshakeParams);
    function Initiates: Boolean; override;
    function Start: TArray<THandshakeEffect>; override;
    procedure ForgetSessionsOnFatal; override;
    /// <summary>The cached TLS 1.2 session this unified ClientHello offered (nil when it
    /// offered none), for a version-dispatching parent to hand to a 1.2 sub-machine when
    /// the server selects 1.2.</summary>
    property Tls12ResumptionSession: ITls12ResumableSession read FTls12ResumptionSession;
    /// <summary>The path the offer-time re-check validated for the offered session; empty unless
    /// Reverify applied.</summary>
    property ResumeValidatedPath: TArray<TBytes> read FResumeValidatedPath;
    /// <summary>Why the ClientHello offered or withheld 0-RTT, for a TLS 1.2 handover to report.</summary>
    property EarlyReasonAtOffer: TEarlyDataReason read FEarlyReasonAtOffer;
    /// <summary>The legacy_session_id this unified ClientHello actually put on the wire -
    /// the cached 1.2 session id when resuming, otherwise the random TLS 1.3 compatibility-mode
    /// id. A 1.2 sub-machine uses it to detect a server echoing the id, whether that echo is a
    /// genuine resumption or a false one (RFC 5246 7.4.1.3).</summary>
    property SentLegacySessionId: TBytes read FSentLegacySessionId;
    /// <summary>Whether this ClientHello offered early data (0-RTT). A version-dispatching parent
    /// reads it to refuse a 1.2 hand-off, since 0-RTT is a TLS 1.3 construct (RFC 9846 4.3.10).</summary>
    property EarlyDataOffered: Boolean read FEarlyDataOffered;
  end;

implementation

resourcestring
  SClockRequired = 'a clock is required (the handshake reads time for tickets and freshness)';
  SUnofferedSuite = 'the server selected a cipher suite that was not offered';
  SUnknownSelectedSuite = 'the selected cipher suite is not in the registry';
  SNotTls13Suite = 'the server selected a suite that is not a TLS 1.3 suite';
  SBadSessionIdEcho = 'the server echoed a session id that was not offered';
  SDowngradeDetected = 'the ServerHello carries a version downgrade sentinel';
  SUnsupportedSelectedVersion = 'the server did not select TLS 1.3';
  SSupportedVersionsBelowTls13 =
    'the ServerHello carries supported_versions selecting a version below TLS 1.3';
  SUnofferedGroup = 'the server selected a key share group that was not offered';
  SMissingServerKeyShare = 'the ServerHello carries no key_share for the asymmetric key exchange';
  SEarlyDataWithoutPsk =
    'EncryptedExtensions carries early_data but no offered PSK was accepted';
  SBadServerFinished = 'the server Finished did not verify';
  SEmptyCertificate = 'the server sent an empty certificate list';
  SServerCertContextNotEmpty =
    'the server Certificate carried a non-empty certificate_request_context in the handshake';
  SUnsolicitedCertExtension =
    'the server certificate carries an extension that was not requested';
  SNoCertificateVerifier = 'no certificate verifier configured (fail-closed)';
  SVerbatimHelloWithEchOrCache = 'a verbatim replay ClientHello is incompatible with ECH ' +
    'or a session cache (both rewrite the ClientHello)';
  SEchRequiresTls13 = 'Encrypted Client Hello requires TLS 1.3; it cannot be offered by a ' +
    'client that also offers TLS 1.2';
  SUntrustedCertificate = 'the server certificate chain was not trusted';
  SUnofferedAlpn = 'the server selected an ALPN protocol that was not offered';
  SEarlyDataSuiteMismatch = 'the server accepted early data under a cipher suite that differs from the resumption ticket';
  SEarlyDataAlpnMismatch = 'the server accepted early data but negotiated a different ALPN protocol than the resumption ticket';
  SBadRecordSizeLimit = 'the server record_size_limit is below the 64-byte minimum';
  SHelloRetryUnoffered = 'the HelloRetryRequest named a group that was not offered';
  SHelloRetrySameGroup = 'the HelloRetryRequest named the already-offered key_share group';
  SHelloRetryTwice = 'the server sent a second HelloRetryRequest';
  SHelloRetryVersion = 'the HelloRetryRequest does not select TLS 1.3';
  SHelloRetryNoGroup = 'the HelloRetryRequest group is not available';
  SHelloRetryCookieTooLarge =
    'the HelloRetryRequest cookie is too large to echo in the second ClientHello';
  SHelloRetryNoChange =
    'the HelloRetryRequest changes neither the key_share group nor adds a cookie';
  SRetryCipherChanged =
    'the ServerHello changed the cipher suite the HelloRetryRequest selected';
  SServerHelloExtNotAllowed =
    'the ServerHello carries an extension not permitted in a TLS 1.3 ServerHello';
  SRequestContextNotEmpty = 'the CertificateRequest carried a non-empty request context in the handshake';
  SCertificateRequestTwice = 'the server sent a second CertificateRequest';
  SNoUsableCertificateRequestScheme =
    'the CertificateRequest lists no signature scheme usable in TLS 1.3';
  SBadSelectedPskIdentity = 'the server selected a pre_shared_key identity index beyond the offered list';
  SPskHashMismatch = 'the selected cipher suite hash does not match the accepted pre_shared_key hash';
  SPskRequiredNotSelected = 'the server did not select a pre_shared_key and no certificate trust is configured';
  SEchRejectPsk = 'a rejected-ECH ServerHello selected the outer pre_shared_key';
  SCertReqMissingSigAlgs = 'CertificateRequest must contain signature_algorithms (RFC 9846 4.4.2)';

const
  PskDheKeMode = Byte(1); // psk_key_exchange_modes: psk_dhe_ke
  MaxRememberedTickets = Int32(16); // tickets a fatal alert withdraws from the cache
  CookieExtensionOverhead = Int32(4 + 2); // extension header and the cookie's length prefix (RFC 9846 4.3.2)

{ TTls13ClientStateMachine }

constructor TTls13ClientStateMachine.Create(const AParams: TClientHandshakeParams);
begin
  inherited Create(AParams.ExtensionRegistry);
  if AParams.Clock = nil then
    raise EArgumentTlsLibException.CreateRes(@SClockRequired);
  FParams := AParams;
  FCurrentGroup := AParams.Group;
  FCurrentGroupCode := AParams.GroupCode;
  // start on the outer identity; ECH accept / reject swaps these to the inner random / public_name
  FActiveClientRandom := AParams.ClientRandom;
  FExpectedName := AParams.ExpectedServerName;
  FRetried := False;
  FGreaseSeed := -1;
  FHrrChangedGroup := False;
  FPhase := TPhase.Initial;
  // the ECH orchestrator resolves the posture once (usable config / GREASE / fail-closed) and
  // owns the per-connection ECH mechanics; a preset verbatim ClientHello is mutually exclusive
  // with ECH (enforced in SetVerbatimClientHello), so selection runs purely off the policy here
  FEchOrch := TEchClientOrchestrator.Create(AParams.Crypto, AParams.EchPolicy);
  // ECH is 1.3-only (RFC 9849 sec. 6.1 restricts the inner; refusing a 1.2 offer beside a usable
  // config is local policy): a usable config cannot pair with a 1.2 offer. A GREASE-only
  // posture (Active False) rides through - GREASE ech is permitted in any ClientHello (sec. 6.2)
  if FParams.AlsoOfferTls12 and FEchOrch.Active then
    raise EArgumentTlsLibException.CreateRes(@SEchRequiresTls13);
end;

procedure TTls13ClientStateMachine.SetVerbatimClientHello(const AFramed: TBytes);
begin
  // a captured ClientHello is sent as-is, so the machine must not also try to offer ECH or a
  // resumption PSK against it (those rewrite the hello); reject that misconfiguration up front
  if (FParams.EchPolicy <> nil) or (FParams.SessionCache <> nil) then
    raise EArgumentTlsLibException.CreateRes(@SVerbatimHelloWithEchOrCache);
  FVerbatimClientHello := AFramed;
end;

procedure TTls13ClientStateMachine.RememberOffered(
  const AFramedClientHello: TBytes);
begin
  FOfferedExtensions := TClientSessionPolicy.OfferedExtensionTypes(AFramedClientHello);
end;

procedure TTls13ClientStateMachine.ApplyOffered(const AContext: TExtensionContext);
var
  LType: UInt16;
begin
  for LType in FOfferedExtensions do
    AContext.MarkOffered(LType);
end;

function TTls13ClientStateMachine.BuildClientHello(const ARandom: TBytes;
  const AEchBody: TBytes): TBytes;
var
  LContext: TExtensionContext;
  LHello: TTlsClientHello;
  LGroups, LSchemes, LSuites: TArray<UInt16>;
  LBlock: TBytes;
  LSeed, LI: Int32;
begin
  Result := nil;
  LSeed := 0; // only meaningful under GREASE
  LContext := TExtensionContext.Create;
  try
    // a 1.2 offer never coexists with active ECH (the ctor rejects that pairing by local policy)
    if FParams.AlsoOfferTls12 then
    begin
      // one unified ClientHello: the 1.3 key_share coexists with a 1.2 offer, and a
      // 1.2 server ignores the 1.3-only extensions and negotiates from legacy fields
      LContext.SupportedVersions := TArray<UInt16>.Create(TlsWireVersionTls13,
        TlsWireVersionTls12);
      LContext.ExtendedMasterSecret := True;
      // secure-renegotiation signalling for the 1.2 path (RFC 5746); a 1.3 server ignores it
      LContext.RenegotiationInfo := True;
      // ec_point_formats (RFC 8422) for the 1.2 ECC suites; a 1.3 server ignores it. Strict
      // 1.2 servers require it to accept ECDHE
      LContext.EcPointFormatsOffered := True;
    end
    else
      LContext.SupportedVersions := TArray<UInt16>.Create(TlsWireVersionTls13);
    if System.Length(FParams.OfferedGroups) > 0 then
      LGroups := FParams.OfferedGroups
    else
      LGroups := TArray<UInt16>.Create(FCurrentGroupCode);
    LSchemes := FParams.OfferedSchemes;
    LSuites := FParams.OfferedSuites;
    LContext.ServerName := FParams.ServerName;
    LContext.AlpnProtocols := FParams.AlpnProtocols;
    LContext.RecordSizeLimit := FParams.RecordSizeLimit;
    // offer to accept a stapled OCSP response (RFC 6066) only when configured to request
    // one; the trust posture then decides what a missing or indeterminate staple means
    LContext.StatusRequestOffered := FParams.RequestOcspStapling;
    // advertise the certificate-compression algorithms we can decompress (RFC 8879)
    LContext.CertCompressionAlgorithms :=
      TCertificateCompression.Algorithms(FParams.CertificateDecompressors);
    // a retry echoes the server's cookie verbatim (empty on the first ClientHello)
    LContext.Cookie := FCookie;
    SetLength(LContext.ClientKeyShares, 1);
    LContext.ClientKeyShares[0].Group := FCurrentGroupCode;
    LContext.ClientKeyShares[0].KeyExchange := FEphemeralPublic;

    // sprinkle distinct GREASE codepoints across the offers so a conformant server
    // ignores them (RFC 8701); the GREASE key_share group is also in supported_groups
    if FParams.Grease then
    begin
      // choose the seed once; a HelloRetryRequest retry reuses it so its GREASE codepoints
      // match the first ClientHello exactly (RFC 9846 4.2.2)
      if FGreaseSeed < 0 then
        FGreaseSeed := FParams.Crypto.Primitives.GetRandom.GenerateBytes(1)[0];
      LSeed := FGreaseSeed;
      LContext.SupportedVersions := TGrease.Prepend(LContext.SupportedVersions,
        TGrease.ValueAt(LSeed));
      LGroups := TGrease.Prepend(LGroups, TGrease.ValueAt(LSeed + 1));
      LSchemes := TGrease.Prepend(LSchemes, TGrease.ValueAt(LSeed + 2));
      LSuites := TGrease.Prepend(LSuites, TGrease.ValueAt(LSeed + 3));
      // a group-change retry MUST carry exactly one KeyShareEntry - the requested group
      // (RFC 9846 4.2.2), so drop the GREASE share then. The first ClientHello, and a
      // cookie-only retry (whose key_share must stay identical to it), keep the GREASE share.
      if not (FRetried and FHrrChangedGroup) then
      begin
        SetLength(LContext.ClientKeyShares, 2);
        LContext.ClientKeyShares[1] := LContext.ClientKeyShares[0];
        LContext.ClientKeyShares[0].Group := TGrease.ValueAt(LSeed + 1);
        LContext.ClientKeyShares[0].KeyExchange := TBytes.Create(0);
      end;
    end;
    LContext.SupportedGroups := LGroups;
    LContext.SignatureSchemes := LSchemes;

    // 0-RTT: offer early_data (an empty ClientHello flag) alongside the PSK
    LContext.EarlyDataOffered := FEarlyDataOffered;
    // signal resumption support (psk_dhe_ke) whenever a cache is configured, so a spec-
    // compliant server issues NewSessionTickets even on the initial handshake where no PSK
    // is offered yet (RFC 9846 4.3.9); the pre_shared_key identity and its back-patched
    // binder are added only when actually resuming (pre_shared_key stays the last extension)
    if (FParams.SessionCache <> nil) or (System.Length(FPskOffers) > 0) then
      LContext.PskModes := TBytes.Create(PskDheKeMode);
    // a dual-version client with a cache signals session_ticket support (RFC 5077) so a 1.2
    // server issues a ticket for future resumption; a held 1.2 session adds its ticket. The
    // extended_master_secret offer is kept on (RFC 7627 5.2: a supporting client offers it in
    // every ClientHello, resumption included) so the 1.2 machine catches a server that resumes
    // a non-EMS session yet echoes the extension (RFC 7627 5.3). A 1.3 server ignores these
    // legacy fields.
    // the 1.2 session_ticket offer is also a TLS-1.2-only extension the ClientHelloInner MUST
    // omit (inferred from the inner not offering TLS 1.2 or below, RFC 9849 sec. 6.1); a 1.2 offer
    // never coexists with active ECH (rejected in the ctor)
    if FParams.AlsoOfferTls12 and (FParams.SessionCache <> nil) then
    begin
      LContext.SessionTicketOffered := True;
      if FTls12ResumptionSession <> nil then
        LContext.SessionTicket := FTls12ResumptionSession.SessionTicket;
    end;
    // pre_shared_key: one identity + obfuscated_age + placeholder binder per offered PSK.
    // A resumption ticket carries its obfuscated_ticket_age; an external PSK has none, so
    // it offers 0 (RFC 9846 4.3.11). The binders are back-patched after serialization.
    if System.Length(FPskOffers) > 0 then
    begin
      SetLength(LContext.OfferedPskIdentities, System.Length(FPskOffers));
      SetLength(LContext.OfferedPskAges, System.Length(FPskOffers));
      SetLength(LContext.OfferedPskBinders, System.Length(FPskOffers));
      for LI := 0 to High(FPskOffers) do
      begin
        LContext.OfferedPskIdentities[LI] := FPskOffers[LI].Identity;
        if FPskOffers[LI].BinderKind = TPskBinderKind.Resumption then
          LContext.OfferedPskAges[LI] := UInt32(
            (FParams.Clock.NowUnixMillis - FPskOffers[LI].IssuedAtMillis) +
            FPskOffers[LI].TicketAgeAdd)
        else
          LContext.OfferedPskAges[LI] := 0;
        SetLength(LContext.OfferedPskBinders[LI],
          FParams.Crypto.Primitives.CreateHash(FPskOffers[LI].Hash).HashSize);
      end;
    end;

    LHello.Random := ARandom;
    // when offering a cached 1.2 session, legacy_session_id carries the id whose echo
    // signals the server's abbreviated (resumed) handshake; otherwise the middlebox id
    if FTls12ResumptionSession <> nil then
      LHello.LegacySessionId := FTls12OfferedSessionId
    else
      LHello.LegacySessionId := FParams.LegacySessionId;
    FSentLegacySessionId := LHello.LegacySessionId;
    LHello.CipherSuites := LSuites;
    // the encrypted_client_hello body to carry, if any: a decoy on a GREASE ClientHello (the same
    // bytes on every hello, so a retry re-sends it verbatim), or the inner-form marker on an ECH
    // ClientHelloInner. The registry places it where a genuine ech sits (before pre_shared_key,
    // else last), so the decoy's position does not betray it
    if System.Length(AEchBody) > 0 then
      LContext.EchExtensionData := AEchBody;
    // a foreign server sizes the cookie; it must fit our reader's body cap (implying the 2^16-1 vector)
    if System.Length(FCookie) > 0 then
    begin
      LContext.Cookie := nil;
      LBlock := FCodec.ProduceBlock(LContext, TTlsExtensionContextKind.ClientHello);
      if FParams.Grease then
        LBlock := TGrease.InjectPair(LBlock, LSeed);
      LContext.Cookie := FCookie;
      LHello.Extensions := LBlock;
      if System.Length(THandshakeMessages.EncodeClientHello(LHello)) +
        CookieExtensionOverhead + System.Length(FCookie) > DefaultMaxHandshakeMessageLength then
        raise EFatalAlertTlsLibException.CreateRes(
          TTlsAlertDescription.InternalError, @SHelloRetryCookieTooLarge);
    end;
    LBlock := FCodec.ProduceBlock(LContext, TTlsExtensionContextKind.ClientHello);
    // GREASE splices two extensions, one empty and one 1-byte (RFC 8701 3.1 varying length), next
    // to encrypted_client_hello (else before pre_shared_key, which must stay last, RFC 9846
    // 4.3.11), so an ECH inner keeps them in one compressible run
    if FParams.Grease then
      LBlock := TGrease.InjectPair(LBlock, LSeed);
    LHello.Extensions := LBlock;
    Result := THandshakeFraming.Frame(TTlsHandshakeType.ClientHello,
      THandshakeMessages.EncodeClientHello(LHello));
  finally
    LContext.Free;
  end;
end;

function TTls13ClientStateMachine.BuildRetryOuter(AMode: TEchChMode;
  const AInner: TBytes): TBytes;
begin
  try
    Result := FEchOrch.BuildClientHelloOuter(AMode, AInner, FParams.ClientRandom,
      FParams.LegacySessionId, FPskOffers);
  except
    // a foreign cookie sized into the inner's room can still overflow the outer wrapper
    on E: EArgumentTlsLibException do
    begin
      // a peer-input error keeps its own alert; nothing here parses peer data, so it is defensive
      if (System.Length(FCookie) = 0) or (E is EPeerInputTlsLibException) then
        raise;
      raise EFatalAlertTlsLibException.CreateRes(
        TTlsAlertDescription.InternalError, @SHelloRetryCookieTooLarge);
    end;
  end;
  if (System.Length(FCookie) > 0) and
    (System.Length(Result) - HandshakeHeaderLength > DefaultMaxHandshakeMessageLength) then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.InternalError, @SHelloRetryCookieTooLarge);
end;

function TTls13ClientStateMachine.CacheServerIdentity: string;
begin
  Result := TClientSessionPolicy.CacheIdentity(FParams.ServerIdentity,
    FParams.ServerName, FParams.SessionScope);
end;

function TTls13ClientStateMachine.HashUnder(AHash: THashAlgorithm;
  const AData: TBytes): TBytes;
var
  LHash: IHash;
begin
  LHash := FParams.Crypto.Primitives.CreateHash(AHash);
  LHash.Update(AData, 0, System.Length(AData));
  Result := LHash.DoFinal;
end;

procedure TTls13ClientStateMachine.PatchBinder(var AClientHello: TBytes;
  const ATranscript: ITranscriptHash);
var
  LI, LHashLen, LBindersLen, LTotal, LOffset: Int32;
  LPartial, LBinder, LPrefixHash: TBytes;
  LTemp: ITls13KeySchedule;
begin
  // the binders vector: a 2-byte list length, then per PSK a 1-byte entry length + binder
  LBindersLen := 2;
  for LI := 0 to High(FPskOffers) do
    Inc(LBindersLen, 1 + FParams.Crypto.Primitives.CreateHash(FPskOffers[LI].Hash).HashSize);
  LTotal := System.Length(AClientHello);
  LPartial := System.Copy(AClientHello, 0, LTotal - LBindersLen);

  // each binder MACs the ClientHello up to (excluding) the binders vector, under its own
  // PSK and hash. On the first flight the transcript is otherwise empty (deferred while
  // several hashes are in play), so the prefix hash is Hash(LPartial); on a HelloRetryRequest
  // retry the transcript is active (message_hash(CH1), HRR) on the single surviving hash.
  // Under ECH the caller supplies the inner transcript so the inner ClientHello binds over
  // its own history rather than the outer one.
  LOffset := (LTotal - LBindersLen) + 2; // past the 2-byte binders list length
  for LI := 0 to High(FPskOffers) do
  begin
    LHashLen := FParams.Crypto.Primitives.CreateHash(FPskOffers[LI].Hash).HashSize;
    if ATranscript.IsActive then
      LPrefixHash := ATranscript.HashPrefixExcludingBinders(LPartial)
    else
      LPrefixHash := HashUnder(FPskOffers[LI].Hash, LPartial);
    // the key length is irrelevant to the binder MAC (only the hash matters)
    LTemp := TTls13KeySchedule.Create(FParams.Crypto, FPskOffers[LI].Hash, LHashLen);
    LTemp.SetPsk(FPskOffers[LI].Key);
    LBinder := LTemp.ComputeBinder(FPskOffers[LI].BinderKind, LPrefixHash);
    Move(LBinder[0], AClientHello[LOffset + 1], LHashLen); // +1 past the 1-byte entry length
    Inc(LOffset, 1 + LHashLen);
  end;
end;

procedure TTls13ClientStateMachine.PruneOffersToHash(AHash: THashAlgorithm);
var
  LKept: TArray<IPreSharedKey>;
  LKeptIdx: TArray<Int32>;
  LI: Int32;
begin
  LKept := nil;
  LKeptIdx := nil;
  for LI := 0 to System.High(FPskOffers) do
    if FPskOffers[LI].Hash = AHash then
    begin
      TArrayUtilities.Append<IPreSharedKey>(LKept, FPskOffers[LI]);
      TArrayUtilities.Append<Int32>(LKeptIdx, LI);
    end;
  FPskOffers := LKept;
  // keep the ECH outer's GREASE-PSK decoys index-aligned with the pruned offers (they are minted
  // per offer on CH1, so a surviving offer keeps across the HRR the identity and age it carried)
  FEchOrch.KeepPskDecoys(LKeptIdx);
end;

function TTls13ClientStateMachine.CacheNewSessionTicket(
  const AMessage: TTlsHandshakeMessage): TArray<THandshakeEffect>;
var
  LNst: TTlsNewSessionTicket;
  LPsk: ISecretBuffer;
  LSession: IResumableSession;
  LContext: TExtensionContext;
  LMaxEarlyData: UInt32;
  LPeerChain: TArray<TBytes>;
  LLifetime: UInt32;
  LAuthenticatedAtMs, LNowMs: UInt64;
begin
  Result := nil;
  // validate the ticket structure even when not caching (an empty/malformed ticket is a
  // protocol error regardless), then read max_early_data_size from its extensions
  LNst := THandshakeMessages.DecodeNewSessionTicket(AMessage.Body);
  LContext := TExtensionContext.Create;
  try
    FCodec.ConsumeBlock(LContext, TTlsExtensionContextKind.NewSessionTicket,
      LNst.Extensions);
    LMaxEarlyData := LContext.EarlyDataMaxSize;
  finally
    LContext.Free;
  end;
  // a rejected ECH handshake authenticated only the public_name, so its tickets MUST be ignored
  // (RFC 9849 sec. 6.1.7); a reject is already terminal, so this guards against a future refactor
  if FEchOrch.Status = TEchStatus.Rejected then
    Exit;
  if FParams.SessionCache = nil then
    Exit;
  // ticket_lifetime 0 means discard immediately, and a client MUST NOT use a ticket for longer
  // than seven days regardless of what the server advertised (RFC 9846 4.7.1)
  if LNst.TicketLifetime = 0 then
    Exit;
  // a ticket beyond what a ClientHello is budgeted for is ignored (RFC 9846 4.7.1)
  if System.Length(LNst.Ticket) > TSessionTicketLimits.MaxCachedTicketBytes then
    Exit;
  // a ticket keeps the authentication time of its connection's handshake and only the days left
  LNowMs := FParams.Clock.NowUnixMillis;
  LAuthenticatedAtMs := FAuthenticatedAtMs;
  LLifetime := TClientSessionPolicy.RenewedTicketLifetime(LNst.TicketLifetime,
    LAuthenticatedAtMs, LNowMs);
  if LLifetime = 0 then
    Exit;
  LPsk := FSchedule.ResumptionPsk(LNst.TicketNonce);
  // carry the verified server chain so an opt-in ReverifyOnResume can re-check it on resume. On a
  // resumed connection no Certificate was sent, so the ticket inherits the resumed session's chain
  LPeerChain := FCertificateChain;
  if FResumedFromTicket then
    LPeerChain := FResumptionPeerCertificates;
  LSession := TTls13ResumableSession.Create(FSelectedSuite.Common.Code,
    FSelectedSuite.Common.Hash, LPsk, FNegotiatedAlpn,
    FParams.ServerName, LNst.Ticket,
    LLifetime, LNst.TicketAgeAdd, LNowMs,
    LMaxEarlyData, LPeerChain, nil, FSessionPskIdentity, FSessionPskBinding,
    FPeerSignatureScheme, LAuthenticatedAtMs);
  FParams.SessionCache.Store(CacheServerIdentity, FParams.ServerName, LSession);
  // bounded against a server streaming tickets; a dropped ticket escapes the fatal-alert cache
  // withdrawal (RFC 9846 6, "if possible")
  if System.Length(FStoredSessions) >= MaxRememberedTickets then
    FStoredSessions := System.Copy(FStoredSessions, 1, MaxRememberedTickets - 1);
  TArrayUtilities.Append<IResumableSession>(FStoredSessions, LSession);
  Result := TArray<THandshakeEffect>.Create(
    THandshakeEffects.RaiseEvent(TTlsEventKind.SessionTicketReceived));
end;

function TTls13ClientStateMachine.Initiates: Boolean;
begin
  Result := True;
end;

function TTls13ClientStateMachine.Start: TArray<THandshakeEffect>;
var
  LClientHello, LInner: TBytes;
  LCached: IResumableSession;
  LOfferedPsk: IPreSharedKey;
  L13: ITls13ResumableSession;
  L12: ITls12ResumableSession;
  LPskSuite: TTlsCipherSuite;
  LHint: UInt16;
  LHintGroup: INamedGroup;
  LSessionTaken: Boolean;
begin
  // key-exchange hint: lead the key_share with the group the server last selected for this
  // server, to avoid a HelloRetryRequest. Only an offered, resolvable group is honored. Under
  // Encrypted Client Hello the hint is not used: the outer key_share group would then vary with
  // prior negotiations, an avoidable cross-connection correlation signal, so ECH connections
  // always lead with the configured preference.
  if (FParams.SessionCache <> nil) and (FParams.GroupRegistry <> nil) and
    (not FEchOrch.Active) then
  begin
    LHint := FParams.SessionCache.KxHint(CacheServerIdentity, FParams.ServerName);
    if (LHint <> 0) and (LHint <> FCurrentGroupCode) and
      (TArrayUtilities.Contains<UInt16>(FParams.OfferedGroups, LHint)) and
      FParams.GroupRegistry.TryGet(LHint, LHintGroup) then
    begin
      FCurrentGroup := LHintGroup;
      FCurrentGroupCode := LHint;
    end;
  end;
  FCurrentGroup.GenerateKeyPair(FEphemeralPrivate, FEphemeralPublic);
  // resumption: pop one cached session for this server. A 1.3 session is offered as a PSK,
  // whose single hash the transcript runs under from the start so the binder can be MAC'd
  // and (if accepted) the handshake continues under it (RFC 9846 4.3.11). A cached 1.2
  // session is instead offered as a legacy session_ticket / session id in this dual-version
  // hello, for a 1.2 server to resume (a 1.3 server ignores it); the taken session is
  // threaded to a 1.2 sub-machine by the version-dispatching parent.
  // a preset verbatim ClientHello forbids a SessionCache, so no resumption take here
  LSessionTaken := (FParams.SessionCache <> nil)
    and FParams.SessionCache.Take(CacheServerIdentity, FParams.ServerName,
    FParams.Clock.NowUnixMillis, LCached);
  if LSessionTaken then
  begin
    if LCached.Version.WireValue = TlsWireVersionTls13 then
    begin
      if TClientSessionPolicy.IsOfferableTls13(LCached, FParams.Clock.NowUnixMillis) and
        Supports(LCached, ITls13ResumableSession, L13) and
        TClientSessionPolicy.SessionTrustedForOffer(FParams.ResumeVerification, LCached,
        FParams.CertificateVerifier, FParams.ResumeCertificateVerifier, FExpectedName,
        FResumeValidatedPath) then
      begin
        // the default session projects itself as a PSK; a custom cache may return one that does
        // not, so build the offer from the documented ITls13ResumableSession surface instead
        if not Supports(L13, IPreSharedKey, LOfferedPsk) then
          LOfferedPsk := TPreSharedKey.Create(L13.TicketIdentity, L13.ResumptionSecret,
            L13.Hash, L13.CipherSuite, L13.MaxEarlyData, L13.Alpn, TPskBinderKind.Resumption,
            L13.TicketLifetime, L13.TicketAgeAdd, L13.IssuedAtMillis);
        FPskOffers := TArray<IPreSharedKey>.Create(LOfferedPsk);
        // kept to surface the resumed chain and to park a deferred verdict on it
        FResumptionPeerCertificates := LCached.PeerCertificates;
        FResumptionPskIdentity := LCached.PskIdentity;
        FResumptionPskBinding := LCached.PskBinding;
        FResumptionPeerSignatureScheme := LCached.PeerSignatureScheme;
        FAuthenticatedAtMs := LCached.AuthenticatedAtMillis;
      end;
    end
    else if FParams.AlsoOfferTls12 then
    begin
      if TClientSessionPolicy.IsOfferableTls12(LCached, FParams.Clock.NowUnixMillis) and
        Supports(LCached, ITls12ResumableSession, L12) and
        TClientSessionPolicy.SessionTrustedForOffer(FParams.ResumeVerification, LCached,
        FParams.CertificateVerifier, FParams.ResumeCertificateVerifier, FExpectedName,
        FResumeValidatedPath) then
      begin
        FTls12ResumptionSession := L12;
        if System.Length(L12.SessionId) > 0 then
          FTls12OfferedSessionId := L12.SessionId
        else
          FTls12OfferedSessionId := FParams.LegacySessionId;
      end;
    end;
  end;
  // configured out-of-band external PSKs (RFC 9258) are offered after any cached resumption
  // (each imported for every supported KDF hash), so a server prefers a resumption ticket
  // when it holds one and falls back to the external PSK otherwise (both may be offered in
  // one ClientHello). Several hashes may then be in play, so the transcript stays deferred
  // (activated once the ServerHello fixes the suite) and each binder is MAC'd under its own
  // PSK's hash in PatchBinder.
  if System.Length(FParams.ExternalPsks) > 0 then
    FPskOffers := TArrayUtilities.Concat<IPreSharedKey>(FPskOffers,
      TExternalPskImporter.ImportAll(FParams.Crypto, FParams.ExternalPsks,
      TlsWireVersionTls13));
  // a single offered PSK has one known hash, so activate the transcript on it now (the
  // resumption / 0-RTT path relies on it); several offers defer activation to ServerHello
  if System.Length(FPskOffers) = 1 then
  begin
    FTranscript.Activate(FParams.Crypto.Primitives.CreateHash(FPskOffers[0].Hash));
    FTranscriptPreActivated := True;
    FPreActivatedHash := FPskOffers[0].Hash;
  end;
  // 0-RTT is offered only for one ticket that authorized it and whose ALPN is still advertised
  FEarlyReasonAtOffer := EarlyDataOfferReason(LSessionTaken);
  FEarlyDataOffered := FEarlyReasonAtOffer = TEarlyDataReason.Accepted;
  FEarlyDataEverOffered := FEarlyDataOffered;
  if FEarlyDataOffered then
    FParams.CipherSuites.TryGet(FPskOffers[0].CipherSuite, LPskSuite);
  // the inner transcript must exist before the inner ClientHello is built, so its PSK binder
  // MACs the inner history; a single offered PSK fixes the hash, so pre-activate it too (0-RTT
  // early keys derive from it before the ServerHello selects the suite)
  if FEchOrch.Active then
    FEchOrch.PrepareInnerTranscript(FTranscriptPreActivated, FPreActivatedHash);
  if System.Length(FVerbatimClientHello) > 0 then
    LClientHello := FVerbatimClientHello
  else if FEchOrch.Active then
  begin
    // build and binder-patch the inner ClientHello here (the machine owns the builder and the
    // real PSK offers), then let the orchestrator seal it into the ClientHelloOuter
    LInner := BuildClientHello(FEchOrch.InnerRandom, FEchOrch.InnerEchExt);
    if System.Length(FPskOffers) > 0 then
      PatchBinder(LInner, FEchOrch.InnerTranscript);
    LClientHello := FEchOrch.BuildClientHelloOuter(TEchChMode.Initial, LInner,
      FParams.ClientRandom, FParams.LegacySessionId, FPskOffers);
  end
  else
    // a plain or GREASE ClientHello: GreaseEchExt is nil unless a decoy was built
    LClientHello := BuildClientHello(FParams.ClientRandom, FEchOrch.GreaseEchExt);
  if FEchOrch.Active then
  begin
    // the outer is on the wire; the inner is the logical ClientHello once accepted, so
    // both transcripts are kept until the ServerHello confirmation decides between them
    RememberOffered(FEchOrch.SentInnerRaw);
    FSentClientHelloRaw := LClientHello;
    FTranscript.Update(LClientHello);
    FEchOrch.InnerTranscript.Update(FEchOrch.SentInnerRaw);
  end
  else
  begin
    if System.Length(FPskOffers) > 0 then
      PatchBinder(LClientHello, FTranscript);
    RememberOffered(LClientHello);
    FSentClientHelloRaw := LClientHello;
    FTranscript.Update(LClientHello);
  end;
  FPhase := TPhase.WaitServerHello;
  // the middlebox change_cipher_spec is deferred until the client commits to 1.3 and is
  // about to send its second flight; sending it here (before ServerHello) would break a
  // 1.2 negotiation, where the client's change_cipher_spec comes after ServerHelloDone
  Result := TArray<THandshakeEffect>.Create(
    THandshakeEffects.SendHandshake(LClientHello));
  if FEarlyDataOffered then
  begin
    // derive the client_early_traffic keys from the ClientHello transcript and open the
    // early write epoch, after the (plaintext) middlebox CCS. Under ECH the 0-RTT keys derive
    // from the inner transcript (+ inner random), the logical ClientHello (RFC 9849 sec. 6.1.5)
    FSchedule := TTls13KeySchedule.Create(FParams.Crypto, LPskSuite.Common.Hash,
      LPskSuite.Common.KeyLength);
    FSchedule.SetPsk(FPskOffers[0].Key);
    // key the log by the same random the early transcript uses: the inner ClientHello's under ECH
    if FEchOrch.Active then
      FSchedule.SetKeyLog(FParams.KeyLog, FEchOrch.InnerRandom)
    else
      FSchedule.SetKeyLog(FParams.KeyLog, FParams.ClientRandom);
    if FEchOrch.Active then
      FSchedule.DeriveEpochSecrets(TTlsEpoch.EarlyData, FEchOrch.InnerTranscript.CurrentHash)
    else
      FSchedule.DeriveEpochSecrets(TTlsEpoch.EarlyData, FTranscript.CurrentHash);
    // the plaintext CCS precedes the early keys
    Result := TArrayUtilities.Concat<THandshakeEffect>(Result, MiddleboxCcs);
    TArrayUtilities.Append<THandshakeEffect>(Result,
      THandshakeEffects.InstallKeys(FSchedule.TrafficKeys(TTlsEpoch.EarlyData,
      TTlsDirection.ClientWrite), TRecordSide.WriteSide, LPskSuite.Common.Aead,
      TTlsVersion.Tls13, TTlsEpoch.EarlyData));
    // bound the outbound 0-RTT at the ticket's max_early_data; bytes beyond the budget are
    // refused and the caller resends them as 1-RTT (RFC 9846 4.3.10)
    TArrayUtilities.Append<THandshakeEffect>(Result,
      THandshakeEffects.SetEarlyDataLimit(EarlyDataBudget(FPskOffers[0].MaxEarlyData)));
  end;
end;

class procedure TTls13ClientStateMachine.EnforceTls13ServerHelloExtensions(
  const AVector: TExtensionVector);
var
  LTypes: TArray<UInt16>;
  LType: UInt16;
begin
  LTypes := AVector.Types;
  for LType in LTypes do
    if (LType <> TExtensionTypes.SupportedVersions) and
      (LType <> TExtensionTypes.KeyShare) and
      (LType <> TExtensionTypes.PreSharedKey) then
      raise EFatalAlertTlsLibException.CreateRes(
        TTlsAlertDescription.UnsupportedExtension, @SServerHelloExtNotAllowed);
end;

procedure TTls13ClientStateMachine.RebuildTranscriptUnderSelectedHash;
var
  LFresh: ITranscriptHash;
begin
  LFresh := TTranscriptHash.Create(
    FParams.Crypto.Primitives.CreateHash(FSelectedSuite.Common.Hash));
  LFresh.Update(FSentClientHelloRaw);
  FTranscript := LFresh;
end;

function TTls13ClientStateMachine.ProcessServerHello(
  const AMessage: TTlsHandshakeMessage): TArray<THandshakeEffect>;
var
  LHello: TTlsServerHello;
  LContext: TExtensionContext;
  LExtensions: TExtensionVector;
  LShared: ISecretBuffer;
  LNegotiatedVersion: UInt16;
begin
  LHello := THandshakeMessages.DecodeServerHello(AMessage.Body);

  // a HelloRetryRequest arrives as a ServerHello with the sentinel random
  if THelloRetryRequest.IsSentinel(LHello.Random) then
    Exit(HandleHelloRetryRequest(LHello, AMessage));

  // resolve the negotiated version before anything version-specific (the cipher suite, the
  // key_share): supported_versions when present, else the legacy_version. This client offers
  // only TLS 1.3, so any other selection is not one it agreed to - a stamped downgrade is an
  // attack (illegal_parameter, RFC 9846 4.2.3), any other lower version is unsupported and
  // reported as protocol_version (RFC 9846 E.1; a deliberate deviation from 4.3.1's
  // illegal_parameter), not a cipher/decode error. supported_versions below 1.3 is
  // unsupported_extension, as in the dispatcher.
  if THandshakeMessages.TryGetServerHelloSelectedVersion(LHello.Extensions,
    LNegotiatedVersion) then
  begin
    if LNegotiatedVersion < TlsWireVersionTls13 then
      raise EFatalAlertTlsLibException.CreateRes(
        TTlsAlertDescription.UnsupportedExtension, @SSupportedVersionsBelowTls13);
    // a ServerHello that selects its version via supported_versions is a TLS 1.3 construct
    // whose legacy_version MUST be 0x0303 (RFC 9846 4.2.3); any other value is not a version
    // this client agreed to
    if LHello.LegacyVersion <> TlsWireVersionTls12 then
      raise EFatalAlertTlsLibException.CreateRes(
        TTlsAlertDescription.ProtocolVersion, @SUnsupportedSelectedVersion);
  end
  else
  begin
    // TLS 1.3 is selected only through supported_versions (RFC 9846 4.3.1); an unsupported version
    // aborts with protocol_version (E.1)
    if LHello.LegacyVersion >= TlsWireVersionTls13 then
      raise EFatalAlertTlsLibException.CreateRes(
        TTlsAlertDescription.ProtocolVersion, @SUnsupportedSelectedVersion);
    LNegotiatedVersion := LHello.LegacyVersion;
  end;
  if TDowngradeProtection.IsDowngradeAttack(LHello.Random, True, LNegotiatedVersion) then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.IllegalParameter, @SDowngradeDetected);
  if LNegotiatedVersion <> TlsWireVersionTls13 then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.ProtocolVersion, @SUnsupportedSelectedVersion);

  // after a HelloRetryRequest the ServerHello MUST keep the cipher suite the HRR chose (it
  // fixes the transcript hash); a change is illegal (RFC 9846 4.2.4)
  if FRetried and (LHello.CipherSuite <> FSelectedSuite.Common.Code) then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.IllegalParameter, @SRetryCipherChanged);

  // the selected suite must be one this client offered, not merely one it supports
  // (RFC 9846 4.2.3)
  if not (TArrayUtilities.Contains<UInt16>(FParams.OfferedSuites, LHello.CipherSuite)) then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.IllegalParameter, @SUnofferedSuite);
  if not FParams.CipherSuites.TryGet(LHello.CipherSuite, FSelectedSuite) then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.IllegalParameter, @SUnknownSelectedSuite);
  // a 1.2 suite in a 1.3 hello is a wrong-version selection (RFC 9846 4.2.3)
  if FSelectedSuite.Protocol <> TSuiteProtocol.Tls13 then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.IllegalParameter, @SNotTls13Suite);

  // legacy_session_id_echo must equal the id offered in the ClientHello (RFC 9846 4.2.3)
  if not TArrayUtilities.AreEqual(LHello.LegacySessionIdEcho, FSentLegacySessionId) then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.IllegalParameter, @SBadSessionIdEcho);

  // the hash is now known: activate the transcript (replays the ClientHello) unless a
  // retry already activated it, then add ServerHello. A single offered PSK pre-activated
  // the transcript under its hash; when the server rejects that PSK and selects a suite with
  // a different hash (a 0-RTT reject that changes the PRF), rebuild the transcript from the
  // raw first ClientHello under the newly selected hash so the derivations match the peer.
  // activate the (outer) transcript under the now-known hash unless a retry already did, else
  // rebuild it when a 0-RTT PSK reject changed the PRF (RFC 9846 4.1)
  if not FTranscript.IsActive then
    FTranscript.Activate(FParams.Crypto.Primitives.CreateHash(FSelectedSuite.Common.Hash))
  else if FTranscriptPreActivated and
    (FPreActivatedHash <> FSelectedSuite.Common.Hash) then
    RebuildTranscriptUnderSelectedHash;
  if FEchOrch.Active then
  begin
    // ECH decides accept vs reject from the ServerHello confirmation. On accept the inner
    // ClientHello is the logical one, so the handshake continues on the inner transcript and
    // inner random; on reject it continues to public_name on the outer transcript. The verdict
    // is computed here; the machine applies the state change (all mutation stays in the machine).
    if FEchOrch.DecideServerHello(AMessage.Raw, LHello.Random, FSelectedSuite.Common.Hash,
      FTranscriptPreActivated and (FPreActivatedHash <> FSelectedSuite.Common.Hash)) then
    begin
      FTranscript := FEchOrch.InnerTranscript;
      FActiveClientRandom := FEchOrch.InnerRandom;
    end
    else
    begin
      FExpectedName := TServerName.DnsName(FEchOrch.PublicName);
      // the server answered the ClientHelloOuter, so response extensions are checked against the
      // outer's offers; after a HelloRetryRequest the retry path already recorded CH2's outer
      if not FEchOrch.HrrDecided then
        RememberOffered(FSentClientHelloRaw);
    end;
  end;
  // append the ServerHello to the surviving transcript (the inner on accept, the outer otherwise)
  FTranscript.Update(AMessage.Raw);

  LContext := TExtensionContext.Create;
  try
    ApplyOffered(LContext);
    // the negotiated TLS 1.3 was already confirmed before the cipher suite (above); a
    // TLS 1.3 ServerHello may carry only supported_versions, key_share and pre_shared_key;
    // anything else (e.g. ALPN, which belongs in the encrypted EncryptedExtensions) is
    // unsupported_extension (local policy: RFC 9846 4.2.3 limits the set, and 4.3 would send
    // illegal_parameter for a recognized extension). Checked before the decoders run, so a
    // malformed forbidden extension is reported as forbidden.
    LExtensions := TExtensionVector.Parse(LHello.Extensions);
    EnforceTls13ServerHelloExtensions(LExtensions);
    FCodec.ConsumeBlock(LContext, TTlsExtensionContextKind.ServerHello, LExtensions);

    // this client only ever offers psk_dhe_ke, so a key_share is always required; its
    // absence is missing_extension, distinct from the wrong-group illegal_parameter below
    // (RFC 9846 4.3.8 / 9.2)
    if System.Length(LContext.SelectedKeyShare.KeyExchange) = 0 then
      raise EFatalAlertTlsLibException.CreateRes(
        TTlsAlertDescription.MissingExtension, @SMissingServerKeyShare);

    // the selected group must be the one we key-shared (the initial group, or the one
    // a HelloRetryRequest moved us to), checked before decapsulation (RFC 9846 4.3.8)
    if LContext.SelectedKeyShare.Group <> FCurrentGroupCode then
      raise EFatalAlertTlsLibException.CreateRes(
        TTlsAlertDescription.IllegalParameter, @SUnofferedGroup);

    FCurrentGroup.Decapsulate(FEphemeralPrivate,
      LContext.SelectedKeyShare.KeyExchange, LShared);
    // the ephemeral private is spent; release it now so its buffer is wiped
    FEphemeralPrivate := nil;

    // the server accepted a PSK iff it echoed pre_shared_key with our identity index; that
    // index must be within the list we offered (RFC 9846 4.3.11), and the selected suite's
    // hash must match the accepted PSK's bound hash. Otherwise it fell through to a full
    // handshake and we drop the PSK.
    FPskAccepted := (System.Length(FPskOffers) > 0) and LContext.PskSelected;
    if FPskAccepted then
    begin
      if LContext.SelectedPskIdentity >= System.Length(FPskOffers) then
        raise EFatalAlertTlsLibException.CreateRes(
          TTlsAlertDescription.IllegalParameter, @SBadSelectedPskIdentity);
      FAcceptedPsk := FPskOffers[LContext.SelectedPskIdentity];
      if FSelectedSuite.Common.Hash <> FAcceptedPsk.Hash then
        raise EFatalAlertTlsLibException.CreateRes(
          TTlsAlertDescription.IllegalParameter, @SPskHashMismatch);
      FResumedFromTicket := FAcceptedPsk.BinderKind = TPskBinderKind.Resumption;
      if FResumedFromTicket then
      begin
        FSessionPskIdentity := FResumptionPskIdentity;
        FSessionPskBinding := FResumptionPskBinding;
        // a resumption reports the original authentication's signer, as it reports its chain
        FPeerSignatureScheme := FResumptionPeerSignatureScheme;
      end
      else
      begin
        FSessionPskIdentity := FAcceptedPsk.Identity;
        FSessionPskBinding := TPskSessionBinding.Derive(FParams.Crypto, FAcceptedPsk.Key);
      end;
    end;
    // a PSK-only client requires the server to select one of its PSKs; a ServerHello that
    // falls through to certificate authentication is a fatal missing_extension (local policy,
    // RFC 9846 6.2), since there is no certificate trust to fall back on. A rejected-ECH
    // handshake is the exception: it authenticates the public_name by certificate (RFC 9849
    // sec. 6.1.7) and completes to that name before aborting ech_required, so the PSK
    // requirement does not apply
    if (not FPskAccepted) and FParams.RequirePsk and
      (FEchOrch.Status <> TEchStatus.Rejected) then
      raise EFatalAlertTlsLibException.CreateRes(
        TTlsAlertDescription.MissingExtension, @SPskRequiredNotSelected);
    // a rejected-ECH handshake runs over the outer ClientHello, whose pre_shared_key is only a
    // GREASE decoy: the client aborts with illegal_parameter if the ServerHello selects it
    // (RFC 9849 sec. 6.1.2)
    if (FEchOrch.Status = TEchStatus.Rejected) and LContext.PskSelected then
      raise EFatalAlertTlsLibException.CreateRes(
        TTlsAlertDescription.IllegalParameter, @SEchRejectPsk);
  finally
    LContext.Free;
  end;

  // remember the group the server accepted (our key_share, no HelloRetryRequest needed),
  // so the next initial ClientHello to this server leads with it. Not on an ECH reject: that
  // group is the public_name server's choice, not the real server's, so it is no hint for it
  if (FParams.SessionCache <> nil) and (FEchOrch.Status <> TEchStatus.Rejected) then
    FParams.SessionCache.SetKxHint(CacheServerIdentity, FParams.ServerName,
      FCurrentGroupCode);

  // a PSK is bound to a hash, so the server may pick any same-hash suite for the handshake;
  // 0-RTT, however, is bound to a resumption ticket's exact suite (checked at EE below). An
  // external PSK is bound only to a hash (CipherSuite 0) and offers no 0-RTT.
  FEarlySuiteMatched := FPskAccepted and (FAcceptedPsk.CipherSuite <> 0) and
    (FSelectedSuite.Common.Code = FAcceptedPsk.CipherSuite);

  // reuse the early-data schedule (already PSK-seeded) only when the selected suite
  // matches the ticket's; otherwise build a fresh schedule under the selected suite (still
  // PSK-seeded for psk_dhe_ke) for the full/non-early or different-suite handshake
  if (FSchedule = nil) or (not FPskAccepted) or (not FEarlySuiteMatched) then
  begin
    FSchedule := TTls13KeySchedule.Create(FParams.Crypto, FSelectedSuite.Common.Hash,
      FSelectedSuite.Common.KeyLength);
    // psk_dhe_ke: seed the accepted PSK before deriving the handshake secret
    if FPskAccepted then
      FSchedule.SetPsk(FAcceptedPsk.Key);
  end;
  // report every full-handshake secret; FActiveClientRandom is the inner ClientHello's when ECH
  // was accepted (switched at accept), the outer's otherwise (RFC 9850)
  FSchedule.SetKeyLog(FParams.KeyLog, FActiveClientRandom);
  FSchedule.SetSharedSecret(LShared);
  FSchedule.DeriveEpochSecrets(TTlsEpoch.Handshake, FTranscript.CurrentHash);

  FPhase := TPhase.WaitEncryptedExtensions;
  // the version leads the flight so the server's change_cipher_spec is classified (dropped)
  // before it is pulled; then the middlebox change_cipher_spec goes out (empty here when 0-RTT
  // already sent it) and the server handshake read keys install
  Result := TArrayUtilities.Concat<THandshakeEffect>(
    TArray<THandshakeEffect>.Create(
    THandshakeEffects.NegotiatedVersion(TTlsVersion.Tls13)), MiddleboxCcs);
  TArrayUtilities.Append<THandshakeEffect>(Result,
    THandshakeEffects.InstallKeys(FSchedule.TrafficKeys(TTlsEpoch.Handshake,
    TTlsDirection.ServerWrite), TRecordSide.ReadSide, FSelectedSuite.Common.Aead, TTlsVersion.Tls13, TTlsEpoch.Handshake));
  // with an accepted 0-RTT offer the write side stays on the early keys until
  // EndOfEarlyData (sent at EncryptedExtensions); otherwise switch write to handshake now
  if FEarlyDataOffered and FPskAccepted then
    Exit;
  TArrayUtilities.Append<THandshakeEffect>(Result,
    THandshakeEffects.InstallKeys(FSchedule.TrafficKeys(TTlsEpoch.Handshake,
    TTlsDirection.ClientWrite), TRecordSide.WriteSide, FSelectedSuite.Common.Aead, TTlsVersion.Tls13, TTlsEpoch.Handshake));
  // a PSK-rejected 0-RTT offer means the early data was ignored: the engine replays it
  if FEarlyDataOffered then
  begin
    // the server never derived the early exporter for a refused offer, so drop ours
    FSchedule.ForgetEarlyExporter;
    TArrayUtilities.Append<THandshakeEffect>(Result,
      THandshakeEffects.RaiseEvent(TTlsEventKind.EarlyDataRejected));
  end;
end;

function TTls13ClientStateMachine.ProcessEncryptedExtensions(
  const AMessage: TTlsHandshakeMessage): TArray<THandshakeEffect>;
var
  LContext: TExtensionContext;
  LServerAcceptedEarly, LEchPresent: Boolean;
  LEchData: TBytes;
begin
  Result := nil;
  FTranscript.Update(AMessage.Raw);
  LContext := TExtensionContext.Create;
  try
    // a response extension the client did not offer is fatal (RFC 9846 4.3)
    ApplyOffered(LContext);
    FCodec.ConsumeBlock(LContext, TTlsExtensionContextKind.EncryptedExtensions,
      THandshakeMessages.DecodeEncryptedExtensions(AMessage.Body));
    LServerAcceptedEarly := LContext.EarlyDataAccepted;
    // the codec already detected/extracted any ech extension into the context; capture it before
    // the context is freed so the orchestrator applies the EncryptedExtensions ech rule below
    LEchPresent := LContext.EchPresent;
    LEchData := LContext.EchExtensionData;

    // the server's ALPN choice must be one this client offered (the server's rule, RFC 7301 3.2)
    if System.Length(LContext.SelectedAlpn) > 0 then
    begin
      if not TAlpnProtocols.Contains(FParams.AlpnProtocols, LContext.SelectedAlpn) then
        raise EFatalAlertTlsLibException.CreateRes(
          TTlsAlertDescription.IllegalParameter, @SUnofferedAlpn);
      FNegotiatedAlpn := LContext.SelectedAlpn; // stored on any resumption ticket
      TArrayUtilities.Append<THandshakeEffect>(Result,
        THandshakeEffects.SelectAlpn(LContext.SelectedAlpn));
    end;

    // apply record_size_limit (RFC 8449) only when it was negotiated - the server echoed it,
    // which the extension codec permits only because we offered it. When the server omits it the
    // limit is not in force in either direction (RFC 8449 4), so a caller-configured limit must
    // not cap the server's records. Caps are raw TLSInnerPlaintext; the record layer accounts for
    // the inner content-type byte.
    if LContext.RecordSizeLimit > 0 then
    begin
      if LContext.RecordSizeLimit < 64 then
        raise EFatalAlertTlsLibException.CreateRes(
          TTlsAlertDescription.IllegalParameter, @SBadRecordSizeLimit);
      TArrayUtilities.Append<THandshakeEffect>(Result,
        THandshakeEffects.SetRecordSizeLimit(LContext.RecordSizeLimit,
        FParams.RecordSizeLimit));
    end;
  finally
    LContext.Free;
  end;
  // the EncryptedExtensions ech rule (retry_configs on reject, unsolicited on accept, validated
  // and ignored under GREASE) lives in the orchestrator
  FEchOrch.NoteEncryptedExtensions(LEchPresent, LEchData);
  // early_data in EncryptedExtensions is meaningful only when we offered 0-RTT and the server
  // accepted the PSK; sent on a full handshake it is an extension the response cannot carry
  // (RFC 9846 4.3.10)
  if LServerAcceptedEarly and not (FEarlyDataOffered and FPskAccepted) then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.UnsupportedExtension, @SEarlyDataWithoutPsk);
  // 0-RTT resolution (only when we offered it and the PSK was accepted): the write side
  // stays on the early keys here. On accept, EndOfEarlyData and the write switch happen
  // after the server Finished (transcript order); on reject we switch off early now and
  // the engine replays the early data as 1-RTT.
  if FEarlyDataOffered and FPskAccepted then
  begin
    if LServerAcceptedEarly then
    begin
      // 0-RTT is bound to the ticket's exact suite; a server that accepts early data
      // under a different suite than the PSK's is illegal (RFC 9846 4.3.10)
      if not FEarlySuiteMatched then
        raise EFatalAlertTlsLibException.CreateRes(
          TTlsAlertDescription.IllegalParameter, @SEarlyDataSuiteMismatch);
      // 0-RTT is likewise bound to the resumed session's ALPN: when the server accepts early
      // data it MUST negotiate the same ALPN protocol as that session (RFC 9846 4.3.10); a
      // changed (or dropped) protocol is illegal
      if not TArrayUtilities.AreEqual(FNegotiatedAlpn, FAcceptedPsk.Alpn) then
        raise EFatalAlertTlsLibException.CreateRes(
          TTlsAlertDescription.IllegalParameter, @SEarlyDataAlpnMismatch);
      FEarlyDataAccepted := True;
      TArrayUtilities.Append<THandshakeEffect>(Result,
        THandshakeEffects.RaiseEvent(TTlsEventKind.EarlyDataAccepted));
    end
    else
    begin
      FSchedule.ForgetEarlyExporter;
      TArrayUtilities.Append<THandshakeEffect>(Result,
        THandshakeEffects.RaiseEvent(TTlsEventKind.EarlyDataRejected));
      TArrayUtilities.Append<THandshakeEffect>(Result,
        THandshakeEffects.InstallKeys(FSchedule.TrafficKeys(TTlsEpoch.Handshake,
        TTlsDirection.ClientWrite), TRecordSide.WriteSide, FSelectedSuite.Common.Aead,
        TTlsVersion.Tls13, TTlsEpoch.Handshake));
    end;
  end;
  // on an accepted resumption the server sends no Certificate/CertificateVerify: the
  // next message is its Finished
  if FPskAccepted then
    FPhase := TPhase.WaitServerFinished
  else
    FPhase := TPhase.WaitCertificate;
end;

function TTls13ClientStateMachine.HandleHelloRetryRequest(
  const AHello: TTlsServerHello;
  const AMessage: TTlsHandshakeMessage): TArray<THandshakeEffect>;
var
  LContext: TExtensionContext;
  LNewGroup: INamedGroup;
  LClientHello2, LInner2: TBytes;
  LOffered: TArray<UInt16>;
  LCh1Hash: IHash;
  LEarlyDataWasOffered: Boolean;
  LSelectedVersion: UInt16;
begin
  // at most one HelloRetryRequest per handshake (RFC 9846 4.2.4)
  if FRetried then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.UnexpectedMessage, @SHelloRetryTwice);

  // like any ServerHello, the HRR's legacy_version must be exactly 0x0303 (RFC 9846 4.2.3); the
  // real version rides supported_versions, checked next
  if AHello.LegacyVersion <> TlsWireVersionTls12 then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.ProtocolVersion, @SUnsupportedSelectedVersion);

  // a HelloRetryRequest is a TLS 1.3 message, so its supported_versions MUST select TLS 1.3;
  // absent or any other value is a version this client did not agree to (RFC 9846 4.2.4, 4.3.1)
  if not THandshakeMessages.TryGetServerHelloSelectedVersion(AHello.Extensions,
    LSelectedVersion) or (LSelectedVersion <> TlsWireVersionTls13) then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.IllegalParameter, @SHelloRetryVersion);

  // the selected suite must be one we offered (RFC 9846 4.2.3)
  if not (TArrayUtilities.Contains<UInt16>(FParams.OfferedSuites, AHello.CipherSuite)) then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.IllegalParameter, @SUnofferedSuite);
  if not FParams.CipherSuites.TryGet(AHello.CipherSuite, FSelectedSuite) then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.IllegalParameter, @SUnknownSelectedSuite);
  if FSelectedSuite.Protocol <> TSuiteProtocol.Tls13 then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.IllegalParameter, @SNotTls13Suite);
  if not TArrayUtilities.AreEqual(AHello.LegacySessionIdEcho, FSentLegacySessionId) then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.IllegalParameter, @SBadSessionIdEcho);

  // the cipher (hence hash) is now fixed: drop any offered PSK bound to a different hash, so
  // the second ClientHello offers only the still-eligible PSKs (RFC 9846 4.2.2). A single
  // resumption offer already matches; a multi-hash external offer shrinks to one entry.
  PruneOffersToHash(FSelectedSuite.Common.Hash);

  // the hash is known: rebase the transcript to message_hash(Hash(ClientHello1)) under the
  // retry-selected hash (RFC 9846 4.1), computed from the RAW first ClientHello. Using the
  // raw bytes keeps this correct even when a single-PSK resumption pre-activated the transcript
  // under a different hash the retry then rejects (a non-resumable-cipher HRR). Then add the HRR.
  LCh1Hash := FParams.Crypto.Primitives.CreateHash(FSelectedSuite.Common.Hash);
  LCh1Hash.Update(FSentClientHelloRaw, 0, System.Length(FSentClientHelloRaw));
  FTranscript.SeedWithMessageHash(
    FParams.Crypto.Primitives.CreateHash(FSelectedSuite.Common.Hash), LCh1Hash.DoFinal);
  FTranscript.Update(AMessage.Raw);
  // the retry-selected hash is now the transcript's hash, so the pre-activation reconciliation
  // (the different-PRF rebuild in ProcessServerHello) no longer applies to the next ServerHello
  FTranscriptPreActivated := False;
  // under ECH, decide accept/reject from the HRR's ech confirmation and rebase the inner
  // transcript before building the second ClientHello
  if FEchOrch.Active then
    FEchOrch.DecideHelloRetryRequest(AHello, AMessage, FSelectedSuite.Common.Hash);

  LContext := TExtensionContext.Create;
  try
    // the cookie is the response the client did not offer but must accept in a HRR
    ApplyOffered(LContext);
    LContext.MarkOffered(TExtensionTypes.Cookie);
    FCodec.ConsumeBlock(LContext, TTlsExtensionContextKind.HelloRetryRequest,
      AHello.Extensions);

    // a HelloRetryRequest may request a different key_share group, or carry only a cookie
    // (RFC 9846 4.2.4). When it names a group, it must be one we advertised and must differ
    // from the group we already key-shared; we then regenerate the key_share for it.
    if LContext.HelloRetryGroup <> 0 then
    begin
      LOffered := FParams.OfferedGroups;
      if System.Length(LOffered) = 0 then
        LOffered := TArray<UInt16>.Create(FCurrentGroupCode);
      if not (TArrayUtilities.Contains<UInt16>(LOffered, LContext.HelloRetryGroup)) then
        raise EFatalAlertTlsLibException.CreateRes(
          TTlsAlertDescription.IllegalParameter, @SHelloRetryUnoffered);
      if LContext.HelloRetryGroup = FCurrentGroupCode then
        raise EFatalAlertTlsLibException.CreateRes(
          TTlsAlertDescription.IllegalParameter, @SHelloRetrySameGroup);
      if (FParams.GroupRegistry = nil) or
        not FParams.GroupRegistry.TryGet(LContext.HelloRetryGroup, LNewGroup) then
        raise EFatalAlertTlsLibException.CreateRes(
          TTlsAlertDescription.IllegalParameter, @SHelloRetryNoGroup);
      FCurrentGroup := LNewGroup;
      FCurrentGroupCode := LContext.HelloRetryGroup;
      FCurrentGroup.GenerateKeyPair(FEphemeralPrivate, FEphemeralPublic);
      FHrrChangedGroup := True;
    end
    else if System.Length(LContext.Cookie) = 0 then
      // no group change and no cookie leaves the ClientHello unchanged: a HelloRetryRequest
      // must produce some change, else it is illegal (RFC 9846 4.2.4)
      raise EFatalAlertTlsLibException.CreateRes(
        TTlsAlertDescription.IllegalParameter, @SHelloRetryNoChange);
    FCookie := LContext.Cookie;
    FRetried := True;
  finally
    LContext.Free;
  end;

  // a HelloRetryRequest rejects any offered 0-RTT (RFC 9846 4.3.10): the second ClientHello
  // MUST NOT re-offer early_data, so clear the offer before rebuilding it
  LEarlyDataWasOffered := FEarlyDataOffered;
  FEarlyDataOffered := False;

  if FEchOrch.Active and FEchOrch.HrrAccepted then
  begin
    // ECH was accepted on CH1: build a fresh inner CH2 (new key_share), patch its binder over the
    // rebased inner transcript, then re-seal at seq=1 with an empty enc; feed both transcripts
    // (outer + inner) their second ClientHello
    LInner2 := BuildClientHello(FEchOrch.InnerRandom, FEchOrch.InnerEchExt);
    if System.Length(FPskOffers) > 0 then
      PatchBinder(LInner2, FEchOrch.InnerTranscript);
    LClientHello2 := BuildRetryOuter(TEchChMode.RetryAccept, LInner2);
    RememberOffered(FEchOrch.SentInnerRaw);
    FTranscript.Update(LClientHello2);
    FEchOrch.InnerTranscript.Update(FEchOrch.SentInnerRaw);
  end
  else if FEchOrch.Active then
  begin
    // ECH was not accepted on CH1: the handshake continues on the outer to public_name, so CH2
    // is a ClientHelloOuter (public_name SNI, GREASE PSK, retry key_share) whose ech extension
    // is CH1's echoed verbatim. The inner is still built (it shapes the outer's extensions).
    // Only the outer transcript advances.
    LInner2 := BuildClientHello(FEchOrch.InnerRandom, FEchOrch.InnerEchExt);
    if System.Length(FPskOffers) > 0 then
      PatchBinder(LInner2, FEchOrch.InnerTranscript);
    LClientHello2 := BuildRetryOuter(TEchChMode.RetryReject, LInner2);
    RememberOffered(LClientHello2);
    FTranscript.Update(LClientHello2);
  end
  else
  begin
    // a GREASE decoy is re-sent verbatim on the retry (RFC 9849 sec. 6.2.1); GreaseEchExt is nil
    // on a plain handshake
    LClientHello2 := BuildClientHello(FParams.ClientRandom, FEchOrch.GreaseEchExt);
    // recompute the binder over the retry transcript (message_hash(CH1), HRR, this
    // ClientHello up to the binders): the first flight's binder does not vouch for it
    if System.Length(FPskOffers) > 0 then
      PatchBinder(LClientHello2, FTranscript);
    RememberOffered(LClientHello2);
    FTranscript.Update(LClientHello2);
  end;
  FPhase := TPhase.WaitServerHello;
  // on a retry the client's second flight is the second ClientHello, so the middlebox
  // change_cipher_spec goes immediately before it (RFC 9846 E.4). The negotiated version leads
  // the flight so the server's post-HelloRetryRequest change_cipher_spec is classified (dropped)
  // before it is pulled: a retry installs no keys, so nothing else fixes the version until the
  // real ServerHello.
  Result := TArrayUtilities.Concat<THandshakeEffect>(
    TArray<THandshakeEffect>.Create(
    THandshakeEffects.NegotiatedVersion(TTlsVersion.Tls13)), MiddleboxCcs);
  // when this ClientHello had opened the 0-RTT write window, the early data is now rejected:
  // signal it and drop the write epoch back to plaintext so the second ClientHello onward is
  // sent in the clear (the middlebox change_cipher_spec was already emitted with the first flight)
  if LEarlyDataWasOffered then
  begin
    FSchedule.ForgetEarlyExporter;
    TArrayUtilities.Append<THandshakeEffect>(Result,
      THandshakeEffects.RaiseEvent(TTlsEventKind.EarlyDataRejected));
    TArrayUtilities.Append<THandshakeEffect>(Result,
      THandshakeEffects.RevertWriteToPlaintext);
  end;
  TArrayUtilities.Append<THandshakeEffect>(Result,
    THandshakeEffects.SendHandshake(LClientHello2));
end;

function TTls13ClientStateMachine.HandleCertificate(
  const ACertificateBody, ATranscriptRaw: TBytes): TArray<THandshakeEffect>;
var
  LCert: TTlsCertificate;
  LI: Int32;
  LExtType: UInt16;
  LAlert: TTlsAlertDescription;
  LVerified: TVerifiedChain;
  LVerifier: IServerCertificateVerifier;
begin
  LCert := THandshakeMessages.DecodeCertificate(ACertificateBody);
  // the server Certificate context is empty in the main handshake (RFC 9846 4.5.1)
  if System.Length(LCert.RequestContext) <> 0 then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.DecodeError, @SServerCertContextNotEmpty);
  if System.Length(LCert.Entries) = 0 then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.DecodeError, @SEmptyCertificate);
  // RFC 9846 4.5.1: every CertificateEntry extension must correspond to one offered in the
  // ClientHello, and only status_request / SCT are defined for a certificate entry; an
  // unsolicited or unknown extension is unsupported_extension. Only the leaf's values are used;
  // intermediates' are validated and ignored. A repeated type is already illegal_parameter from
  // the extension parse in CertificateEntryExtensionTypes, so it never reaches this check.
  for LI := 0 to High(LCert.Entries) do
    for LExtType in THandshakeMessages.CertificateEntryExtensionTypes(
      LCert.Entries[LI].Extensions) do
      if not (((LExtType = StatusRequestExtensionCode) or (LExtType = SctExtensionCode)) and
        (TArrayUtilities.Contains<UInt16>(FOfferedExtensions, LExtType))) then
        raise EFatalAlertTlsLibException.CreateRes(
          TTlsAlertDescription.UnsupportedExtension, @SUnsolicitedCertExtension);
  // keep the chain (leaf first) for the CertificateVerify and the trust verdict
  FCertificateChain := nil;
  FParsedServerLeaf := nil;
  SetLength(FCertificateChain, System.Length(LCert.Entries));
  for LI := 0 to High(LCert.Entries) do
    FCertificateChain[LI] := LCert.Entries[LI].CertData;

  // a server leaf that is not a well-formed certificate is a decode error, caught before
  // the CertificateVerify signature check and the trust verdict
  FParsedServerLeaf := TCertificateVerify.ParseWellFormedLeaf(FParams.Inspector,
    FCertificateChain[0]);

  // capture any stapled OCSP response carried in the leaf entry (RFC 9846 4.5.1.1)
  FReceivedOcspStaple := nil;
  THandshakeMessages.TryExtractLeafStaple(LCert.Entries[0].Extensions,
    FReceivedOcspStaple);

  // the trust verdict is fail-closed: no configured verifier, or a negative verdict,
  // aborts the handshake with the reason's alert
  LVerifier := FParams.CertificateVerifier;
  // a reject proves public_name before its retry_configs are trusted (RFC 9849 6.1.7)
  if (FEchOrch.Status = TEchStatus.Rejected) and (FParams.EchRejectCertificateVerifier <> nil) then
    LVerifier := FParams.EchRejectCertificateVerifier;
  if LVerifier = nil then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.InternalError, @SNoCertificateVerifier);
  if not LVerifier.VerifyServerCertificate(FCertificateChain,
    FExpectedName, FReceivedOcspStaple, LVerified, LAlert) then
    raise EFatalAlertTlsLibException.CreateRes(LAlert, @SUntrustedCertificate);

  // the on-the-wire message (compressed, when compressed) is what feeds the transcript
  FTranscript.Update(ATranscriptRaw);
  FPhase := TPhase.WaitCertificateVerify;
  // surface the presented chain and the validated path for connection info (read-only; both the
  // inline and async paths)
  Result := TArray<THandshakeEffect>.Create(
    THandshakeEffects.PeerCertificateChain(FCertificateChain, LVerified.ValidatedPath));
  // surface any accepted staple so an integration can inspect it
  if System.Length(FReceivedOcspStaple) > 0 then
    TArrayUtilities.Append<THandshakeEffect>(Result,
      THandshakeEffects.PeerOcspStaple(FReceivedOcspStaple));
  FPeerVerified := LVerified;
end;

function TTls13ClientStateMachine.ProcessCertificateVerify(
  const AMessage: TTlsHandshakeMessage): TArray<THandshakeEffect>;
begin
  VerifyCertificateVerify(AMessage);
  FTranscript.Update(AMessage.Raw);
  FPhase := TPhase.WaitServerFinished;
  Result := nil;
  // park only after the key proof so an unproven certificate never costs a fetch or a host decision
  if TPeerAuthentication.ShouldPark(FParams.Deferral, FPeerVerified.Outcome) then
    Result := TArray<THandshakeEffect>.Create(ParkForVerdict(FCertificateChain,
      FPeerVerified.ValidatedPath, FExpectedName.ToString, FReceivedOcspStaple,
      FParams.RevocationPosture));
  FPeerVerified := Default(TVerifiedChain);
end;

function TTls13ClientStateMachine.ProcessCertificate(
  const AMessage: TTlsHandshakeMessage): TArray<THandshakeEffect>;
begin
  Result := HandleCertificate(AMessage.Body, AMessage.Raw);
end;

function TTls13ClientStateMachine.ProcessCompressedCertificate(
  const AMessage: TTlsHandshakeMessage): TArray<THandshakeEffect>;
var
  LCompressed: TTlsCompressedCertificate;
  LCertificateBody: TBytes;
begin
  // a CompressedCertificate is legal only if we advertised compress_certificate
  if not (TArrayUtilities.Contains<UInt16>(FOfferedExtensions,
    TExtensionTypes.CompressCertificate)) then
    Exit(Unexpected);
  LCompressed := THandshakeMessages.DecodeCompressedCertificate(AMessage.Body);
  // decompression runs through the injected decompressors under one bomb defense (ratio guard,
  // exact-length match); the ceiling is the configured message budget, so the decompressed chain
  // is bounded by the same cap as the uncompressed path before it reaches any verifier
  LCertificateBody := TCertificateCompression.Decompress(
    FParams.CertificateDecompressors, LCompressed.Algorithm,
    LCompressed.Compressed, LCompressed.UncompressedLength,
    FParams.CertificateChainLimits.MaxTotalChainLength);
  Result := HandleCertificate(LCertificateBody, AMessage.Raw);
end;

procedure TTls13ClientStateMachine.VerifyCertificateVerify(
  const AMessage: TTlsHandshakeMessage);
var
  LCertVerify: TTlsCertificateVerify;
  LScheme: TSignatureScheme;
  LContent: TBytes;
begin
  LCertVerify := THandshakeMessages.DecodeCertificateVerify(AMessage.Body);
  // the server must sign with a scheme the client offered, valid for a TLS 1.3 handshake, and
  // the leaf's key must be allowed to produce it
  LScheme := TPeerAuthentication.RequirePeerScheme(FParams.OfferedSchemes,
    LCertVerify.Algorithm, TTlsVersion.Tls13, FParsedServerLeaf);
  FPeerSignatureScheme := LCertVerify.Algorithm;
  // the signature is over the transcript through the Certificate (this message not yet folded in)
  LContent := TCertificateVerify.SignatureContent(TCertificateVerifySide.Server,
    FTranscript.CurrentHash);
  TPeerAuthentication.VerifyPeerSignature(FParams.Crypto, FParsedServerLeaf, LScheme,
    LContent, LCertVerify.Signature);
end;

procedure TTls13ClientStateMachine.ProcessCertificateRequest(
  const AMessage: TTlsHandshakeMessage);
var
  LRequest: TTlsCertificateRequest13;
  LContext: TExtensionContext;
  LExtensions: TExtensionVector;
begin
  // one CertificateRequest per handshake; post-handshake authentication is not offered, so a
  // second one has no legal slot (RFC 9846 4.4.2, 4.7.2)
  if FCertificateRequested then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.UnexpectedMessage, @SCertificateRequestTwice);
  LRequest := THandshakeMessages.DecodeCertificateRequest13(AMessage.Body);
  // the certificate_request_context is zero-length in the handshake CertificateRequest;
  // a non-empty one is only valid in post-handshake auth, which is not offered (RFC 9846 4.4.2)
  if System.Length(LRequest.RequestContext) <> 0 then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.DecodeError, @SRequestContextNotEmpty);
  FRequestContext := LRequest.RequestContext;
  // a CertificateRequest MUST carry signature_algorithms; its absence is fatal (RFC 9846 4.4.2)
  LExtensions := TExtensionVector.Parse(LRequest.Extensions);
  if not LExtensions.Contains(TExtensionTypes.SignatureAlgorithms) then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.MissingExtension, @SCertReqMissingSigAlgs);
  LContext := TExtensionContext.Create;
  try
    FCodec.ConsumeBlock(LContext, TTlsExtensionContextKind.CertificateRequest, LExtensions);
    FClientAuthSchemes := LContext.SignatureSchemes;
    if System.Length(LContext.SignatureSchemesCert) > 0 then
      FClientAuthCertSchemes := LContext.SignatureSchemesCert
    else
      FClientAuthCertSchemes := LContext.SignatureSchemes;
    FRequestedCertificateAuthorities := LContext.CertificateAuthorities;
    FServerCertCompressionAlgorithms := LContext.CertCompressionAlgorithms;
  finally
    LContext.Free;
  end;
  // a request none of whose schemes a TLS 1.3 handshake can use (RFC 9846 4.3.3) could never
  // accept a CertificateVerify, whatever the credential, so it is refused; a request with usable schemes
  // none of which fits the credential is declined with an empty Certificate (RFC 9846 4.5.1)
  if not HasTls13UsableScheme(FClientAuthSchemes) then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.HandshakeFailure, @SNoUsableCertificateRequestScheme);
  FCertificateRequested := True;
  FTranscript.Update(AMessage.Raw);
end;

class function TTls13ClientStateMachine.HasTls13UsableScheme(
  const ASchemes: TArray<UInt16>): Boolean;
var
  LI: Int32;
  LScheme: TSignatureScheme;
begin
  Result := False;
  for LI := 0 to System.High(ASchemes) do
    if TSignatureScheme.TryFromCode(ASchemes[LI], LScheme) and
      LScheme.IsValidForHandshake(TTlsVersion.Tls13) then
      Exit(True);
end;

procedure TTls13ClientStateMachine.AppendClientAuthFlight(
  var AEffects: TArray<THandshakeEffect>);
var
  LCert: TTlsCertificate;
  LScheme: TSignatureScheme;
  LI: Int32;
  LHasScheme: Boolean;
  LCertBytes, LContent, LCertVerifyBytes: TBytes;
  LSigner: ISignatureSigner;
  LVerify: TTlsCertificateVerify;
begin
  // choose a credential scheme the server accepts; with no credential, or none whose scheme the
  // server accepts, the client declines with an empty Certificate (RFC 9846 4.5.1) and the
  // server's own policy decides. On an ECH reject the handshake is with the client-facing
  // server on the public_name, not the intended server, so the client MUST NOT present its
  // certificate there (RFC 9849 sec. 6.1.7): it declines with an empty one. It also declines when
  // its chain has MD5, or SHA-1 the server did not advertise (RFC 9846 4.5.1.2; MD5 inferred from
  // 4.5.1.3).
  LHasScheme := False;
  if (System.Length(FParams.ClientCredential.CertificateChain) > 0) and
    (FEchOrch.Status <> TEchStatus.Rejected) and
    TChainAlgorithmPolicy.SendableTo(FParams.Inspector,
    FParams.ClientCredential.CertificateChain, FClientAuthCertSchemes) then
  begin
    for LScheme in FParams.ClientCredential.PrivateKey.CapableSchemes do
      if LScheme.IsValidForHandshake(TTlsVersion.Tls13) and
        (TArrayUtilities.Contains<UInt16>(FClientAuthSchemes, LScheme.ToCode)) then
      begin
        LHasScheme := True;
        Break;
      end;
  end;

  LCert.RequestContext := FRequestContext;
  LCert.Entries := nil;
  if LHasScheme then
  begin
    SetLength(LCert.Entries, System.Length(FParams.ClientCredential.CertificateChain));
    for LI := 0 to High(FParams.ClientCredential.CertificateChain) do
    begin
      LCert.Entries[LI].CertData := FParams.ClientCredential.CertificateChain[LI];
      LCert.Entries[LI].Extensions := TBytes.Create($00, $00);
    end;
  end;
  // compressed when the server advertised an algorithm we hold (RFC 8879), else a plain Certificate;
  // the transcript folds the message as sent
  LCertBytes := TCertificateCompression.FrameCertificate(FParams.CertificateCompressors,
    FServerCertCompressionAlgorithms, FParams.CertificateCompressionCache, FParams.Crypto,
    THandshakeMessages.EncodeCertificate(LCert), LHasScheme);
  FTranscript.Update(LCertBytes);
  TArrayUtilities.Append<THandshakeEffect>(AEffects,
    THandshakeEffects.SendHandshake(LCertBytes));

  if not LHasScheme then
    Exit;
  // the CertificateVerify signs the transcript through the client Certificate
  LContent := TCertificateVerify.SignatureContent(TCertificateVerifySide.Client,
    FTranscript.CurrentHash);
  LSigner := FParams.Crypto.Signing.CreateSignatureSigner(LScheme,
    FParams.ClientCredential.PrivateKey);
  LSigner.Update(LContent, 0, System.Length(LContent));
  LVerify.Algorithm := LScheme.ToCode;
  LVerify.Signature := LSigner.Sign;
  LCertVerifyBytes := THandshakeFraming.Frame(TTlsHandshakeType.CertificateVerify,
    THandshakeMessages.EncodeCertificateVerify(LVerify));
  FTranscript.Update(LCertVerifyBytes);
  TArrayUtilities.Append<THandshakeEffect>(AEffects,
    THandshakeEffects.SendHandshake(LCertVerifyBytes));
end;

function TTls13ClientStateMachine.MiddleboxCcs: TArray<THandshakeEffect>;
begin
  Result := nil;
  if FMiddleboxCcsSent then
    Exit;
  FMiddleboxCcsSent := True;
  Result := TArray<THandshakeEffect>.Create(THandshakeEffects.SendChangeCipherSpec);
end;

function TTls13ClientStateMachine.EarlyDataOfferReason(ASessionTaken: Boolean): TEarlyDataReason;
var
  LSuite: TTlsCipherSuite;
begin
  Result := TEarlyDataReason.Accepted;
  if not FParams.EarlyDataEnabled then
    Result := TEarlyDataReason.Disabled
  else if not ASessionTaken then
    Result := TEarlyDataReason.NoSessionOffered
  else if (System.Length(FPskOffers) <> 1) or
    (FPskOffers[0].BinderKind <> TPskBinderKind.Resumption) or
    (FPskOffers[0].MaxEarlyData = 0) or
    (not FParams.CipherSuites.TryGet(FPskOffers[0].CipherSuite, LSuite)) then
    Result := TEarlyDataReason.UnsupportedForSession
  else if (System.Length(FPskOffers[0].Alpn) > 0) and
    (not TAlpnProtocols.Contains(FParams.AlpnProtocols, FPskOffers[0].Alpn)) then
    // RFC 9846 4.3.10: the ticket's ALPN must still be an offered protocol
    Result := TEarlyDataReason.AlpnMismatch
  else if ResumeVerdictOwed then
    // the out-of-band verdict arrives after the server flight, so no early data may precede it
    Result := TEarlyDataReason.Disabled;
end;

function TTls13ClientStateMachine.ResumeVerdictOwed: Boolean;
begin
  Result := (FParams.ResumeVerification = TResumeVerification.Reverify) and
    (FParams.Deferral <> TVerdictDeferral.None) and
    (System.Length(FResumptionPskIdentity) = 0);
end;

function TTls13ClientStateMachine.Facts: TNegotiationFacts;
begin
  Result := Default(TNegotiationFacts);
  Result.PeerSignatureScheme := FPeerSignatureScheme;
  Result.HelloRetryRequest := FRetried;
  if not FEarlyDataEverOffered then
    Result.EarlyDataReason := FEarlyReasonAtOffer
  else if FRetried then
    Result.EarlyDataReason := TEarlyDataReason.HelloRetryRequest
  else if FEarlyDataAccepted then
    Result.EarlyDataReason := TEarlyDataReason.Accepted
  else if FPskAccepted and FResumedFromTicket then
    Result.EarlyDataReason := TEarlyDataReason.PeerDeclined
  else
    Result.EarlyDataReason := TEarlyDataReason.SessionNotResumed;
end;

function TTls13ClientStateMachine.ProcessServerFinished(
  const AMessage: TTlsHandshakeMessage): TArray<THandshakeEffect>;
var
  LHashBeforeFinished, LHashAfterFinished: TBytes;
begin
  // the server Finished is over the transcript EXCLUDING itself
  LHashBeforeFinished := FTranscript.CurrentHash;
  if not FSchedule.VerifyFinished(TTlsDirection.ServerWrite, LHashBeforeFinished,
    AMessage.Body) then
    raise EFatalAlertTlsLibException.CreateRes(TTlsAlertDescription.DecryptError,
      @SBadServerFinished);
  FTranscript.Update(AMessage.Raw);
  if not FResumedFromTicket then
    FAuthenticatedAtMs := FParams.Clock.NowUnixMillis;

  // application secrets are over the transcript through the server Finished (before any
  // EndOfEarlyData or the client Finished)
  LHashAfterFinished := FTranscript.CurrentHash;
  FSchedule.DeriveEpochSecrets(TTlsEpoch.Application, LHashAfterFinished);

  // a resumed handshake carries no Certificate: surface the server chain the ticket stored, with the
  // path the offer-time re-check validated under Reverify (empty otherwise). Before any park,
  // so connection info reads it while parked - the ordering a full handshake already has. Only a
  // resumed ticket carries a chain; an accepted external PSK did not authenticate by this stored one.
  Result := nil;
  if FResumedFromTicket and (System.Length(FResumptionPeerCertificates) > 0) then
    TArrayUtilities.Append<THandshakeEffect>(Result,
      THandshakeEffects.PeerCertificateChain(FResumptionPeerCertificates, FResumeValidatedPath));

  // a resumption has no staple, so the owed verdict parks here, before our Finished is committed
  if FResumedFromTicket and ResumeVerdictOwed then
  begin
    FPhase := TPhase.WaitResumeVerdict;
    TArrayUtilities.Append<THandshakeEffect>(Result,
      ParkForVerdict(FResumptionPeerCertificates, FResumeValidatedPath,
      FExpectedName.ToString, nil, FParams.RevocationPosture));
    Exit;
  end;

  Result := TArrayUtilities.Concat<THandshakeEffect>(Result, BuildClientFinishedFlight);
end;

function TTls13ClientStateMachine.BuildClientFinishedFlight: TArray<THandshakeEffect>;
var
  LClientVerifyData, LClientFinished, LEndOfEarlyData: TBytes;
begin
  Result := nil;
  // accepted 0-RTT: EndOfEarlyData (under the early keys) closes early data and folds
  // into the transcript, then the write side moves to the handshake keys (RFC 9846 4.6)
  if FEarlyDataAccepted then
  begin
    LEndOfEarlyData := THandshakeFraming.Frame(TTlsHandshakeType.EndOfEarlyData, nil);
    FTranscript.Update(LEndOfEarlyData);
    TArrayUtilities.Append<THandshakeEffect>(Result,
      THandshakeEffects.SendHandshake(LEndOfEarlyData));
    TArrayUtilities.Append<THandshakeEffect>(Result,
      THandshakeEffects.InstallKeys(FSchedule.TrafficKeys(TTlsEpoch.Handshake,
      TTlsDirection.ClientWrite), TRecordSide.WriteSide, FSelectedSuite.Common.Aead,
      TTlsVersion.Tls13, TTlsEpoch.Handshake));
  end;

  // mutual TLS: the client Certificate (+ CertificateVerify) precede the client Finished
  // and fold into the transcript the Finished verify_data covers
  if FCertificateRequested then
    AppendClientAuthFlight(Result);

  LClientVerifyData := FSchedule.ComputeVerifyData(TTlsDirection.ClientWrite,
    FTranscript.CurrentHash);
  LClientFinished := THandshakeFraming.Frame(TTlsHandshakeType.Finished,
    THandshakeMessages.EncodeFinished(LClientVerifyData));
  FTranscript.Update(LClientFinished);
  // the resumption secret is over the transcript through the client Finished
  FSchedule.DeriveResumptionMasterSecret(FTranscript.CurrentHash);
  FSchedule.ForgetHandshakeSecrets;
  // drop the offered/accepted PSKs too, so a resumption PSK does not outlive the handshake
  FAcceptedPsk := nil;
  FPskOffers := nil;

  // ECH reject: the flight to the public_name is complete (cert verified against it, our
  // Finished built); send that Finished, then abort with ech_required and surface the
  // retry_configs (RFC 9849 sec. 6.1.6) - no ticket caching, no plaintext fall-back
  if FEchOrch.Status = TEchStatus.Rejected then
  begin
    FPhase := TPhase.Connected;
    TArrayUtilities.Append<THandshakeEffect>(Result,
      THandshakeEffects.SendHandshake(LClientFinished));
    // the handshake completed, so the write side moves to the application keys (RFC 9846 4.5.3)
    // before the ech_required alert: a completed connection's post-Finished records - the alert
    // included - ride the application keys, and the peer decrypts them as such
    TArrayUtilities.Append<THandshakeEffect>(Result,
      THandshakeEffects.InstallKeys(FSchedule.TrafficKeys(TTlsEpoch.Application,
      TTlsDirection.ClientWrite), TRecordSide.WriteSide, FSelectedSuite.Common.Aead,
      TTlsVersion.Tls13, TTlsEpoch.Application));
    TArrayUtilities.Append<THandshakeEffect>(Result,
      THandshakeEffects.EchRejected(FEchOrch.RetryConfigs, FParams.EchPolicy.IsRetryAttempt));
    Exit(Result);
  end;

  FPhase := TPhase.Connected;
  MarkConnected;
  // the client auth flight and Finished are sent under the handshake write keys, THEN
  // the write side moves to the application keys - order matters
  TArrayUtilities.Append<THandshakeEffect>(Result,
    THandshakeEffects.SendHandshake(LClientFinished));
  TArrayUtilities.Append<THandshakeEffect>(Result,
    THandshakeEffects.InstallKeys(FSchedule.TrafficKeys(TTlsEpoch.Application,
    TTlsDirection.ClientWrite), TRecordSide.WriteSide, FSelectedSuite.Common.Aead,
    TTlsVersion.Tls13, TTlsEpoch.Application));
  TArrayUtilities.Append<THandshakeEffect>(Result,
    THandshakeEffects.InstallKeys(FSchedule.TrafficKeys(TTlsEpoch.Application,
    TTlsDirection.ServerWrite), TRecordSide.ReadSide, FSelectedSuite.Common.Aead,
    TTlsVersion.Tls13, TTlsEpoch.Application));
  TArrayUtilities.Append<THandshakeEffect>(Result,
    THandshakeEffects.ConnectionParams(FSelectedSuite.Common.Code,
    FCurrentGroupCode, FPskAccepted and FResumedFromTicket, True, FParams.ServerName, Facts));
  // the external identity as configured, also for a ticket resumption of a PSK-authenticated session
  if FPskAccepted and (System.Length(FSessionPskIdentity) > 0) then
    TArrayUtilities.Append<THandshakeEffect>(Result,
      THandshakeEffects.PskIdentity(
      TExternalPskImporter.ExternalIdentity(FSessionPskIdentity)));
  if FCertificateRequested then
    TArrayUtilities.Append<THandshakeEffect>(Result,
      THandshakeEffects.RequestedCertificateAuthorities(
      FRequestedCertificateAuthorities, FClientAuthSchemes));
  if FEchOrch.Status = TEchStatus.Accepted then
    TArrayUtilities.Append<THandshakeEffect>(Result,
      THandshakeEffects.EchAccepted)
  else if FEchOrch.Status = TEchStatus.Greased then
    TArrayUtilities.Append<THandshakeEffect>(Result,
      THandshakeEffects.EchGreased);
  TArrayUtilities.Append<THandshakeEffect>(Result,
    THandshakeEffects.HandshakeEstablished);
end;

function TTls13ClientStateMachine.ContinueAfterVerdict: TArray<THandshakeEffect>;
begin
  // only the reverify-on-resume park withholds a continuation; the initial-certificate park
  // resumes by draining the buffered server flight, so there is nothing to emit for that one
  Result := nil;
  if FPhase = TPhase.WaitResumeVerdict then
    Result := BuildClientFinishedFlight;
end;

function TTls13ClientStateMachine.WriteDirection: TTlsDirection;
begin
  Result := TTlsDirection.ClientWrite;
end;

function TTls13ClientStateMachine.ReadDirection: TTlsDirection;
begin
  Result := TTlsDirection.ServerWrite;
end;

function TTls13ClientStateMachine.Route(
  const AMessage: TTlsHandshakeMessage): TArray<THandshakeEffect>;
var
  LType: TTlsHandshakeType;
  LKnown: Boolean;
begin
  LKnown := TTlsHandshakeType.TryFromByte(AMessage.TypeByte, LType);
  case FPhase of
    TPhase.WaitServerHello:
      if LKnown and (LType = TTlsHandshakeType.ServerHello) then
        Result := ProcessServerHello(AMessage)
      else
        Result := Unexpected;
    TPhase.WaitEncryptedExtensions:
      if LKnown and (LType = TTlsHandshakeType.EncryptedExtensions) then
        Result := ProcessEncryptedExtensions(AMessage)
      else
        Result := Unexpected;
    TPhase.WaitCertificate:
      // a CertificateRequest (mutual TLS) precedes the server Certificate; record it
      // and keep waiting for the Certificate (RFC 9846 4.4.2)
      if LKnown and (LType = TTlsHandshakeType.CertificateRequest) then
      begin
        ProcessCertificateRequest(AMessage);
        Result := nil;
      end
      else if LKnown and (LType = TTlsHandshakeType.Certificate) then
        Result := ProcessCertificate(AMessage)
      else if LKnown and (LType = TTlsHandshakeType.CompressedCertificate) then
        Result := ProcessCompressedCertificate(AMessage)
      else
        Result := Unexpected;
    TPhase.WaitCertificateVerify:
      if LKnown and (LType = TTlsHandshakeType.CertificateVerify) then
        Result := ProcessCertificateVerify(AMessage)
      else
        Result := Unexpected;
    TPhase.WaitServerFinished:
      if LKnown and (LType = TTlsHandshakeType.Finished) then
        Result := ProcessServerFinished(AMessage)
      else
        Result := Unexpected;
    TPhase.Connected:
      // post-handshake: a NewSessionTicket is cached (RFC 9846 4.7.1), a KeyUpdate rekeys
      // the read epoch and may trigger one responding update (RFC 9846 4.7.3)
      if LKnown and (LType = TTlsHandshakeType.NewSessionTicket) then
        Result := CacheNewSessionTicket(AMessage)
      else if LKnown and (LType = TTlsHandshakeType.KeyUpdate) then
        Result := HandleInboundKeyUpdate(AMessage)
      else
        Result := Unexpected;
  else
    Result := Unexpected;
  end;
end;

procedure TTls13ClientStateMachine.ForgetSessionsOnFatal;
var
  LSession: IResumableSession;
  LStored: TArray<IResumableSession>;
begin
  // RFC 9846 6: tickets of a failed connection SHOULD be discarded
  LStored := FStoredSessions;
  FStoredSessions := nil;
  if FParams.SessionCache = nil then
    Exit;
  for LSession in LStored do
    try
      FParams.SessionCache.Remove(CacheServerIdentity, FParams.ServerName, LSession);
    except
      // one failing removal must not keep the rest from being withdrawn
    end;
end;

end.
