{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpTls13ServerStateMachine;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpArrayUtilities,
  TlpBinaryPrimitives,
  TlpTlsAlert,
  TlpTlsVersion,
  TlpTlsLibExceptions,
  TlpISecretBuffer,
  TlpISigningKey,
  TlpICryptoProvider,
  TlpIPkixProvider,
  TlpINamedGroup,
  TlpIKeySchedule,
  TlpTls13KeySchedule,
  TlpITranscriptHash,
  TlpTranscriptHash,
  TlpCryptoDomainTypes,
  TlpNegotiationTypes,
  TlpINegotiation,
  TlpNegotiationPolicy,
  TlpISession,
  TlpIClock,
  TlpSession,
  TlpExternalPskImporter,
  TlpSessionTicketStrategy,
  TlpExtensionContext,
  TlpITlsExtension,
  TlpCoreExtensions,
  TlpExtensionVector,
  TlpWireReader,
  TlpHandshakeMessage,
  TlpHandshakeMessages,
  TlpHelloRetryCookie,
  TlpCertificateCompression,
  TlpICertificateCompression,
  TlpICertificateCompressionCache,
  TlpCertificateVerify,
  TlpPeerAuthentication,
  TlpICertificateTrust,
  TlpTlsCredential,
  TlpITlsCredentialResolver,
  TlpServerOfferSelection,
  TlpIEch,
  TlpEchConfig,
  TlpEchExtension,
  TlpEchServer,
  TlpHandshakeEffect,
  TlpRecordHeader,
  TlpIHandshakeMachine,
  TlpTls13HandshakeBase;

type
  /// <summary>The inputs a server handshake needs to negotiate and send its flight.</summary>
  TServerHandshakeParams = record
    Crypto: ICryptoProvider;
    Inspector: ICertificateInspector;
    Policy: INegotiationPolicy;
    CipherSuites: ICipherSuiteRegistry;
    ExtensionRegistry: IExtensionRegistry;
    /// <summary>The (EC)DHE groups this server supports, in preference order (RFC 8446
    /// 4.2.7). The server selects the first that the client offered - preferring one the
    /// client already key-shared to avoid a HelloRetryRequest. secp256r1 is mandatory to
    /// implement (RFC 8446 9.1), so a server offers several groups, not a single one. When
    /// empty, the single Group below is used instead (resolved via GroupRegistry).</summary>
    OfferedGroups: TArray<UInt16>;
    /// <summary>Resolves a selected group code (from OfferedGroups) to its INamedGroup for
    /// key agreement; required whenever OfferedGroups is set.</summary>
    GroupRegistry: INamedGroupRegistry;
    /// <summary>A single fixed (EC)DHE group, used only when OfferedGroups is empty (the
    /// low-level sans-IO entry point); the engine factory always sets OfferedGroups.</summary>
    Group: INamedGroup;
    ServerRandom: TBytes;
    /// <summary>The server's ALPN protocols in preference order. When set and the
    /// client offers ALPN, the server selects its first match, or aborts with
    /// no_application_protocol on no overlap (RFC 7301).</summary>
    AlpnProtocols: TArray<string>;
    /// <summary>The record_size_limit (RFC 8449) plaintext value the server advertises,
    /// in [64, 2^14]; 0 leaves the extension unoffered.</summary>
    RecordSizeLimit: Int32;
    /// <summary>Whether the server echoes the empty server_name acknowledgement (RFC 6066 3)
    /// when the client offered a host_name.</summary>
    ServerNameAck: Boolean;
    /// <summary>Whether the server rejects any client ALPN offer with no_application_protocol
    /// (RFC 7301) instead of selecting or declining.</summary>
    AlpnRejectAll: Boolean;
    /// <summary>The per-server-instance secret authenticating the HelloRetryRequest
    /// cookie. Required for a server that may answer with a HelloRetryRequest.</summary>
    CookieSecret: ISecretBuffer;
    /// <summary>The certificate-compression algorithms the server can compress with
    /// (RFC 8879). When the client advertised a matching algorithm and compression
    /// shrinks the Certificate, the server sends a CompressedCertificate; empty never
    /// compresses.</summary>
    CertificateCompressors: TArray<ICertificateCompressor>;
    /// <summary>Memoizes the compressed Certificate across connections (RFC 8879), so a
    /// stable certificate deflates once; nil compresses on every handshake.</summary>
    CertificateCompressionCache: ICertificateCompressionCache;
    /// <summary>Selects the credential the Certificate and CertificateVerify are produced from,
    /// per handshake from the client's SNI (virtual hosting). The selected chain is sent, its
    /// private key signs the CertificateVerify, and its OCSP staple (if any) is stapled in the
    /// leaf CertificateEntry when the client offered status_request (RFC 8446 4.4.2.1). nil for
    /// a PSK-only server.</summary>
    CredentialResolver: ITlsServerCredentialResolver;
    /// <summary>The Encrypted Client Hello key store (RFC 9849), or nil when ECH is not
    /// served. When set, the server trial-decrypts an offered ech, and on success
    /// continues with the reconstructed inner ClientHello.</summary>
    EchKeyStore: IEchServerKeyStore;
    /// <summary>Whether to trial-decrypt against every key regardless of config_id (the
    /// guarded ignore-config_id mode). Off by default.</summary>
    EchTrialDecrypt: Boolean;
    /// <summary>Whether the server requests a client certificate (mutual TLS) and how
    /// strictly it is enforced.</summary>
    ClientAuth: TClientAuthMode;
    /// <summary>The signature schemes advertised in CertificateRequest and accepted for
    /// the client CertificateVerify (RFC 8446 4.3.2).</summary>
    ClientAuthSignatureSchemes: TArray<UInt16>;
    /// <summary>The DER-encoded DistinguishedName issuers named in the CertificateRequest's
    /// certificate_authorities extension (RFC 8446 4.2.4); empty names none.</summary>
    ClientCertificateAuthorities: TArray<TBytes>;
    /// <summary>Trusts (or rejects) the client certificate chain; required whenever
    /// ClientAuth is not None. Hostname identity does not apply to a client cert.</summary>
    ClientCertificateVerifier: IClientCertificateVerifier;
    /// <summary>When set, after the built-in pipeline accepts the client chain the machine
    /// parks the handshake for an out-of-band verdict (the deferred-verdict seam) rather than
    /// continuing inline. Augment-only and fail-closed. OFF by default.</summary>
    AsyncVerdict: Boolean;
    // whether the async verdict is a live-revocation deferral (vs a host-decision park): a
    // live-revocation park is skipped when the verifier settled revocation inline
    LiveRevocationDeferral: Boolean;
    /// <summary>The out-of-band external PSKs (RFC 9258) the server imports and matches an
    /// offered pre_shared_key against, in preference order. A matching PSK is preferred over
    /// the server certificate. Empty leaves external PSK off.</summary>
    ExternalPsks: TArray<TExternalPsk>;
    /// <summary>The stateless session-ticket key manager (STEK). When set (and no store),
    /// the server issues AEAD-sealed tickets under it - the default resumption strategy.</summary>
    SessionTicketKeys: ISessionTicketKeyManager;
    /// <summary>When set, upgrades resumption to stateful single-use handles into this
    /// store (over the STEK default). Nil (with no STEK) disables 1.3 resumption.</summary>
    SessionStore: ISessionStore;
    /// <summary>An opaque scope sealed into issued tickets and required to match on resumption,
    /// partitioning configurations that share a ticket key or store; empty does not partition.</summary>
    ResumptionScope: TBytes;
    /// <summary>How many NewSessionTickets to send after the handshake (0 = none).</summary>
    IssueTicketCount: Int32;
    /// <summary>The ticket lifetime hint in seconds carried in each NewSessionTicket.</summary>
    TicketLifetimeSeconds: UInt32;
    /// <summary>The 0-RTT byte budget the server advertises in its tickets and accepts;
    /// 0 disables early data (the default).</summary>
    MaxEarlyData: UInt32;
    /// <summary>The bounded anti-replay register that gates 0-RTT acceptance; required
    /// whenever MaxEarlyData is set (no register means no early data is accepted).</summary>
    AntiReplay: IAntiReplayStrategy;
    /// <summary>The clock read for ticket issue time and 0-RTT freshness (RFC 8446 4.6.1). The
    /// factory supplies one from the config; the constructor defaults it to the system clock.</summary>
    Clock: ITlsClock;
  end;

  /// <summary>
  /// The TLS 1.3 server machine. It kicks on the ClientHello: if the client offered
  /// no key_share for the group the server selects, it answers with a stateless
  /// HelloRetryRequest (a cookie carries Hash(ClientHello1) and the group, so no
  /// per-connection state is kept across the two hellos) and rebuilds the transcript
  /// from the cookie on the second ClientHello. Otherwise it sends the ServerHello,
  /// installs the handshake keys, sends the encrypted flight (EncryptedExtensions,
  /// Certificate, CertificateVerify, Finished), installs the server application write
  /// keys, then verifies the client Finished and installs the read keys. It returns
  /// effects and never touches the record layer.
  /// </summary>
  TTls13ServerStateMachine = class sealed(TTls13HandshakeBase, ITls13ServerReplay)
  strict private
  type
    TPhase = (Initial, WaitSecondClientHello, WaitClientCertificate,
      WaitClientCertVerify, WaitEndOfEarlyData, WaitClientFinished, Connected);
    /// <summary>The server's encrypted-flight messages, framed. CertificateRequest is
    /// empty unless client authentication is requested.</summary>
    TServerFlight = record
      EncryptedExtensions: TBytes;
      CertificateRequest: TBytes;
      Certificate: TBytes;
      CertificateVerify: TBytes;
      Finished: TBytes;
    end;
  var
    FParams: TServerHandshakeParams;
    FPhase: TPhase;
    /// <summary>The (EC)DHE group selected from the client's offer, resolved to its group
    /// object for encapsulation (RFC 8446 4.2.8).</summary>
    FSelectedGroup: INamedGroup;
    FCookie: THelloRetryCookie;
    FSelectedAlpn: string;
    /// <summary>The ALPN protocol bound to an accepted resumption ticket; 0-RTT is only
    /// accepted when the ALPN negotiated on the resumed handshake matches it (RFC 8446 4.2.11).</summary>
    FAcceptedSessionAlpn: string;
    FClientSentServerName: Boolean;
    FRequestedServerName: string;
    // the credential the resolver selected for this handshake, from the client's SNI
    FResolvedCredential: TTlsCredential;
    FPeerRecordSizeLimit: Int32;
    /// <summary>The CertificateVerify scheme negotiated in NegotiateFrom: the first of
    /// the credential's schemes the client also offered.</summary>
    FSelectedSignatureScheme: TSignatureScheme;
    /// <summary>The certificate-compression algorithms the client advertised, used to
    /// pick a compressor for the Certificate flight (RFC 8879).</summary>
    FClientCertCompressionAlgorithms: TArray<UInt16>;
    /// <summary>The client's certificate chain (leaf first), captured for the client
    /// CertificateVerify once the client Certificate is processed.</summary>
    FClientCertChain: TArray<TBytes>;
    // the client chain the accepted ticket carried (empty when none), surfaced on the resumed
    // connection since a resumed handshake sends no Certificate
    FResumedPeerCertificates: TArray<TBytes>;
    // the client leaf parsed once for the well-formed gate, reused for the signing-policy
    // check and its SubjectPublicKeyInfo; released once the signature is verified
    FParsedClientLeaf: IInspectedCertificate;
    /// <summary>Whether this handshake authenticated via a pre_shared_key (a resumption
    /// ticket or an out-of-band external PSK): the server skips its Certificate/
    /// CertificateVerify and seeds the schedule with the PSK.</summary>
    FPskAccepted: Boolean;
    FSelectedPskIdentity: UInt16;
    /// <summary>The accepted PSK secret, seeded into the schedule.</summary>
    FPskSecret: ISecretBuffer;
    /// <summary>Which binder label the accepted PSK uses (resumption vs imported), for the
    /// retry re-validation over the second ClientHello.</summary>
    FPskBinderKind: TPskBinderKind;
    /// <summary>The accepted PSK's wire identity, re-located in the retry ClientHello (its
    /// offered index may shift when the client prunes its PSK list).</summary>
    FAcceptedPskIdentity: TBytes;
    /// <summary>The configured external PSKs imported for every supported KDF hash, in
    /// server preference order; matched against a ClientHello's offered identities.</summary>
    FExternalPsks: TArray<IPreSharedKey>;
    /// <summary>How tickets are sealed and opened (STEK stateless, or store single-use);
    /// nil when resumption is not configured.</summary>
    FTicketStrategy: ISessionTicketStrategy;
    /// <summary>Whether the ClientHello offered early_data, and whether the server accepted
    /// 0-RTT (a valid ticket within max_early_data that passed anti-replay).</summary>
    FEarlyDataOfferedByClient: Boolean;
    FEarlyDataAccepted: Boolean;
    /// <summary>The max_early_data_size the resumed ticket authorized; bounds how much rejected
    /// 0-RTT to skip. 0 when no ticket opened (e.g. a foreign STEK), in which case the skip budget
    /// falls back to the fixed default unless this server's own config authorizes early data.</summary>
    FResumedMaxEarlyData: UInt32;
    /// <summary>Whether the ClientHello offered status_request, so the server staples its
    /// configured OCSP response in the leaf CertificateEntry (RFC 8446 4.4.2.1).</summary>
    FStatusRequestOffered: Boolean;
    /// <summary>Whether the ClientHello advertised psk_dhe_ke in psk_key_exchange_modes. A ticket
    /// this server issues is only resumable via psk_dhe_ke, so a client that offered neither that
    /// mode nor the extension cannot use one: the server sends no NewSessionTicket (RFC 8446
    /// 4.2.9).</summary>
    FClientOfferedPskDheKe: Boolean;
    /// <summary>Whether a HelloRetryRequest has been sent. After an HRR a conformant client
    /// never sends 0-RTT, so the server neither accepts nor skips early data on the second
    /// flight: any early-data records there fail to deprotect (RFC 8446 4.2.10).</summary>
    FHelloRetrySent: Boolean;
    /// <summary>The ClientHello-only transcript hash, for the early traffic secret.</summary>
    FEarlyTranscriptHash: TBytes;
    /// <summary>Encrypted Client Hello per-connection state (RFC 9849): the trial-decrypt
    /// handshake, the outcome, the inner random (for the accept confirmation stamped into
    /// ServerHello.random), and the retry_configs to advertise on reject.</summary>
    FEch: IEchServerHandshake;
    FEchStatus: TEchStatus;
    FEchInnerRandom: TBytes;
    FEchRetryConfigs: TBytes;
    // ITls13ServerReplay: framed messages emitted verbatim when set, built normally when empty
    FVerbatimRetryCookie: TBytes;
    FVerbatimEncryptedExtensions: TBytes;
    FVerbatimCertificate: TBytes;
    FVerbatimCertificateVerify: TBytes;
    /// <summary>Stamps the ECH accept confirmation into the last 8 bytes of the framed
    /// ServerHello (RFC 9849 sec. 7.2), computed over the inner transcript through this
    /// ServerHello with those 8 bytes zeroed.</summary>
    procedure StampEchAcceptConfirmation(var AServerHelloBytes: TBytes);
    /// <summary>Whether the ClientHello carries an inner-type encrypted_client_hello (the
    /// backend role, RFC 9849 sec. 7.1). Raises decode_error on a malformed ech extension
    /// (a non-empty inner body or an unknown type).</summary>
    class function DetectBackendEch(const AClientHello: TTlsClientHello): Boolean; static;
    /// <summary>Stamps the HelloRetryRequest ech accept confirmation (RFC 9849 sec. 7.2.1):
    /// its 8-byte value is the LAST 8 bytes of AHrrBytes (the ech extension is spliced last),
    /// computed over message_hash(AInnerCh1Hash) then the HRR with that payload zeroed.</summary>
    procedure StampHrrEchConfirmation(var AHrrBytes: TBytes;
      const AInnerCh1Hash: TBytes);
    /// <summary>Appends the SelectAlpn and SetRecordSizeLimit effects for the flight.</summary>
    procedure AppendNegotiatedInfoEffects(var AEffects: TArray<THandshakeEffect>);
    function ProcessClientHello(const AMessage: TTlsHandshakeMessage)
      : TArray<THandshakeEffect>;
    function ProcessSecondClientHello(const AMessage: TTlsHandshakeMessage)
      : TArray<THandshakeEffect>;
    /// <summary>Consumes the ClientHello extensions into AContext, validates the
    /// signature_algorithms, and selects the version, suite (FSelectedSuite), and the
    /// server's group; raises the right alert on any mismatch. When AAllowResumption is
    /// set it first tries to accept a resumption PSK (which then picks the suite and
    /// skips the certificate-auth path).</summary>
    procedure NegotiateFrom(const AClientHello: TTlsClientHello;
      const AContext: TExtensionContext; const ARawClientHello: TBytes;
      AAllowResumption: Boolean; out ASelectedGroup: UInt16);
    /// <summary>
    /// Attempts to accept a resumption PSK from the ClientHello: looks up the first
    /// offered identity in the store (single-use), checks it is unexpired, and verifies
    /// the binder constant-time over the truncated ClientHello. On success it seeds
    /// FPskAccepted/FPskSecret/FSelectedSuite and marks AContext; any failure returns
    /// False (the caller then runs a full handshake, never fatal).
    /// </summary>
    function TryAcceptResumption(const AClientHello: TTlsClientHello;
      const AContext: TExtensionContext; const ARawClientHello: TBytes): Boolean;
    /// <summary>
    /// Attempts to accept an out-of-band external PSK (RFC 9258 / RFC 8446 4.2.11): walks
    /// the server's imported PSKs in preference order, taking the first whose imported
    /// identity the client offered and for which the client offered a same-hash cipher
    /// suite the server supports, then verifies its "imp binder" over the truncated
    /// ClientHello. A matched identity with an invalid binder is fatal; no match returns
    /// False (the server then tries its certificate). Requires psk_dhe_ke.
    /// </summary>
    function TryAcceptExternalPsk(const AClientHello: TTlsClientHello;
      const AContext: TExtensionContext; const ARawClientHello: TBytes): Boolean;
    /// <summary>The first TLS 1.3 cipher suite (server preference) whose hash is AHash and
    /// which AClientSuites offered; False when none qualifies.</summary>
    function SelectSuiteWithHash(const AClientSuites: TArray<UInt16>;
      AHash: THashAlgorithm; out ASuite: TTlsCipherSuite): Boolean;
    /// <summary>The index of AIdentity in AOffered (exact bytes), or -1 when absent.</summary>
    class function IndexOfOfferedIdentity(const AOffered: TArray<TBytes>;
      const AIdentity: TBytes): Int32; static;
    /// <summary>Rejects a malformed pre_shared_key that offers unequal identity and binder
    /// counts (RFC 8446 4.2.11); a no-op when no PSK is offered. Runs on every ClientHello
    /// (including the retry) so a mismatch introduced on either flight is caught.</summary>
    procedure ValidatePskBinderCount(const AContext: TExtensionContext);
    /// <summary>Appends the post-handshake NewSessionTicket sends (RFC 8446 4.6.1).</summary>
    procedure EmitNewSessionTickets(var AEffects: TArray<THandshakeEffect>);
    /// <summary>The serialized length of a pre_shared_key binders vector.</summary>
    class function BindersVectorLength(const ABinders: TArray<TBytes>): Int32; static;
    /// <summary>Whether the client's obfuscated_ticket_age is fresh enough to accept 0-RTT: the
    /// de-obfuscated reported age must be within 60s of the server-measured elapsed time in
    /// either direction (RFC 8446 8.2; matches rustls MAX_FRESHNESS_SKEW_MS and BoringSSL's
    /// ticket_age_skew window). A larger skew declines 0-RTT while the session still resumes.</summary>
    class function EarlyDataAgeFresh(AObfuscatedAgeMillis, ATicketAgeAdd: UInt32;
      AIssuedAtMillis, ANowMillis: UInt64): Boolean; static;
    /// <summary>Whether pre_shared_key is the last extension in a ClientHello extension block
    /// (RFC 8446 4.2.11); True when no pre_shared_key is present.</summary>
    class function PreSharedKeyIsLast(const AExtensions: TBytes): Boolean; static;
    /// <summary>The first credential scheme (preference order) the client also offered;
    /// False when the credential's key can satisfy none of the client's schemes.</summary>
    function SelectSignatureScheme(const AClientSchemes: TArray<UInt16>;
      out AScheme: TSignatureScheme): Boolean;
    /// <summary>The client's key_share bytes for AGroup, or nil when none was offered.</summary>
    class function KeyShareFor(const AContext: TExtensionContext;
      AGroup: UInt16): TBytes; static;
    function HashOf(const AData: TBytes): TBytes;
    /// <summary>The wire-byte budget for skipping rejected 0-RTT records: the ticket-authorized
    /// max_early_data plus each record's header + AEAD expansion (RFC 8446 4.6.1), counted the
    /// way the record layer debits the skip; the fixed fallback applies with no authorization.</summary>
    function EarlyDataSkipBudget: Int32;
    /// <summary>Emits a HelloRetryRequest for ASelectedGroup and waits for the retry.</summary>
    function EmitHelloRetryRequest(const AClientHello: TTlsClientHello;
      const ARaw: TBytes; ASelectedGroup: UInt16): TArray<THandshakeEffect>;
    /// <summary>Frames a HelloRetryRequest (a ServerHello with the sentinel random).</summary>
    function BuildHelloRetryRequest(const ALegacySessionId: TBytes;
      ASelectedGroup: UInt16; const ACookie: TBytes;
      const AEchInnerCh1Hash: TBytes): TBytes;
    /// <summary>Emits the ServerHello and encrypted flight over a transcript already
    /// seeded through the client hello; encapsulates against AClientShare.</summary>
    function EmitServerFlight(const AClientHello: TTlsClientHello;
      ASelectedGroup: UInt16; const AClientShare: TBytes; ASendChangeCipherSpec: Boolean)
      : TArray<THandshakeEffect>;
    /// <summary>Frames the ServerHello for the selected group and server key share.</summary>
    function BuildServerHello(const AClientHello: TTlsClientHello;
      ASelectedGroup: UInt16; const AServerShare: TBytes): TBytes;
    /// <summary>Re-validates the resumption PSK binder on the retry ClientHello over the
    /// rebuilt transcript (message_hash(CH1), HRR, second ClientHello up to the binders).
    /// The client recomputes the binder after a HelloRetryRequest, so the first flight's
    /// binder does not vouch for the retry; a present-but-invalid binder is fatal
    /// (RFC 8446 4.2.11.2). The transcript must already be seeded through the HRR.</summary>
    procedure RevalidateRetryBinder(const ARawClientHello: TBytes;
      const AContext: TExtensionContext);
    /// <summary>Builds EncryptedExtensions..Finished, folding each into the transcript
    /// and deriving the application secrets over the full flight.</summary>
    function BuildEncryptedFlight: TServerFlight;
    /// <summary>Consumes EndOfEarlyData (RFC 8446 4.5) and switches the read epoch from
    /// the early keys to the handshake keys for the client Finished.</summary>
    function ProcessEndOfEarlyData(const AMessage: TTlsHandshakeMessage)
      : TArray<THandshakeEffect>;
    function ProcessClientFinished(const AMessage: TTlsHandshakeMessage)
      : TArray<THandshakeEffect>;
    /// <summary>Serializes the EncryptedExtensions from a typed empty extension list.</summary>
    function BuildEncryptedExtensions: TBytes;
    /// <summary>Frames the Certificate message from the credential's chain.</summary>
    function BuildCertificate: TBytes;
    /// <summary>Frames a CertificateRequest advertising the accepted signature schemes.</summary>
    function BuildCertificateRequest: TBytes;
    /// <summary>Signs and frames the CertificateVerify over the transcript hash.</summary>
    function SignCertificateVerify(const ATranscriptHash: TBytes): TBytes;
    /// <summary>Trust-verifies the client Certificate; fail-closed when auth is required
    /// and the client presented none.</summary>
    function ProcessClientCertificate(const AMessage: TTlsHandshakeMessage)
      : TArray<THandshakeEffect>;
    /// <summary>Verifies the client CertificateVerify signature against the client leaf.</summary>
    function ProcessClientCertVerify(const AMessage: TTlsHandshakeMessage)
      : TArray<THandshakeEffect>;
    // ITls13ServerReplay
    procedure SetVerbatimRetryCookie(const ACookie: TBytes);
    procedure SetVerbatimEncryptedExtensions(const AFramed: TBytes);
    procedure SetVerbatimCertificate(const AFramed: TBytes);
    procedure SetVerbatimCertificateVerify(const AFramed: TBytes);
  strict protected
    function Route(const AMessage: TTlsHandshakeMessage)
      : TArray<THandshakeEffect>; override;
    function WriteDirection: TTlsDirection; override;
    function ReadDirection: TTlsDirection; override;
  public
    constructor Create(const AParams: TServerHandshakeParams);
    destructor Destroy; override;
    function Start: TArray<THandshakeEffect>; override;
  end;

implementation

resourcestring
  SUnknownSelectedSuite = 'the negotiated cipher suite is not in the registry';
  SGroupNotOffered = 'the client offered no (EC)DHE group the server supports';
  SGroupNotResolvable = 'the selected named group is not in the group registry';
  SGroupsKeyShareMismatch =
    'supported_groups and key_share must both be present or both absent';
  SNoSignatureAlgorithms = 'the client offered no signature_algorithms';
  SNoCompatibleScheme = 'the server credential cannot satisfy the client signature_algorithms';
  SNoPskOrCertificate = 'no offered pre_shared_key matched and the server has no certificate';
  SNoCredentialForServerName = 'no server certificate is configured for the requested SNI host';
  SNoDefaultCredential = 'the client sent no server_name and no default certificate is configured';
  SCredentialNoSigningKey = 'the selected server credential has no signing key';
  SBadClientFinished = 'the client Finished did not verify';
  SBadPskBinder = 'the pre_shared_key binder did not validate';
  SPskBinderCountMismatch = 'the pre_shared_key offers unequal identity and binder counts';
  SPskMissingOnRetry = 'the second ClientHello dropped the pre_shared_key the server selected';
  SPskIdentityNotFound = 'the second ClientHello no longer offers the selected pre_shared_key identity';
  SPreSharedKeyNotLast = 'pre_shared_key is not the last ClientHello extension';
  SPskWithoutKeyExchangeModes =
    'pre_shared_key was offered without psk_key_exchange_modes';
  SClientCertificateRequired = 'client authentication is required but none was sent';
  SUnsolicitedClientCertExtension =
    'the client certificate carries an extension that was not requested';
  SUntrustedClientCertificate = 'the client certificate chain was not trusted';
  SBadClientCertVerify = 'the client CertificateVerify did not verify';
  SUnrequestedClientCertVerifyScheme =
    'the client CertificateVerify uses a signature scheme the CertificateRequest did not offer';
  SLegacyPkcs1InClientCertVerify = 'the client CertificateVerify uses a legacy rsa_pkcs1 ' +
    'scheme, which is certificate-only in TLS 1.3';
  SNoCookieAuthority = 'no cookie secret configured for a HelloRetryRequest';
  SMissingCookie = 'the second ClientHello carried no cookie';
  SBadCookie = 'the HelloRetryRequest cookie did not verify';
  SCookieGroupMismatch = 'the cookie group does not match the selected group';
  SNoRetryKeyShare = 'the second ClientHello sent no key_share for the requested group';
  SRetrySuiteChanged =
    'the retry ClientHello does not keep the cipher suite the HelloRetryRequest selected';
  SNoAlpnOverlap = 'no overlap between the client and server ALPN protocols';
  SBadRecordSizeLimit = 'the peer record_size_limit is below the 64-byte minimum';
  SNonEmptyEndOfEarlyData = 'the EndOfEarlyData message must be empty';
  SEchInnerRandomChanged = 'the ClientHelloInner random changed across the HelloRetryRequest';
  SEchAcceptedWithoutHandshake = 'ECH is marked accepted but the handshake state is gone';
  SEchInnerAtClientFacing = 'an inner-type Encrypted Client Hello reached a server that ' +
    'holds ECH keys; it must arrive only at a split-mode backend';

const
  PskDheKeMode = Byte(1);       // psk_key_exchange_modes: psk_dhe_ke
  TicketNonceLength = Int32(8); // per-ticket nonce for the resumption PSK derivation
  // fallback skip budget when no ticket authorization is known (RFC 8446 4.6.1 / 5.1): one
  // record layer's worth of plaintext, beyond which a rejected-0-RTT peer is treated as
  // sending too much skipped early data
  DefaultMaxEarlyDataSkipBytes = Int32(16384);

{ TTls13ServerStateMachine }

constructor TTls13ServerStateMachine.Create(const AParams: TServerHandshakeParams);
begin
  inherited Create(AParams.ExtensionRegistry);
  FParams := AParams;
  FPhase := TPhase.Initial;
  FEchStatus := TEchStatus.NotOffered;
  if FParams.CookieSecret <> nil then
    FCookie := THelloRetryCookie.Create(FParams.Crypto, FParams.CookieSecret);
  // a configured store upgrades the stateless STEK default to single-use handles
  FTicketStrategy := TSessionTicketStrategies.ForServer(FParams.Crypto,
    FParams.SessionTicketKeys, FParams.SessionStore);
  // each configured external PSK imported once per supported KDF hash, in server preference
  // order, so an offered identity for either hash can be matched (RFC 9258)
  FExternalPsks := TExternalPskImporter.ImportAll(FParams.Crypto, FParams.ExternalPsks,
    TlsWireVersionTls13);
end;

destructor TTls13ServerStateMachine.Destroy;
begin
  FCookie.Free;
  inherited Destroy;
end;

function TTls13ServerStateMachine.Start: TArray<THandshakeEffect>;
begin
  // a server does not initiate; it starts on the first ClientHello
  Result := nil;
end;

procedure TTls13ServerStateMachine.SetVerbatimRetryCookie(const ACookie: TBytes);
begin
  FVerbatimRetryCookie := ACookie;
end;

procedure TTls13ServerStateMachine.SetVerbatimEncryptedExtensions(
  const AFramed: TBytes);
begin
  FVerbatimEncryptedExtensions := AFramed;
end;

procedure TTls13ServerStateMachine.SetVerbatimCertificate(const AFramed: TBytes);
begin
  FVerbatimCertificate := AFramed;
end;

procedure TTls13ServerStateMachine.SetVerbatimCertificateVerify(
  const AFramed: TBytes);
begin
  FVerbatimCertificateVerify := AFramed;
end;

function TTls13ServerStateMachine.HashOf(const AData: TBytes): TBytes;
var
  LHash: IHash;
begin
  LHash := FParams.Crypto.Primitives.CreateHash(FSelectedSuite.Common.Hash);
  LHash.Update(AData, 0, System.Length(AData));
  Result := LHash.DoFinal;
end;

function TTls13ServerStateMachine.EarlyDataSkipBudget: Int32;
var
  LLimit, LContentCap, LRecords, LBudget: Int64;
begin
  // the record layer debits skipped records in WIRE bytes, so convert the authorized
  // max_early_data (larger of ticket and config) to a wire budget: the plaintext plus each
  // record's header + AEAD expansion, with one record of slack.
  LLimit := FResumedMaxEarlyData;
  if Int64(FParams.MaxEarlyData) > LLimit then
    LLimit := FParams.MaxEarlyData;
  if LLimit = 0 then
    Exit(DefaultMaxEarlyDataSkipBytes);
  // count records at the content cap the client actually fragments early data to: the
  // record_size_limit we advertised (less the inner content-type byte), else the 2^14 ceiling.
  // A smaller cap means more records, hence more per-record overhead to allow (RFC 8449 4).
  LContentCap := TRecordLimits.MaxPlaintext;
  if (FParams.RecordSizeLimit > 0) and (FParams.RecordSizeLimit - 1 < LContentCap) then
    LContentCap := FParams.RecordSizeLimit - 1;
  if LContentCap < 1 then
    LContentCap := 1;
  LRecords := (LLimit + LContentCap - 1) div LContentCap;
  LBudget := LLimit + (LRecords + 1) *
    (TRecordLimits.HeaderLength +
    (TRecordLimits.MaxCipherTextTls13 - TRecordLimits.MaxPlaintext));
  if LBudget > High(Int32) then
    LBudget := High(Int32);
  Result := Int32(LBudget);
end;

procedure TTls13ServerStateMachine.AppendNegotiatedInfoEffects(
  var AEffects: TArray<THandshakeEffect>);
begin
  if FSelectedAlpn <> '' then
    TArrayUtilities.Append<THandshakeEffect>(AEffects,
      THandshakeEffects.SelectAlpn(FSelectedAlpn));
  // pass the raw negotiated record_size_limit values (RFC 8449 TLSInnerPlaintext caps);
  // the record layer accounts for the inner content-type byte. 0 means not negotiated.
  if (FPeerRecordSizeLimit > 0) or (FParams.RecordSizeLimit > 0) then
    TArrayUtilities.Append<THandshakeEffect>(AEffects,
      THandshakeEffects.SetRecordSizeLimit(FPeerRecordSizeLimit,
      FParams.RecordSizeLimit));
end;

procedure TTls13ServerStateMachine.NegotiateFrom(
  const AClientHello: TTlsClientHello; const AContext: TExtensionContext;
  const ARawClientHello: TBytes; AAllowResumption: Boolean;
  out ASelectedGroup: UInt16);
var
  LSuiteCode, LGroupCode: UInt16;
begin
  FCodec.ConsumeBlock(AContext, TTlsExtensionContextKind.ClientHello,
    AClientHello.Extensions);
  ValidatePskBinderCount(AContext);
  // pre_shared_key MUST be the last ClientHello extension (RFC 8446 4.2.11) so the binder
  // covers a well-defined prefix; a present-but-not-last offer is illegal_parameter
  if (System.Length(AContext.OfferedPskIdentities) > 0) and
    not PreSharedKeyIsLast(AClientHello.Extensions) then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.IllegalParameter, @SPreSharedKeyNotLast);
  // a pre_shared_key offer without psk_key_exchange_modes leaves the server no way to know which
  // key agreement the PSK may use, so it MUST abort rather than fall through to a full handshake
  // (RFC 8446 4.2.9 / 9.2)
  if (System.Length(AContext.OfferedPskIdentities) > 0) and
    not AContext.WasOffered(TExtensionTypes.PskKeyExchangeModes) then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.MissingExtension, @SPskWithoutKeyExchangeModes);
  FEarlyDataOfferedByClient := AContext.EarlyDataOffered;
  FStatusRequestOffered := AContext.StatusRequestOffered;
  FClientOfferedPskDheKe := TArrayUtilities.Contains<Byte>(AContext.PskModes,
    PskDheKeMode);

  // version is confirmed via supported_versions
  FParams.Policy.SelectVersion(AContext.SupportedVersions);

  // RFC 8446 9.2: supported_groups and key_share are mutually required - present one without
  // the other and the handshake aborts with missing_extension (an empty key_share list is
  // still "present" and instead draws a HelloRetryRequest). Both absent is permitted only for
  // a pure PSK (psk_ke) offer, which needs neither.
  if AContext.WasOffered(TExtensionTypes.SupportedGroups) <>
    AContext.WasOffered(TExtensionTypes.KeyShare) then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.MissingExtension, @SGroupsKeyShareMismatch);

  // capture the client's SNI host_name up front (RFC 6066 3): it drives the certificate
  // selection on the non-PSK path below and guards resumption against a host mismatch, both of
  // which precede the EncryptedExtensions where the acknowledgement is later echoed
  FClientSentServerName := AContext.ServerName <> '';
  FRequestedServerName := AContext.ServerName;

  // try PSK auth before the certificate path: an accepted PSK (a resumption ticket or an
  // out-of-band external PSK) picks the suite and authenticates the peer, so no server
  // certificate is sent. A matching external PSK is preferred over the certificate.
  if AAllowResumption then
  begin
    TryAcceptResumption(AClientHello, AContext, ARawClientHello);
    if not FPskAccepted then
      TryAcceptExternalPsk(AClientHello, AContext, ARawClientHello);
  end;

  if not FPskAccepted then
  begin
    // no PSK matched: fall back to the server certificate for this handshake, selected from the
    // client's SNI (virtual hosting). A PSK-only server (external PSKs configured, no certificate)
    // has nothing to fall back on, so an unmatched offer is a handshake failure (RFC 8446 4.2.11)
    FResolvedCredential := TServerOfferSelection.ResolveCredential(
      FParams.CredentialResolver, AContext, AClientHello.CipherSuites, TTlsVersion.Tls13);
    // certificate-based auth requires the client to offer signature_algorithms
    // (RFC 8446 4.4.2.2 / 4.4.3); the CertificateVerify scheme is then the first of the
    // credential's key-compatible schemes the client also offered
    if System.Length(AContext.SignatureSchemes) = 0 then
      raise EFatalAlertTlsLibException.CreateRes(
        TTlsAlertDescription.MissingExtension, @SNoSignatureAlgorithms);
    if not SelectSignatureScheme(AContext.SignatureSchemes, FSelectedSignatureScheme) then
      raise EFatalAlertTlsLibException.CreateRes(
        TTlsAlertDescription.HandshakeFailure, @SNoCompatibleScheme);
    LSuiteCode := FParams.Policy.SelectCipherSuite(AClientHello.CipherSuites,
      TlsWireVersionTls13);
    if not FParams.CipherSuites.TryGet(LSuiteCode, FSelectedSuite) then
      raise EFatalAlertTlsLibException.CreateRes(
        TTlsAlertDescription.InternalError, @SUnknownSelectedSuite);
  end;

  // select an (EC)DHE group by the server's own preference order among the groups the client
  // lists in supported_groups (RFC 8446 4.2.8). The client's key_share offers do NOT change
  // which group is chosen - they only decide whether a HelloRetryRequest is needed: the caller
  // asks for a key_share via HelloRetryRequest when the chosen group has none, even if the
  // client already sent a usable key_share for a less-preferred group. A client that omits
  // X25519 but offers secp256r1 (mandatory to implement, RFC 8446 9.1) negotiates secp256r1
  // rather than failing. With no OfferedGroups the single fixed Group is used.
  if System.Length(FParams.OfferedGroups) > 0 then
  begin
    ASelectedGroup := 0;
    for LGroupCode in FParams.OfferedGroups do
      if TArrayUtilities.Contains<UInt16>(AContext.SupportedGroups, LGroupCode) then
      begin
        ASelectedGroup := LGroupCode;
        Break;
      end;
    if ASelectedGroup = 0 then
      raise EFatalAlertTlsLibException.CreateRes(
        TTlsAlertDescription.HandshakeFailure, @SGroupNotOffered);
    if not FParams.GroupRegistry.TryGet(ASelectedGroup, FSelectedGroup) then
      raise EFatalAlertTlsLibException.CreateRes(
        TTlsAlertDescription.InternalError, @SGroupNotResolvable);
  end
  else
  begin
    ASelectedGroup := FParams.Group.Code;
    if not (TArrayUtilities.Contains<UInt16>(AContext.SupportedGroups, ASelectedGroup)) then
      raise EFatalAlertTlsLibException.CreateRes(
        TTlsAlertDescription.HandshakeFailure, @SGroupNotOffered);
    FSelectedGroup := FParams.Group;
  end;

  // ALPN + record_size_limit are negotiated from the same ClientHello extensions and
  // echoed later in EncryptedExtensions
  FSelectedAlpn := TServerOfferSelection.SelectAlpn(FParams.AlpnProtocols,
    AContext.AlpnProtocols, FParams.AlpnRejectAll);
  // 0-RTT is bound to the ticket's ALPN (RFC 8446 4.2.11): a resumed handshake that negotiates
  // a different protocol than the ticket carried must reject early data (the session still
  // resumes). Only applies to an accepted resumption ticket.
  if FEarlyDataAccepted and (FSelectedAlpn <> FAcceptedSessionAlpn) then
    FEarlyDataAccepted := False;
  if AContext.RecordSizeLimit > 0 then
  begin
    if AContext.RecordSizeLimit < 64 then
      raise EFatalAlertTlsLibException.CreateRes(
        TTlsAlertDescription.IllegalParameter, @SBadRecordSizeLimit);
    FPeerRecordSizeLimit := AContext.RecordSizeLimit;
  end;
  // remember what the client can decompress so the Certificate flight can compress
  FClientCertCompressionAlgorithms := AContext.CertCompressionAlgorithms;
end;

class function TTls13ServerStateMachine.BindersVectorLength(
  const ABinders: TArray<TBytes>): Int32;
var
  LBinder: TBytes;
begin
  // binders<...>: a 2-byte list length, then each entry a 1-byte length + binder bytes
  Result := 2;
  for LBinder in ABinders do
    Inc(Result, 1 + System.Length(LBinder));
end;

class function TTls13ServerStateMachine.EarlyDataAgeFresh(AObfuscatedAgeMillis,
  ATicketAgeAdd: UInt32; AIssuedAtMillis, ANowMillis: UInt64): Boolean;
const
  MaxFreshnessSkewMillis = UInt32(60) * 1000;
var
  LClientAgeMs, LServerAgeMs, LSkewMs: UInt32;
  LElapsedMs: UInt64;
begin
  // de-obfuscate the client-reported ticket age with wrapping u32 subtraction (RFC 8446 4.2.11.1)
  LClientAgeMs := AObfuscatedAgeMillis - ATicketAgeAdd;
  // the server-measured age since issuance, saturated into u32 milliseconds
  if ANowMillis > AIssuedAtMillis then
    LElapsedMs := ANowMillis - AIssuedAtMillis
  else
    LElapsedMs := 0;
  if LElapsedMs > High(UInt32) then
    LServerAgeMs := High(UInt32)
  else
    LServerAgeMs := UInt32(LElapsedMs);
  // the absolute skew between the reported and the measured age
  if LServerAgeMs >= LClientAgeMs then
    LSkewMs := LServerAgeMs - LClientAgeMs
  else
    LSkewMs := LClientAgeMs - LServerAgeMs;
  Result := LSkewMs <= MaxFreshnessSkewMillis;
end;

class function TTls13ServerStateMachine.PreSharedKeyIsLast(
  const AExtensions: TBytes): Boolean;
var
  LVector: TExtensionVector;
begin
  // Called only when a pre_shared_key was offered, so "last is pre_shared_key" is the required
  // condition (RFC 8446 4.2.11: pre_shared_key must be the final ClientHello extension)
  LVector := TExtensionVector.Parse(AExtensions);
  Result := LVector.IsLast(TExtensionTypes.PreSharedKey);
end;

function TTls13ServerStateMachine.TryAcceptResumption(
  const AClientHello: TTlsClientHello; const AContext: TExtensionContext;
  const ARawClientHello: TBytes): Boolean;
var
  LSession: IResumableSession;
  LSuite: TTlsCipherSuite;
  LTemp: ITls13KeySchedule;
  LTruncated: TBytes;
  LNowMs: UInt64;
begin
  Result := False;
  FPskAccepted := False;
  if (FTicketStrategy = nil) or
    (System.Length(AContext.OfferedPskIdentities) = 0) or
    (System.Length(AContext.OfferedPskBinders) = 0) then
    Exit;
  // require psk_dhe_ke (forward secrecy); psk_ke alone is never accepted here
  if not (TArrayUtilities.Contains<Byte>(AContext.PskModes, PskDheKeMode)) then
    Exit;
  // open the ticket (a store handle is consumed here; a STEK ticket is decrypted)
  if not FTicketStrategy.Open(AContext.OfferedPskIdentities[0], LSession) then
    Exit;
  if not LSession.Version.Equals(TTlsVersion.Tls13) then
    Exit;
  // remember what this authenticated ticket authorized as early data, so a rejected 0-RTT skip is
  // bounded by the client's actual authorization even when the ticket is then declined (SNI/suite/
  // expiry/mTLS) or 0-RTT is refused (e.g. a retry), all of which still skip the client's records
  FResumedMaxEarlyData := LSession.MaxEarlyData;
  // a ticket issued under one SNI host must not resume as another (virtual-hosting guard): a
  // host mismatch falls through to a full handshake under the name the client now requests
  if not SameText(LSession.ServerName, FRequestedServerName) then
    Exit;
  // resumption-scope guard: a ticket minted under a different scope belongs to a configuration
  // that may not share this one's client-auth trust, so decline it to a full handshake rather than
  // reuse its stored identity
  if not TArrayUtilities.AreEqual(LSession.ResumptionScope, FParams.ResumptionScope) then
    Exit;
  // the client must still offer the PSK's suite (RFC 8446 4.2.11)
  if not (TArrayUtilities.Contains<UInt16>(AClientHello.CipherSuites,
    LSession.CipherSuite)) then
    Exit;
  if not FParams.CipherSuites.TryGet(LSession.CipherSuite, LSuite) then
    Exit;
  // freshness: reject a ticket at or past its lifetime (a 0-second lifetime is expired)
  LNowMs := FParams.Clock.NowUnixMillis;
  if LNowMs >= LSession.IssuedAtMillis + UInt64(LSession.TicketLifetime) * 1000 then
    Exit;
  // mutual-TLS resumption gate. A resumed handshake never re-runs client auth (RFC 8446 4.3.2
  // forbids a CertificateRequest in a PSK handshake), so the ticket must already carry the client
  // identity: a Required server offered a ticket with no stored identity (e.g. a foreign ticket
  // minted by a non-mTLS config sharing this STEK) falls through to a full handshake that requests
  // it. Verification (sync or async) is otherwise NOT repeated on resume - the original
  // handshake's authentication is reused (RFC 8446 2.2).
  if (FParams.ClientAuth = TClientAuthMode.Required) and
    (System.Length(LSession.PeerCertificates) = 0) then
    Exit;
  // the binder MACs the ClientHello up to (excluding) the binders vector
  FSelectedSuite := LSuite; // so HashOf uses the PSK's hash
  LTruncated := System.Copy(ARawClientHello, 0,
    System.Length(ARawClientHello) - BindersVectorLength(AContext.OfferedPskBinders));
  LTemp := TTls13KeySchedule.Create(FParams.Crypto, LSuite.Common.Hash,
    LSuite.Common.KeyLength);
  LTemp.SetPsk(LSession.ResumptionSecret);
  // a present binder that does not validate against a successfully opened ticket is fatal
  // (RFC 8446 4.2.11.2). The earlier declines above - no ticket strategy, no offered
  // identities/binders, an Open failure (unknown/undecryptable/expired/rotated-out key),
  // a version or offered-suite mismatch - legitimately fall through to a full handshake;
  // only a decrypted ticket carrying a bad binder value aborts.
  if not LTemp.VerifyBinder(TPskBinderKind.Resumption, HashOf(LTruncated),
    AContext.OfferedPskBinders[0]) then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.DecryptError, @SBadPskBinder);
  FPskAccepted := True;
  FPskBinderKind := TPskBinderKind.Resumption;
  FSelectedPskIdentity := 0;
  FAcceptedPskIdentity := AContext.OfferedPskIdentities[0];
  FPskSecret := LSession.ResumptionSecret;
  FResumedPeerCertificates := LSession.PeerCertificates;
  // 0-RTT is bound to the ticket's ALPN: it is only accepted below when the resumed handshake
  // negotiates the same protocol (checked once ALPN is selected)
  FAcceptedSessionAlpn := LSession.Alpn;
  AContext.PskSelected := True;
  AContext.SelectedPskIdentity := 0;
  // accept 0-RTT only when configured, the ticket authorized it, the reported ticket age is
  // fresh (bounded clock skew, RFC 8446 8.2), and the binder is not a replay - the binder
  // uniquely identifies this early-data attempt (RFC 8446 8)
  FEarlyDataAccepted := FEarlyDataOfferedByClient and (FParams.MaxEarlyData > 0) and
    (LSession.MaxEarlyData > 0) and
    EarlyDataAgeFresh(AContext.OfferedPskAges[0], LSession.TicketAgeAdd,
    LSession.IssuedAtMillis, LNowMs) and (FParams.AntiReplay <> nil) and
    FParams.AntiReplay.CheckAndRecord(AContext.OfferedPskBinders[0], LNowMs,
    LNowMs + UInt64(LSession.TicketLifetime) * 1000);
  Result := True;
end;

class function TTls13ServerStateMachine.IndexOfOfferedIdentity(
  const AOffered: TArray<TBytes>; const AIdentity: TBytes): Int32;
var
  LI: Int32;
begin
  Result := -1;
  for LI := 0 to High(AOffered) do
    if TArrayUtilities.AreEqual(AOffered[LI], AIdentity) then
      Exit(LI);
end;

function TTls13ServerStateMachine.SelectSuiteWithHash(
  const AClientSuites: TArray<UInt16>; AHash: THashAlgorithm;
  out ASuite: TTlsCipherSuite): Boolean;
var
  LCode: UInt16;
  LSuite: TTlsCipherSuite;
begin
  Result := False;
  // server preference (the shared hardware-AES-aware order), constrained to a 1.3 suite of
  // the PSK's hash the client also offered
  for LCode in TNegotiationPolicy.SuitePreferenceOrder(FParams.Crypto,
    FParams.CipherSuites, TSuiteProtocol.Tls13) do
    if FParams.CipherSuites.TryGet(LCode, LSuite) and
      (LSuite.Protocol = TSuiteProtocol.Tls13) and (LSuite.Common.Hash = AHash) and
      (TArrayUtilities.Contains<UInt16>(AClientSuites, LSuite.Common.Code)) then
    begin
      ASuite := LSuite;
      Exit(True);
    end;
end;

function TTls13ServerStateMachine.TryAcceptExternalPsk(
  const AClientHello: TTlsClientHello; const AContext: TExtensionContext;
  const ARawClientHello: TBytes): Boolean;
var
  LOffer: IPreSharedKey;
  LSuite: TTlsCipherSuite;
  LTemp: ITls13KeySchedule;
  LTruncated: TBytes;
  LIndex: Int32;
begin
  Result := False;
  FPskAccepted := False;
  if (System.Length(FExternalPsks) = 0) or
    (System.Length(AContext.OfferedPskIdentities) = 0) or
    (System.Length(AContext.OfferedPskBinders) = 0) then
    Exit;
  // require psk_dhe_ke (forward secrecy); psk_ke alone is never accepted here
  if not (TArrayUtilities.Contains<Byte>(AContext.PskModes, PskDheKeMode)) then
    Exit;
  // walk the server's imported PSKs in preference order; take the first whose identity the
  // client offered and for which a same-hash cipher suite is jointly available
  for LOffer in FExternalPsks do
  begin
    LIndex := IndexOfOfferedIdentity(AContext.OfferedPskIdentities, LOffer.Identity);
    if LIndex < 0 then
      Continue;
    if not SelectSuiteWithHash(AClientHello.CipherSuites, LOffer.Hash, LSuite) then
      Continue;
    FSelectedSuite := LSuite; // so HashOf uses the PSK's hash
    LTruncated := System.Copy(ARawClientHello, 0,
      System.Length(ARawClientHello) - BindersVectorLength(AContext.OfferedPskBinders));
    LTemp := TTls13KeySchedule.Create(FParams.Crypto, LOffer.Hash,
      LSuite.Common.KeyLength);
    LTemp.SetPsk(LOffer.Key);
    // a matched identity whose binder does not validate is fatal (RFC 8446 4.2.11.2)
    if not LTemp.VerifyBinder(LOffer.BinderKind, HashOf(LTruncated),
      AContext.OfferedPskBinders[LIndex]) then
      raise EFatalAlertTlsLibException.CreateRes(
        TTlsAlertDescription.DecryptError, @SBadPskBinder);
    FPskAccepted := True;
    FPskBinderKind := LOffer.BinderKind;
    FSelectedPskIdentity := UInt16(LIndex);
    FAcceptedPskIdentity := LOffer.Identity;
    FPskSecret := LOffer.Key;
    AContext.PskSelected := True;
    AContext.SelectedPskIdentity := UInt16(LIndex);
    Exit(True);
  end;
end;

procedure TTls13ServerStateMachine.ValidatePskBinderCount(
  const AContext: TExtensionContext);
begin
  // only meaningful when a pre_shared_key is actually offered; an empty binders vector with
  // a present PSK is caught as decode_error while parsing, so guard on both being non-empty
  if (System.Length(AContext.OfferedPskIdentities) > 0) and
    (System.Length(AContext.OfferedPskBinders) > 0) and
    (System.Length(AContext.OfferedPskIdentities) <>
    System.Length(AContext.OfferedPskBinders)) then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.IllegalParameter, @SPskBinderCountMismatch);
end;

procedure TTls13ServerStateMachine.RevalidateRetryBinder(
  const ARawClientHello: TBytes; const AContext: TExtensionContext);
var
  LTruncated: TBytes;
  LTemp: ITls13KeySchedule;
  LIndex: Int32;
begin
  // the retry must re-carry the PSK the server committed to on the first flight. A client
  // may prune its PSK list once the cipher (hence hash) is fixed, so re-locate the accepted
  // identity by value: an omitted pre_shared_key is a missing extension, the accepted
  // identity absent from a present offer is PSK_IDENTITY_NOT_FOUND, and a present identity
  // whose binder does not validate is a decrypt error (RFC 8446 4.1.4 / 4.2.11.2). The
  // client also recomputes the binder over the retry transcript, so re-verify it here.
  if System.Length(AContext.OfferedPskIdentities) = 0 then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.MissingExtension, @SPskMissingOnRetry);
  LIndex := IndexOfOfferedIdentity(AContext.OfferedPskIdentities, FAcceptedPskIdentity);
  if (LIndex < 0) or (LIndex >= System.Length(AContext.OfferedPskBinders)) then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.IllegalParameter, @SPskIdentityNotFound);
  LTruncated := System.Copy(ARawClientHello, 0,
    System.Length(ARawClientHello) - BindersVectorLength(AContext.OfferedPskBinders));
  LTemp := TTls13KeySchedule.Create(FParams.Crypto, FSelectedSuite.Common.Hash,
    FSelectedSuite.Common.KeyLength);
  LTemp.SetPsk(FPskSecret);
  // the binder hash runs over the seeded transcript (message_hash(CH1), HRR) plus this
  // ClientHello up to the binders
  if not LTemp.VerifyBinder(FPskBinderKind,
    FTranscript.HashPrefixExcludingBinders(LTruncated),
    AContext.OfferedPskBinders[LIndex]) then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.DecryptError, @SBadPskBinder);
  // the client's pruned list may put the identity at a new index; echo the new one
  FSelectedPskIdentity := UInt16(LIndex);
end;

function TTls13ServerStateMachine.SelectSignatureScheme(
  const AClientSchemes: TArray<UInt16>; out AScheme: TSignatureScheme): Boolean;
var
  LScheme: TSignatureScheme;
begin
  Result := False;
  // the key reports only schemes it can sign; take the first (owner preference) the
  // client also offered. The legacy rsa_pkcs1_* schemes are certificate-only in TLS 1.3
  // and MUST NOT sign a CertificateVerify (RFC 8446 4.2.3), so skip them here.
  for LScheme in FResolvedCredential.PrivateKey.CapableSchemes do
    if LScheme.IsValidForHandshake(TTlsVersion.Tls13) and
      (TArrayUtilities.Contains<UInt16>(AClientSchemes, LScheme.ToCode)) then
    begin
      AScheme := LScheme;
      Exit(True);
    end;
end;

class function TTls13ServerStateMachine.KeyShareFor(
  const AContext: TExtensionContext; AGroup: UInt16): TBytes;
var
  LEntry: TTlsKeyShareEntry;
begin
  Result := nil;
  for LEntry in AContext.ClientKeyShares do
    if LEntry.Group = AGroup then
      Exit(LEntry.KeyExchange);
end;

function TTls13ServerStateMachine.ProcessClientHello(
  const AMessage: TTlsHandshakeMessage): TArray<THandshakeEffect>;
var
  LClientHello: TTlsClientHello;
  LContext: TExtensionContext;
  LSelectedGroup: UInt16;
  LClientShare, LEchRaw: TBytes;
begin
  LEchRaw := AMessage.Raw;
  LClientHello := THandshakeMessages.DecodeClientHello(
    System.Copy(AMessage.Raw, 4, System.Length(AMessage.Raw) - 4));
  // Encrypted Client Hello (RFC 9849 sec. 7.1). An inner-type ech is a decrypted
  // ClientHelloInner: it is legitimate only at a split-mode backend (no ECH keys), which
  // confirms it in the ServerHello. A client-facing or shared-mode server (it holds ECH keys)
  // must never receive it directly and aborts illegal_parameter. With ECH keys and an outer,
  // trial-decrypt - accept drives negotiation off the reconstructed inner, reject continues to
  // the public_name and advertises retry_configs in EncryptedExtensions.
  if DetectBackendEch(LClientHello) then
  begin
    if FParams.EchKeyStore <> nil then
      raise EFatalAlertTlsLibException.CreateRes(
        TTlsAlertDescription.IllegalParameter, @SEchInnerAtClientFacing);
    FEchStatus := TEchStatus.Backend;
    FEchInnerRandom := LClientHello.Random;
  end
  else if FParams.EchKeyStore <> nil then
  begin
    FEch := TEchServerHandshake.Create(FParams.Crypto, FParams.EchKeyStore,
      FParams.EchTrialDecrypt);
    FEchStatus := FEch.ProcessOuter(AMessage.Raw);
    if FEchStatus = TEchStatus.Accepted then
    begin
      LEchRaw := FEch.InnerFramed;
      FEchInnerRandom := FEch.InnerRandom;
      LClientHello := THandshakeMessages.DecodeClientHello(
        System.Copy(LEchRaw, 4, System.Length(LEchRaw) - 4));
    end
    else if FEchStatus = TEchStatus.Rejected then
      FEchRetryConfigs := FParams.EchKeyStore.RetryConfigs;
  end;
  LContext := TExtensionContext.Create;
  try
    NegotiateFrom(LClientHello, LContext, LEchRaw, True, LSelectedGroup);
    LClientShare := KeyShareFor(LContext, LSelectedGroup);
    if System.Length(LClientShare) = 0 then
      // the client listed our group but sent no share for it: ask for one
      Result := EmitHelloRetryRequest(LClientHello, LEchRaw, LSelectedGroup)
    else
    begin
      // transcript: ClientHello, then (activated) ServerHello inside EmitServerFlight
      FTranscript.Update(LEchRaw);
      FTranscript.Activate(FParams.Crypto.Primitives.CreateHash(FSelectedSuite.Common.Hash));
      // the client_early_traffic secret is over the ClientHello-only transcript
      if FEarlyDataAccepted then
        FEarlyTranscriptHash := FTranscript.CurrentHash;
      Result := EmitServerFlight(LClientHello, LSelectedGroup, LClientShare, True);
    end;
  finally
    LContext.Free;
  end;
end;

function TTls13ServerStateMachine.EmitHelloRetryRequest(
  const AClientHello: TTlsClientHello; const ARaw: TBytes;
  ASelectedGroup: UInt16): TArray<THandshakeEffect>;
var
  LCookie, LHrr, LCh1Hash: TBytes;
begin
  // ARaw is the inner ClientHello on ECH accept, the outer otherwise, so its hash is the one
  // the cookie binds and the one the HRR ech confirmation is computed over
  LCh1Hash := HashOf(ARaw);
  if System.Length(FVerbatimRetryCookie) > 0 then
    LCookie := FVerbatimRetryCookie
  else
  begin
    if FCookie = nil then
      raise EFatalAlertTlsLibException.CreateRes(
        TTlsAlertDescription.InternalError, @SNoCookieAuthority);
    // the cookie binds Hash(ClientHello1) and the requested group under the server
    // secret, so the second ClientHello can be validated without retained state
    LCookie := FCookie.Mint(LCh1Hash, ASelectedGroup);
  end;
  if FEchStatus in [TEchStatus.Accepted, TEchStatus.Backend] then
    LHrr := BuildHelloRetryRequest(AClientHello.LegacySessionId, ASelectedGroup,
      LCookie, LCh1Hash)
  else
    LHrr := BuildHelloRetryRequest(AClientHello.LegacySessionId, ASelectedGroup,
      LCookie, nil);

  // 0-RTT does not survive a retry: the client must not resend early_data, and the server
  // must not accept or skip it on the second flight (RFC 8446 4.2.10)
  FHelloRetrySent := True;
  FEarlyDataAccepted := False;
  FPhase := TPhase.WaitSecondClientHello;
  // no per-connection state is retained: the transcript is rebuilt from the cookie.
  // the version leads the flight so the record layer can classify the client's post-hello
  // change_cipher_spec: a HelloRetryRequest installs no keys, so nothing else fixes it here
  Result := TArray<THandshakeEffect>.Create(
    THandshakeEffects.NegotiatedVersion(TTlsVersion.Tls13),
    THandshakeEffects.SendHandshake(LHrr),
    THandshakeEffects.SendChangeCipherSpec);
  // 0-RTT records the client already sent after ClientHello1 arrive before ClientHello2; the
  // server rejects 0-RTT on any retry (RFC 8446 4.2.10) and skips those early-data records
  // (bounded) while waiting for the second ClientHello
  if FEarlyDataOfferedByClient then
    TArrayUtilities.Append<THandshakeEffect>(Result,
      THandshakeEffects.SkipEarlyData(EarlyDataSkipBudget));
end;

function TTls13ServerStateMachine.BuildHelloRetryRequest(
  const ALegacySessionId: TBytes; ASelectedGroup: UInt16;
  const ACookie: TBytes; const AEchInnerCh1Hash: TBytes): TBytes;
var
  LContext: TExtensionContext;
  LHello: TTlsServerHello;
  LZeroConf: TBytes;
begin
  LContext := TExtensionContext.Create;
  try
    LContext.HelloRetryGroup := ASelectedGroup;
    LContext.Cookie := ACookie;
    LContext.SelectedVersion := TlsWireVersionTls13;
    // under ECH accept the HRR carries an encrypted_client_hello with an 8-byte accept
    // confirmation; the registry places it LAST (nothing in a HRR follows it), so its payload is
    // the final 8 bytes (RFC 9849 sec. 7.2.1) - stamped in below over the zero placeholder
    if System.Length(AEchInnerCh1Hash) > 0 then
    begin
      LZeroConf := nil;
      SetLength(LZeroConf, 8);
      LContext.EchExtensionData := TEchExtension.EncodeHrrConfirmation(LZeroConf);
    end;
    LHello.Random := THelloRetryRequest.SentinelRandom;
    LHello.LegacySessionIdEcho := ALegacySessionId;
    LHello.CipherSuite := FSelectedSuite.Common.Code;
    LHello.Extensions := FCodec.ProduceBlock(LContext,
      TTlsExtensionContextKind.HelloRetryRequest);
  finally
    LContext.Free;
  end;
  Result := THandshakeFraming.Frame(TTlsHandshakeType.ServerHello,
    THandshakeMessages.EncodeServerHello(LHello));
  if System.Length(AEchInnerCh1Hash) > 0 then
    StampHrrEchConfirmation(Result, AEchInnerCh1Hash);
end;

procedure TTls13ServerStateMachine.StampHrrEchConfirmation(
  var AHrrBytes: TBytes; const AInnerCh1Hash: TBytes);
var
  LClone: ITranscriptHash;
  LConf: TBytes;
begin
  // the ech extension was spliced last, so its 8-byte payload is the tail of AHrrBytes; it is
  // still zero here, so hashing AHrrBytes hashes the HRR with the payload zeroed
  LClone := TTranscriptHash.Create;
  LClone.SeedWithMessageHash(
    FParams.Crypto.Primitives.CreateHash(FSelectedSuite.Common.Hash), AInnerCh1Hash);
  LClone.Update(AHrrBytes);
  LConf := TTls13KeySchedule.EchHrrAcceptConfirmation(
    FParams.Crypto.Primitives.CreateHkdf(FSelectedSuite.Common.Hash),
    FEchInnerRandom, LClone.CurrentHash);
  Move(LConf[0], AHrrBytes[System.Length(AHrrBytes) - 8], 8);
end;

function TTls13ServerStateMachine.ProcessSecondClientHello(
  const AMessage: TTlsHandshakeMessage): TArray<THandshakeEffect>;
var
  LClientHello: TTlsClientHello;
  LContext: TExtensionContext;
  LSelectedGroup, LCookieGroup, LPinnedSuite: UInt16;
  LCh1Hash, LClientShare, LHrr, LCh2Raw, LEchHrrHash: TBytes;
  LEchAccepted: Boolean;
begin
  // when ECH was accepted on CH1, the retry outer reuses the CH1 HPKE context at seq=1
  // (RFC 9849 sec. 6.1.5); the reconstructed inner CH2 is the logical ClientHello2
  // the accept invariant must hold here (the flight that releases FEch runs later); a broken one
  // is an internal fault, not a silent fall-through to the outer ClientHello
  if (FEchStatus = TEchStatus.Accepted) and (FEch = nil) then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.InternalError, @SEchAcceptedWithoutHandshake);
  LEchAccepted := FEchStatus = TEchStatus.Accepted;
  if LEchAccepted then
  begin
    FEch.ProcessRetryOuter(AMessage.Raw);
    LCh2Raw := FEch.InnerFramed;
    // ClientHelloInner.random MUST NOT change across the retry (RFC 8446 4.1.2)
    if not TArrayUtilities.AreEqual(FEch.InnerRandom, FEchInnerRandom) then
      raise EFatalAlertTlsLibException.CreateRes(
        TTlsAlertDescription.IllegalParameter, @SEchInnerRandomChanged);
  end
  else
    LCh2Raw := AMessage.Raw;
  LClientHello := THandshakeMessages.DecodeClientHello(
    System.Copy(LCh2Raw, 4, System.Length(LCh2Raw) - 4));
  LContext := TExtensionContext.Create;
  try
    // the HelloRetryRequest named the suite selected from CH1, and the retry transcript is rebuilt
    // under its hash (RFC 8446 4.1.4). Check the retry still offers it before re-negotiating, so a
    // dropped suite aborts illegal_parameter rather than handshake_failure from suite selection.
    LPinnedSuite := FSelectedSuite.Common.Code;
    if not (TArrayUtilities.Contains<UInt16>(LClientHello.CipherSuites, LPinnedSuite)) then
      raise EFatalAlertTlsLibException.CreateRes(
        TTlsAlertDescription.IllegalParameter, @SRetrySuiteChanged);
    // resumption is not attempted on the retry ClientHello (kept to the first flight)
    NegotiateFrom(LClientHello, LContext, LCh2Raw, False, LSelectedGroup);
    // the server must still negotiate that same suite (guards a reordered CH2 under client-preference)
    if FSelectedSuite.Common.Code <> LPinnedSuite then
      raise EFatalAlertTlsLibException.CreateRes(
        TTlsAlertDescription.IllegalParameter, @SRetrySuiteChanged);

    // the retry must echo a cookie that verifies under the server secret (RFC 8446
    // 4.1.4); the cookie carries Hash(ClientHello1) and the requested group
    if System.Length(LContext.Cookie) = 0 then
      raise EFatalAlertTlsLibException.CreateRes(
        TTlsAlertDescription.MissingExtension, @SMissingCookie);
    if (FCookie = nil) or not FCookie.TryOpen(LContext.Cookie, LCh1Hash, LCookieGroup) then
      raise EFatalAlertTlsLibException.CreateRes(
        TTlsAlertDescription.DecryptError, @SBadCookie);
    if LCookieGroup <> LSelectedGroup then
      raise EFatalAlertTlsLibException.CreateRes(
        TTlsAlertDescription.IllegalParameter, @SCookieGroupMismatch);

    // the second ClientHello must now carry the requested share; a still-missing
    // share is a failure, never a second HelloRetryRequest (RFC 8446 4.1.4)
    LClientShare := KeyShareFor(LContext, LSelectedGroup);
    if System.Length(LClientShare) = 0 then
      raise EFatalAlertTlsLibException.CreateRes(
        TTlsAlertDescription.IllegalParameter, @SNoRetryKeyShare);

    // rebuild the transcript statelessly: message_hash(Hash(CH1)), then the reconstructed
    // HelloRetryRequest (byte-identical to the one sent, including its ech confirmation on
    // accept, from the echoed cookie's Hash(CH1)), then this ClientHello (the inner on accept)
    FTranscript := TTranscriptHash.Create;
    FTranscript.SeedWithMessageHash(FParams.Crypto.Primitives.CreateHash(FSelectedSuite.Common.Hash),
      LCh1Hash);
    // the sent HelloRetryRequest carried the ech confirmation on ECH accept and in the backend
    // role, so its transcript reconstruction must too (else the ServerHello confirmation diverges)
    if FEchStatus in [TEchStatus.Accepted, TEchStatus.Backend] then
      LEchHrrHash := LCh1Hash
    else
      LEchHrrHash := nil;
    LHrr := BuildHelloRetryRequest(LClientHello.LegacySessionId, LSelectedGroup,
      LContext.Cookie, LEchHrrHash);
    FTranscript.Update(LHrr);
    // a resuming client recomputes its PSK binder over the retry transcript, so re-validate
    // it here (over message_hash(CH1), HRR, this ClientHello up to the binders) before
    // folding the full retry hello in - the first flight's binder does not vouch for it
    if FPskAccepted then
      RevalidateRetryBinder(LCh2Raw, LContext);
    FTranscript.Update(LCh2Raw); // the second ClientHello (inner on ECH accept)
    Result := EmitServerFlight(LClientHello, LSelectedGroup, LClientShare, False);
  finally
    LContext.Free;
  end;
end;

class function TTls13ServerStateMachine.DetectBackendEch(
  const AClientHello: TTlsClientHello): Boolean;
var
  LVector: TExtensionVector;
  LEntry: TExtensionEntry;
  LType: TEchClientHelloType;
  LOuter: TEchOuterClientHello;
begin
  Result := False;
  // an absent extensions field is a legacy (<=TLS 1.2) ClientHello shape; leave it to version
  // negotiation to reject with protocol_version rather than fail here as a decode_error
  if System.Length(AClientHello.Extensions) = 0 then
    Exit;
  LVector := TExtensionVector.Parse(AClientHello.Extensions);
  if LVector.TryFind(TExtensionTypes.EncryptedClientHello, LEntry) then
  begin
    // Decode validates the wire shape: an out-of-range type is illegal_parameter, a malformed
    // body a decode_error - the boundary maps either to the alert
    TEchExtension.Decode(LEntry.Data, LType, LOuter);
    Result := LType = TEchClientHelloType.Inner;
  end;
end;

procedure TTls13ServerStateMachine.StampEchAcceptConfirmation(
  var AServerHelloBytes: TBytes);
var
  LZeroed, LConf: TBytes;
  LClone: ITranscriptHash;
  LI: Int32;
begin
  // transcript_ech_conf is over (inner ClientHello .. this ServerHello) with the last 8
  // ServerHello.random bytes zeroed; the confirmation then overwrites those same bytes.
  // The random is at offset 6 of the framed message, so bytes 24..32 are 30..38.
  LZeroed := System.Copy(AServerHelloBytes);
  for LI := 0 to 7 do
    LZeroed[30 + LI] := 0;
  LClone := FTranscript.Clone;
  LClone.Update(LZeroed);
  LConf := TTls13KeySchedule.EchAcceptConfirmation(
    FParams.Crypto.Primitives.CreateHkdf(FSelectedSuite.Common.Hash),
    FEchInnerRandom, LClone.CurrentHash);
  Move(LConf[0], AServerHelloBytes[30], 8);
end;

function TTls13ServerStateMachine.EmitServerFlight(
  const AClientHello: TTlsClientHello; ASelectedGroup: UInt16;
  const AClientShare: TBytes; ASendChangeCipherSpec: Boolean)
  : TArray<THandshakeEffect>;
var
  LServerShare: TBytes;
  LShared: ISecretBuffer;
  LServerHelloBytes: TBytes;
  LFlight: TServerFlight;
begin
  // precondition: the transcript is already seeded through this ClientHello and active
  FSelectedGroup.Encapsulate(AClientShare, LServerShare, LShared);
  LServerHelloBytes := BuildServerHello(AClientHello, ASelectedGroup, LServerShare);
  // on ECH accept (or the backend role), overwrite ServerHello.random[24..32] with the accept
  // confirmation before folding it into the transcript (RFC 9849 sec. 7.2)
  if FEchStatus in [TEchStatus.Accepted, TEchStatus.Backend] then
    StampEchAcceptConfirmation(LServerHelloBytes);
  FTranscript.Update(LServerHelloBytes);
  // the decrypted inner ClientHello and the HPKE opener the ECH handshake held are no longer
  // needed once the server flight is out (the inner is in the transcript and the accept/reject
  // status is recorded); release it rather than keep the real SNI and key state alive for the
  // whole connection. A HelloRetryRequest, if any, consumed the opener before this flight.
  FEch := nil;

  FSchedule := TTls13KeySchedule.Create(FParams.Crypto, FSelectedSuite.Common.Hash,
    FSelectedSuite.Common.KeyLength);
  // psk_dhe_ke: the resumption PSK seeds the early secret, the fresh ECDHE the handshake
  if FPskAccepted then
  begin
    FSchedule.SetPsk(FPskSecret);
    // the PSK is now folded into the early secret; drop this reference so it does not outlive
    // the handshake (the schedule releases its own copy after the extract)
    FPskSecret := nil;
  end;
  FSchedule.SetSharedSecret(LShared);
  FSchedule.DeriveEpochSecrets(TTlsEpoch.Handshake, FTranscript.CurrentHash);

  // read the client's 0-RTT under the early keys before the handshake read keys
  if FEarlyDataAccepted then
    FSchedule.DeriveEpochSecrets(TTlsEpoch.EarlyData, FEarlyTranscriptHash);

  LFlight := BuildEncryptedFlight;

  // phase: 0-RTT waits for EndOfEarlyData; client auth waits for the client Certificate;
  // otherwise the client Finished comes next. On resumption the PSK already carries the
  // client's identity, so client auth is not re-done (the CertificateRequest is likewise
  // suppressed above) and the client's Finished follows directly.
  if FEarlyDataAccepted then
    FPhase := TPhase.WaitEndOfEarlyData
  else if (not FPskAccepted) and (FParams.ClientAuth <> TClientAuthMode.None) then
    FPhase := TPhase.WaitClientCertificate
  else
    FPhase := TPhase.WaitClientFinished;
  // the version leads the flight so the record layer classifies a coalesced client
  // change_cipher_spec (dropped) before it is pulled
  Result := TArray<THandshakeEffect>.Create(
    THandshakeEffects.NegotiatedVersion(TTlsVersion.Tls13),
    THandshakeEffects.SendHandshake(LServerHelloBytes));
  // the legacy change_cipher_spec is sent once, after the server's first flight
  if ASendChangeCipherSpec then
    TArrayUtilities.Append<THandshakeEffect>(Result,
      THandshakeEffects.SendChangeCipherSpec);
  TArrayUtilities.Append<THandshakeEffect>(Result,
    THandshakeEffects.InstallKeys(FSchedule.TrafficKeys(TTlsEpoch.Handshake,
    TTlsDirection.ServerWrite), TRecordSide.WriteSide, FSelectedSuite.Common.Aead, TTlsVersion.Tls13));
  // read side: early keys for accepted 0-RTT (handshake read installs after
  // EndOfEarlyData), else the handshake read keys now
  if FEarlyDataAccepted then
  begin
    TArrayUtilities.Append<THandshakeEffect>(Result,
      THandshakeEffects.InstallKeys(FSchedule.TrafficKeys(TTlsEpoch.EarlyData,
      TTlsDirection.ClientWrite), TRecordSide.ReadSide, FSelectedSuite.Common.Aead,
      TTlsVersion.Tls13));
    // the read side is on the early-data epoch: application_data (the client's 0-RTT data)
    // legitimately precedes the handshake completion until EndOfEarlyData (RFC 8446 4.2.10)
    TArrayUtilities.Append<THandshakeEffect>(Result,
      THandshakeEffects.SetEarlyReadEpoch(True));
  end
  else
  begin
    TArrayUtilities.Append<THandshakeEffect>(Result,
      THandshakeEffects.InstallKeys(FSchedule.TrafficKeys(TTlsEpoch.Handshake,
      TTlsDirection.ClientWrite), TRecordSide.ReadSide, FSelectedSuite.Common.Aead, TTlsVersion.Tls13));
    // the client sent 0-RTT the server is not accepting: skip those undecryptable records.
    // Not after an HRR though - a client must not resend early data past a retry, so any
    // early-data records on the second flight are illegal and must fail (bad record MAC).
    if FEarlyDataOfferedByClient and (not FHelloRetrySent) then
      TArrayUtilities.Append<THandshakeEffect>(Result,
        THandshakeEffects.SkipEarlyData(EarlyDataSkipBudget));
  end;
  AppendNegotiatedInfoEffects(Result);
  // a resumed handshake sends no Certificate, so surface the client chain the ticket carried
  // (mutual-TLS resumption); empty on a non-mTLS session
  if FPskAccepted and (System.Length(FResumedPeerCertificates) > 0) then
    TArrayUtilities.Append<THandshakeEffect>(Result,
      THandshakeEffects.PeerCertificateChain(FResumedPeerCertificates));
  TArrayUtilities.Append<THandshakeEffect>(Result,
    THandshakeEffects.SendHandshake(LFlight.EncryptedExtensions));
  if System.Length(LFlight.CertificateRequest) > 0 then
    TArrayUtilities.Append<THandshakeEffect>(Result,
      THandshakeEffects.SendHandshake(LFlight.CertificateRequest));
  // Certificate + CertificateVerify are absent on a resumption flight
  if System.Length(LFlight.Certificate) > 0 then
    TArrayUtilities.Append<THandshakeEffect>(Result,
      THandshakeEffects.SendHandshake(LFlight.Certificate));
  if System.Length(LFlight.CertificateVerify) > 0 then
    TArrayUtilities.Append<THandshakeEffect>(Result,
      THandshakeEffects.SendHandshake(LFlight.CertificateVerify));
  TArrayUtilities.Append<THandshakeEffect>(Result,
    THandshakeEffects.SendHandshake(LFlight.Finished));
  // after its own Finished the server writes with the application keys
  TArrayUtilities.Append<THandshakeEffect>(Result,
    THandshakeEffects.InstallKeys(FSchedule.TrafficKeys(TTlsEpoch.Application,
    TTlsDirection.ServerWrite), TRecordSide.WriteSide, FSelectedSuite.Common.Aead, TTlsVersion.Tls13));
end;

function TTls13ServerStateMachine.BuildServerHello(
  const AClientHello: TTlsClientHello; ASelectedGroup: UInt16;
  const AServerShare: TBytes): TBytes;
var
  LServerContext: TExtensionContext;
  LServerHello: TTlsServerHello;
begin
  LServerContext := TExtensionContext.Create;
  try
    LServerContext.SelectedKeyShare.Group := ASelectedGroup;
    LServerContext.SelectedKeyShare.KeyExchange := AServerShare;
    LServerContext.SelectedVersion := TlsWireVersionTls13;
    // on resumption the ServerHello echoes pre_shared_key with the selected identity
    LServerContext.PskSelected := FPskAccepted;
    LServerContext.SelectedPskIdentity := FSelectedPskIdentity;
    LServerHello.Random := FParams.ServerRandom;
    LServerHello.LegacySessionIdEcho := AClientHello.LegacySessionId;
    LServerHello.CipherSuite := FSelectedSuite.Common.Code;
    LServerHello.Extensions := FCodec.ProduceBlock(LServerContext,
      TTlsExtensionContextKind.ServerHello);
    Result := THandshakeFraming.Frame(TTlsHandshakeType.ServerHello,
      THandshakeMessages.EncodeServerHello(LServerHello));
  finally
    LServerContext.Free;
  end;
end;

function TTls13ServerStateMachine.BuildEncryptedFlight: TServerFlight;
var
  LVerifyData: TBytes;
begin
  Result := Default(TServerFlight);
  // the encrypted flight goes into the transcript; the server Finished is over it.
  // EncryptedExtensions and Certificate first, then the CertificateVerify is signed
  // over the transcript through the Certificate (RFC 8446 4.4.3)
  Result.EncryptedExtensions := BuildEncryptedExtensions;
  FTranscript.Update(Result.EncryptedExtensions);
  // on resumption the PSK authenticates the server: no CertificateRequest, Certificate
  // or CertificateVerify - the flight is EncryptedExtensions then Finished
  if not FPskAccepted then
  begin
    // a CertificateRequest (when client auth is on) precedes the server Certificate and
    // is folded into the transcript the CertificateVerify signs over
    if FParams.ClientAuth <> TClientAuthMode.None then
    begin
      Result.CertificateRequest := BuildCertificateRequest;
      FTranscript.Update(Result.CertificateRequest);
    end;
    if System.Length(FVerbatimCertificate) > 0 then
      Result.Certificate := FVerbatimCertificate
    else
      Result.Certificate := BuildCertificate;
    FTranscript.Update(Result.Certificate);
    if System.Length(FVerbatimCertificateVerify) > 0 then
      Result.CertificateVerify := FVerbatimCertificateVerify
    else
      Result.CertificateVerify := SignCertificateVerify(FTranscript.CurrentHash);
    FTranscript.Update(Result.CertificateVerify);
  end;

  LVerifyData := FSchedule.ComputeVerifyData(TTlsDirection.ServerWrite,
    FTranscript.CurrentHash);
  Result.Finished := THandshakeFraming.Frame(TTlsHandshakeType.Finished,
    THandshakeMessages.EncodeFinished(LVerifyData));
  FTranscript.Update(Result.Finished);
  // application secrets are over the transcript INCLUDING the server Finished
  FSchedule.DeriveEpochSecrets(TTlsEpoch.Application, FTranscript.CurrentHash);
end;

function TTls13ServerStateMachine.BuildEncryptedExtensions: TBytes;
var
  LContext: TExtensionContext;
  LBlock: TBytes;
begin
  if System.Length(FVerbatimEncryptedExtensions) > 0 then
    Exit(System.Copy(FVerbatimEncryptedExtensions));
  // serialize the negotiated EncryptedExtensions (ALPN selection, record_size_limit)
  LContext := TExtensionContext.Create;
  try
    LContext.SelectedAlpn := FSelectedAlpn;
    LContext.RecordSizeLimit := FParams.RecordSizeLimit;
    // no acknowledgement in a resumed/PSK session (RFC 6066 3): the server SHALL NOT include
    // server_name in the EncryptedExtensions of a resumed session
    LContext.ServerNameAck := FClientSentServerName and
      FParams.ServerNameAck and not FPskAccepted;
    // signal 0-RTT acceptance to the client (an empty early_data in EncryptedExtensions)
    LContext.EarlyDataAccepted := FEarlyDataAccepted;
    // on ECH reject the client-facing server advertises retry_configs so the client can refresh
    // its keys (RFC 9849 sec. 7.1); the registry places the ech extension (payload is an
    // ECHConfigList) last in the EncryptedExtensions vector
    if (FEchStatus = TEchStatus.Rejected) and (System.Length(FEchRetryConfigs) > 0) then
      LContext.EchExtensionData := TEchExtension.EncodeRetryConfigs(FEchRetryConfigs);
    LBlock := FCodec.ProduceBlock(LContext,
      TTlsExtensionContextKind.EncryptedExtensions);
  finally
    LContext.Free;
  end;
  Result := THandshakeFraming.Frame(TTlsHandshakeType.EncryptedExtensions,
    THandshakeMessages.EncodeEncryptedExtensions(LBlock));
end;

function TTls13ServerStateMachine.BuildCertificate: TBytes;
var
  LCert: TTlsCertificate;
  LI: Int32;
  LBody, LCompressed, LStaple: TBytes;
  LCompressor: ICertificateCompressor;
  LMsg: TTlsCompressedCertificate;
begin
  LCert.RequestContext := nil; // empty in the server's first flight
  SetLength(LCert.Entries, System.Length(FResolvedCredential.CertificateChain));
  for LI := 0 to High(FResolvedCredential.CertificateChain) do
  begin
    LCert.Entries[LI].CertData := FResolvedCredential.CertificateChain[LI];
    // the per-certificate extensions are stored as their framed vector; empty = 00 00
    LCert.Entries[LI].Extensions := TBytes.Create($00, $00);
  end;

  // staple the OCSP response in the leaf entry when the client offered status_request
  // and a staple is configured (RFC 8446 4.4.2.1)
  if FStatusRequestOffered and (System.Length(LCert.Entries) > 0) then
  begin
    LStaple := FResolvedCredential.CurrentOcspStaple;
    if System.Length(LStaple) > 0 then
      LCert.Entries[0].Extensions :=
        THandshakeMessages.EncodeLeafStapleExtensions(LStaple);
  end;
  LBody := THandshakeMessages.EncodeCertificate(LCert);

  // compress only when the client advertised an algorithm we hold AND the result is
  // strictly smaller (RFC 8879); otherwise send the Certificate uncompressed
  LCompressor := TCertificateCompression.SelectCompressor(
    FParams.CertificateCompressors, FClientCertCompressionAlgorithms);
  if LCompressor <> nil then
  begin
    LCompressed := TCertificateCompression.CompressWithCache(
      FParams.CertificateCompressionCache, FParams.Crypto, LCompressor, LBody);
    if System.Length(LCompressed) < System.Length(LBody) then
    begin
      LMsg.Algorithm := LCompressor.Algorithm;
      LMsg.UncompressedLength := System.Length(LBody);
      LMsg.Compressed := LCompressed;
      Exit(THandshakeFraming.Frame(TTlsHandshakeType.CompressedCertificate,
        THandshakeMessages.EncodeCompressedCertificate(LMsg)));
    end;
  end;

  Result := THandshakeFraming.Frame(TTlsHandshakeType.Certificate, LBody);
end;

function TTls13ServerStateMachine.BuildCertificateRequest: TBytes;
var
  LContext: TExtensionContext;
  LRequest: TTlsCertificateRequest13;
begin
  LContext := TExtensionContext.Create;
  try
    LContext.SignatureSchemes := FParams.ClientAuthSignatureSchemes;
    LContext.CertificateAuthorities := FParams.ClientCertificateAuthorities;
    LRequest.RequestContext := nil; // empty in a first (non-resumption) handshake
    LRequest.Extensions := FCodec.ProduceBlock(LContext,
      TTlsExtensionContextKind.CertificateRequest);
    Result := THandshakeFraming.Frame(TTlsHandshakeType.CertificateRequest,
      THandshakeMessages.EncodeCertificateRequest13(LRequest));
  finally
    LContext.Free;
  end;
end;

function TTls13ServerStateMachine.ProcessClientCertificate(
  const AMessage: TTlsHandshakeMessage): TArray<THandshakeEffect>;
var
  LCert: TTlsCertificate;
  LI: Int32;
  LAlert: TTlsAlertDescription;
  LVerified: TVerifiedChain;
begin
  Result := nil;
  LCert := THandshakeMessages.DecodeCertificate(AMessage.Body);
  FTranscript.Update(AMessage.Raw);

  FClientCertChain := nil;
  FParsedClientLeaf := nil;
  SetLength(FClientCertChain, System.Length(LCert.Entries));
  for LI := 0 to High(LCert.Entries) do
    FClientCertChain[LI] := LCert.Entries[LI].CertData;

  if System.Length(FClientCertChain) = 0 then
  begin
    // an empty client Certificate: required auth aborts, requested auth proceeds with
    // no client identity (RFC 8446 4.4.2.4)
    if FParams.ClientAuth = TClientAuthMode.Required then
      raise EFatalAlertTlsLibException.CreateRes(
        TTlsAlertDescription.CertificateRequired, @SClientCertificateRequired);
    FPhase := TPhase.WaitClientFinished;
    Exit;
  end;

  // a client leaf that is not a well-formed certificate is a decode error, caught before
  // the verifier (which, for -require-any-client-certificate, does not parse the chain)
  FParsedClientLeaf := TCertificateVerify.ParseWellFormedLeaf(FParams.Inspector,
    FClientCertChain[0]);

  // RFC 8446 4.4.2: extensions on a client CertificateEntry must correspond to ones in the
  // CertificateRequest; we request none, so any leaf extension is unsupported_extension.
  if System.Length(THandshakeMessages.CertificateEntryExtensionTypes(
    LCert.Entries[0].Extensions)) > 0 then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.UnsupportedExtension, @SUnsolicitedClientCertExtension);

  // trust the client chain (no hostname identity or OCSP staple applies to a client certificate)
  if not TCertificateVerify.VerifyClientChain(FParams.ClientCertificateVerifier,
    FClientCertChain, LVerified, LAlert) then
    raise EFatalAlertTlsLibException.CreateRes(LAlert, @SUntrustedClientCertificate);
  FPhase := TPhase.WaitClientCertVerify;
  // surface the validated client path (leaf first, with the recovered issuer/anchor) for
  // connection info (read-only), not the raw presented chain
  Result := TArray<THandshakeEffect>.Create(
    THandshakeEffects.PeerCertificateChain(LVerified.Path));
  // async verdict: the pipeline accepted the client chain; park for the host's out-of-band decision.
  // Carry both the presented chain and the validated path (issuer at index 1), so a live resolver
  // authenticates against the PKIX issuer, never a guess. The buffered CertificateVerify/Finished
  // resume once SetCertificateVerdict does.
  if TPeerAuthentication.ShouldPark(FParams.AsyncVerdict,
    FParams.LiveRevocationDeferral, LVerified.Outcome) then
    TArrayUtilities.Append<THandshakeEffect>(Result,
      ParkForVerdict(FClientCertChain, LVerified.Path, '', nil));
end;

function TTls13ServerStateMachine.ProcessClientCertVerify(
  const AMessage: TTlsHandshakeMessage): TArray<THandshakeEffect>;
var
  LCertVerify: TTlsCertificateVerify;
  LScheme: TSignatureScheme;
  LContent: TBytes;
begin
  Result := nil;
  LCertVerify := THandshakeMessages.DecodeCertificateVerify(AMessage.Body);
  // the client may sign only with a scheme the CertificateRequest advertised, valid for a TLS 1.3
  // handshake, and the client leaf's key must be allowed to produce it (RFC 8446 4.4.3)
  LScheme := TPeerAuthentication.RequirePeerScheme(FParams.ClientAuthSignatureSchemes,
    LCertVerify.Algorithm, TTlsVersion.Tls13, FParsedClientLeaf);
  // the client signs the transcript through its Certificate, client-side context string
  LContent := TCertificateVerify.SignatureContent(False, FTranscript.CurrentHash);
  TPeerAuthentication.VerifyPeerSignature(FParams.Crypto, FParsedClientLeaf, LScheme,
    LContent, LCertVerify.Signature);
  FTranscript.Update(AMessage.Raw);
  FPhase := TPhase.WaitClientFinished;
end;

function TTls13ServerStateMachine.SignCertificateVerify(
  const ATranscriptHash: TBytes): TBytes;
var
  LSigner: ISignatureSigner;
  LContent: TBytes;
  LVerify: TTlsCertificateVerify;
begin
  LContent := TCertificateVerify.SignatureContent(True, ATranscriptHash);
  LSigner := FParams.Crypto.Signing.CreateSignatureSigner(
    FSelectedSignatureScheme, FResolvedCredential.PrivateKey);
  LSigner.Update(LContent, 0, System.Length(LContent));
  LVerify.Algorithm := FSelectedSignatureScheme.ToCode;
  LVerify.Signature := LSigner.Sign;
  Result := THandshakeFraming.Frame(TTlsHandshakeType.CertificateVerify,
    THandshakeMessages.EncodeCertificateVerify(LVerify));
end;

function TTls13ServerStateMachine.ProcessEndOfEarlyData(
  const AMessage: TTlsHandshakeMessage): TArray<THandshakeEffect>;
begin
  // EndOfEarlyData is an empty message (RFC 8446 4.5); a non-empty body is a decode error
  if System.Length(AMessage.Body) <> 0 then
    raise EFatalAlertTlsLibException.CreateRes(TTlsAlertDescription.DecodeError,
      @SNonEmptyEndOfEarlyData);
  FTranscript.Update(AMessage.Raw);
  FPhase := TPhase.WaitClientFinished;
  // the early-data read window is over: the client's remaining flight (its Finished) is under
  // the handshake keys, and further application_data before that Finished is unexpected
  Result := TArray<THandshakeEffect>.Create(
    THandshakeEffects.SetEarlyReadEpoch(False),
    THandshakeEffects.InstallKeys(FSchedule.TrafficKeys(TTlsEpoch.Handshake,
    TTlsDirection.ClientWrite), TRecordSide.ReadSide, FSelectedSuite.Common.Aead,
    TTlsVersion.Tls13));
end;

function TTls13ServerStateMachine.ProcessClientFinished(
  const AMessage: TTlsHandshakeMessage): TArray<THandshakeEffect>;
begin
  // the client Finished is over the transcript through the server Finished
  if not FSchedule.VerifyFinished(TTlsDirection.ClientWrite,
    FTranscript.CurrentHash, AMessage.Body) then
    raise EFatalAlertTlsLibException.CreateRes(TTlsAlertDescription.DecryptError,
      @SBadClientFinished);
  FTranscript.Update(AMessage.Raw);
  // the resumption master secret is over the transcript through the client Finished
  FSchedule.DeriveResumptionMasterSecret(FTranscript.CurrentHash);

  FPhase := TPhase.Connected;
  MarkConnected;
  Result := TArray<THandshakeEffect>.Create(
    THandshakeEffects.InstallKeys(FSchedule.TrafficKeys(TTlsEpoch.Application,
    TTlsDirection.ClientWrite), TRecordSide.ReadSide, FSelectedSuite.Common.Aead, TTlsVersion.Tls13),
    THandshakeEffects.ConnectionParams(FSelectedSuite.Common.Code,
    FSelectedGroup.Code, FPskAccepted, FRequestedServerName));
  // record the ECH status before signalling completion, so a sink reading it in the established
  // callback sees the final value (the client machine emits the status before completion too)
  if FEchStatus = TEchStatus.Accepted then
    TArrayUtilities.Append<THandshakeEffect>(Result, THandshakeEffects.EchAccepted)
  else if FEchStatus = TEchStatus.Backend then
    TArrayUtilities.Append<THandshakeEffect>(Result, THandshakeEffects.EchBackend)
  else if FEchStatus = TEchStatus.Rejected then
    TArrayUtilities.Append<THandshakeEffect>(Result, THandshakeEffects.EchServerRejected);
  TArrayUtilities.Append<THandshakeEffect>(Result,
    THandshakeEffects.HandshakeEstablished);
  // issue resumption tickets under the freshly-installed application write keys
  EmitNewSessionTickets(Result);
  // tickets are minted; release the handshake-stage secrets (the connection keeps its application
  // traffic secrets, exporter, and the resumption master derived above)
  FSchedule.ForgetHandshakeSecrets;
end;

procedure TTls13ServerStateMachine.EmitNewSessionTickets(
  var AEffects: TArray<THandshakeEffect>);
var
  LI: Int32;
  LNonce: TBytes;
  LAgeAdd: UInt32;
  LPsk: ISecretBuffer;
  LSession: IResumableSession;
  LHandle: TBytes;
  LNst: TTlsNewSessionTicket;
  LContext: TExtensionContext;
  LLifetime: UInt32;
  LChainForTicket: TArray<TBytes>;
begin
  if (FTicketStrategy = nil) or (FParams.IssueTicketCount <= 0) then
    Exit;
  // a ticket is resumable only via psk_dhe_ke; a client that advertised neither that mode nor a
  // psk_key_exchange_modes extension at all cannot use one, so issuing it would just be wasted
  // bytes the client discards (RFC 8446 4.2.9)
  if not FClientOfferedPskDheKe then
    Exit;
  // a server MUST NOT advertise a lifetime above the RFC 8446 4.6.1 ceiling, and MUST NOT honour
  // a resumption beyond it either, so clamp the value the session stores and the ticket carries
  LLifetime := FParams.TicketLifetimeSeconds;
  if LLifetime > MaxTicketLifetimeSeconds then
    LLifetime := MaxTicketLifetimeSeconds;
  for LI := 0 to FParams.IssueTicketCount - 1 do
  begin
    LNonce := FParams.Crypto.Primitives.GetRandom.GenerateBytes(TicketNonceLength);
    // a fresh random ticket_age_add per ticket obfuscates the wire age (RFC 8446 4.6.1);
    // the same value is sealed into the session so the offered age reconciles on resumption
    LAgeAdd := TBinaryPrimitives.ReadUInt32BigEndian(
      FParams.Crypto.Primitives.GetRandom.GenerateBytes(4), 0);
    LPsk := FSchedule.ResumptionPsk(LNonce);
    // the ticket identity is the sealed/handle output, so the session's own id is unused;
    // MaxEarlyData authorizes 0-RTT on the resumed connection. Carry the client chain forward so a
    // re-issued ticket does not drop the client identity and force the next connection to a full
    // handshake; a resumed chain is only ever one this configuration accepted under its own scope,
    // so re-sealing it launders no foreign identity. Empty on a non-mTLS handshake.
    if System.Length(FClientCertChain) > 0 then
      LChainForTicket := FClientCertChain
    else
      LChainForTicket := FResumedPeerCertificates;
    LSession := TResumableSession.CreateTls13(FSelectedSuite.Common.Code,
      FSelectedSuite.Common.Hash, LPsk, FSelectedGroup.Code, FSelectedAlpn,
      FRequestedServerName, nil,
      LLifetime, LAgeAdd, FParams.Clock.NowUnixMillis,
      FParams.MaxEarlyData, LChainForTicket, FParams.ResumptionScope);
    LHandle := FTicketStrategy.Seal(LSession);
    // an empty handle means the strategy declined to seal (e.g. an oversized chain over the cap):
    // issue no ticket for this connection rather than an unusable one
    if System.Length(LHandle) = 0 then
      Continue;
    LNst := Default(TTlsNewSessionTicket);
    LNst.TicketLifetime := LLifetime;
    LNst.TicketAgeAdd := LAgeAdd;
    LNst.TicketNonce := LNonce;
    LNst.Ticket := LHandle;
    // advertise max_early_data_size in the ticket when 0-RTT is configured
    LContext := TExtensionContext.Create;
    try
      LContext.EarlyDataMaxSize := FParams.MaxEarlyData;
      LNst.Extensions := FCodec.ProduceBlock(LContext,
        TTlsExtensionContextKind.NewSessionTicket);
    finally
      LContext.Free;
    end;
    TArrayUtilities.Append<THandshakeEffect>(AEffects,
      THandshakeEffects.SendHandshake(THandshakeFraming.Frame(
      TTlsHandshakeType.NewSessionTicket,
      THandshakeMessages.EncodeNewSessionTicket(LNst))));
  end;
end;

function TTls13ServerStateMachine.Route(
  const AMessage: TTlsHandshakeMessage): TArray<THandshakeEffect>;
var
  LType: TTlsHandshakeType;
  LKnown: Boolean;
begin
  LKnown := TTlsHandshakeType.TryFromByte(AMessage.TypeByte, LType);
  case FPhase of
    TPhase.Initial:
      if LKnown and (LType = TTlsHandshakeType.ClientHello) then
        Result := ProcessClientHello(AMessage)
      else
        Result := Unexpected;
    TPhase.WaitSecondClientHello:
      if LKnown and (LType = TTlsHandshakeType.ClientHello) then
        Result := ProcessSecondClientHello(AMessage)
      else
        Result := Unexpected;
    TPhase.WaitClientCertificate:
      if LKnown and (LType = TTlsHandshakeType.Certificate) then
        Result := ProcessClientCertificate(AMessage)
      else
        Result := Unexpected;
    TPhase.WaitClientCertVerify:
      if LKnown and (LType = TTlsHandshakeType.CertificateVerify) then
        Result := ProcessClientCertVerify(AMessage)
      else
        Result := Unexpected;
    TPhase.WaitEndOfEarlyData:
      if LKnown and (LType = TTlsHandshakeType.EndOfEarlyData) then
        Result := ProcessEndOfEarlyData(AMessage)
      else
        Result := Unexpected;
    TPhase.WaitClientFinished:
      if LKnown and (LType = TTlsHandshakeType.Finished) then
        Result := ProcessClientFinished(AMessage)
      else
        Result := Unexpected;
    TPhase.Connected:
      // post-handshake: a client KeyUpdate rekeys the read epoch and may trigger one
      // responding update (RFC 8446 4.6.3)
      if LKnown and (LType = TTlsHandshakeType.KeyUpdate) then
        Result := HandleInboundKeyUpdate(AMessage)
      else
        Result := Unexpected;
  else
    Result := Unexpected;
  end;
end;

function TTls13ServerStateMachine.WriteDirection: TTlsDirection;
begin
  Result := TTlsDirection.ServerWrite;
end;

function TTls13ServerStateMachine.ReadDirection: TTlsDirection;
begin
  Result := TTlsDirection.ClientWrite;
end;

end.
