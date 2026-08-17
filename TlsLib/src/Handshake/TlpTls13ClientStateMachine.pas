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
  TlpArrayUtilities,
  TlpTlsAlert,
  TlpTlsVersion,
  TlpTlsLibExceptions,
  TlpISecretBuffer,
  TlpSecretBuffer,
  TlpICryptoProvider,
  TlpINamedGroup,
  TlpIKeySchedule,
  TlpTls13KeySchedule,
  TlpITranscriptHash,
  TlpTranscriptHash,
  TlpCryptoAlgorithms,
  TlpNegotiationTypes,
  TlpINegotiation,
  TlpNegotiationPolicy,
  TlpWireReader,
  TlpExtensionContext,
  TlpITlsExtension,
  TlpExtensionBlockCodec,
  TlpCoreExtensions,
  TlpGrease,
  TlpHandshakeMessage,
  TlpHandshakeMessages,
  TlpCertificateCompression,
  TlpICertificateCompression,
  TlpCertificateVerify,
  TlpICertificateTrust,
  TlpISigningKey,
  TlpTlsCredential,
  TlpISession,
  TlpIClock,
  TlpSession,
  TlpExternalPskImporter,
  TlpITlsEngine,
  TlpHandshakeEffect,
  TlpIHandshakeMachine,
  TlpTls13HandshakeBase;

type
  /// <summary>The inputs a client handshake needs to build and drive its flight.</summary>
  TClientHandshakeParams = record
    Provider: ICryptoProvider;
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
    AlpnProtocols: TArray<string>;
    /// <summary>The record_size_limit (RFC 8449) plaintext value to advertise, in
    /// [64, 2^14]; 0 leaves the extension unoffered.</summary>
    RecordSizeLimit: Int32;
    /// <summary>The certificate-compression algorithms the client can decompress
    /// (RFC 8879), in preference order; empty omits compress_certificate.</summary>
    CertificateDecompressors: TArray<ICertificateDecompressor>;
    /// <summary>Whether to sprinkle GREASE (RFC 8701) codepoints across the offers.</summary>
    Grease: Boolean;
    /// <summary>Whether the client offers the status_request (OCSP stapling) extension
    /// (RFC 6066). Off by default: the client requests a staple only when configured to,
    /// so an unsolicited server staple is rejected.</summary>
    RequestOcspStapling: Boolean;
    /// <summary>When set, the ClientHello also offers TLS 1.2 (supported_versions gains
    /// 1.2 and extended_master_secret is offered) so one hello serves a dual-version
    /// handshake; OfferedSuites is expected to already carry the 1.2 suites.</summary>
    AlsoOfferTls12: Boolean;
    ClientRandom: TBytes;
    LegacySessionId: TBytes;
    ServerName: string;
    /// <summary>Decides whether the server's certificate chain is trusted. Required:
    /// with none configured the handshake fails closed.</summary>
    CertificateVerifier: ICertificateVerifier;
    /// <summary>The host the server certificate must be valid for (RFC 6125).</summary>
    ExpectedHostName: string;
    /// <summary>When set, Start sends these framed ClientHello bytes verbatim (replay/testing).</summary>
    ClientHelloOverride: TBytes;
    /// <summary>The client's credential for mutual TLS: presented when the server sends
    /// a CertificateRequest and the credential can satisfy it. An empty chain sends an
    /// empty client Certificate (declining to authenticate).</summary>
    ClientCredential: TTlsCredential;
    /// <summary>When set, the client offers a cached resumption PSK (if one exists for
    /// the server) and caches the NewSessionTickets the server issues. Nil disables
    /// resumption.</summary>
    SessionCache: ISessionCache;
    /// <summary>The clock read for a resumption PSK's obfuscated_ticket_age and ticket-lifetime
    /// expiry (RFC 8446 4.2.11 / 4.6.1). The factory always supplies one (system clock by
    /// default); a nil value falls back to the real clock at the call site.</summary>
    Clock: ITlsClock;
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
    /// <summary>When set, after the built-in trust pipeline accepts the server chain the
    /// machine parks the handshake for an out-of-band verdict (the deferred-verdict seam)
    /// rather than continuing inline. Augment-only and fail-closed. OFF by default.</summary>
    AsyncVerdict: Boolean;
  end;

  /// <summary>
  /// The TLS 1.3 client happy-path machine: it builds the ClientHello, then on the
  /// server flight installs the handshake keys, verifies the server certificate and
  /// Finished, sends its own Finished, and installs the application keys. It returns
  /// effects and never touches the record layer; the driver applies them. Certificate
  /// trust runs inline and fail-closed.
  /// </summary>
  TTls13ClientStateMachine = class sealed(TTls13HandshakeBase)
  strict private
  type
    TPhase = (Initial, WaitServerHello, WaitEncryptedExtensions, WaitCertificate,
      WaitCertificateVerify, WaitServerFinished, Connected);
  var
    FParams: TClientHandshakeParams;
    FEphemeralPrivate: ISecretBuffer;
    FEphemeralPublic: TBytes;
    FCurrentGroup: INamedGroup;
    FCurrentGroupCode: UInt16;
    FCookie: TBytes;
    FRetried: Boolean;
    /// <summary>The GREASE seed, chosen once for the first ClientHello and reused on a
    /// HelloRetryRequest retry so the retry's GREASE codepoints match the first exactly
    /// (RFC 8446 4.1.4 requires an otherwise-identical second ClientHello). -1 until chosen.</summary>
    FGreaseSeed: Int32;
    /// <summary>Whether the HelloRetryRequest requested a key_share group change. On a group
    /// change the retry sends a single key_share for the new group (no GREASE); a cookie-only
    /// retry keeps the first ClientHello's key_share unchanged (RFC 8446 4.1.2).</summary>
    FHrrChangedGroup: Boolean;
    /// <summary>Guards the single middlebox-compatibility change_cipher_spec so it is
    /// emitted at most once (RFC 8446 D.4).</summary>
    FMiddleboxCcsSent: Boolean;
    FOfferedExtensions: TArray<UInt16>;
    FCertificateChain: TArray<TBytes>;
    /// <summary>The stapled OCSP response the server delivered in the leaf CertificateEntry
    /// (RFC 8446 4.4.2.1); empty when none was stapled. Fed to the trust verdict.</summary>
    FReceivedOcspStaple: TBytes;
    /// <summary>A CertificateRequest was received, so the client owes a Certificate
    /// (and, when it has a usable credential, a CertificateVerify).</summary>
    FCertificateRequested: Boolean;
    FRequestContext: TBytes;
    FClientAuthSchemes: TArray<UInt16>;
    /// <summary>The DER DistinguishedName certificate_authorities the server named in its
    /// CertificateRequest (RFC 8446 4.2.4); surfaced for read-only connection info.</summary>
    FRequestedCertificateAuthorities: TArray<TBytes>;
    /// <summary>The pre-shared keys this ClientHello offered, in offered order (empty when
    /// none): a single resumption PSK from the cache, or the imported external PSKs (RFC
    /// 9258), one entry per (external PSK, supported KDF hash). The server's selected_identity
    /// indexes this list.</summary>
    FPskOffers: TArray<IPreSharedKey>;
    /// <summary>The offered PSK the server selected (nil when none was accepted).</summary>
    FAcceptedPsk: IPreSharedKey;
    /// <summary>A cached TLS 1.2 session this dual-version ClientHello offers for 1.2
    /// resumption (nil otherwise), and the session id it put in legacy_session_id so a 1.2
    /// hand-off can match the server's abbreviated echo. A 1.3 server ignores both.</summary>
    FTls12ResumptionSession: IResumableSession;
    FTls12OfferedSessionId: TBytes;
    /// <summary>The legacy_session_id this ClientHello actually sent, which the server must
    /// echo (RFC 8446 4.1.3); normally the middlebox id, but the offered 1.2 session id when
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
    /// <summary>Whether the server accepted the offered early data (EncryptedExtensions).</summary>
    FEarlyDataAccepted: Boolean;
    /// <summary>Whether the selected suite matches the resumption PSK's bound suite; 0-RTT
    /// is bound to the ticket's exact suite, so accepted early data under a different one
    /// is illegal (RFC 8446 4.2.10).</summary>
    FEarlySuiteMatched: Boolean;
    /// <summary>Whether a single offered PSK pre-activated the transcript at Start (so the
    /// binder and early keys ran under that PSK's hash), and the hash it was activated under.
    /// If the server then rejects the PSK and (without a HelloRetryRequest) selects a suite
    /// with a different hash - a 0-RTT reject that changes the PRF - the transcript must be
    /// rebuilt from the raw first ClientHello under the newly selected hash (RFC 8446 4.4.1).</summary>
    FTranscriptPreActivated: Boolean;
    FPreActivatedHash: THashAlgorithm;
    /// <summary>The transcript hash through the client Finished, for caching tickets.</summary>
    FResumptionTranscriptHash: TBytes;
    /// <summary>The ALPN protocol negotiated in EncryptedExtensions, stored on a ticket.</summary>
    FNegotiatedAlpn: string;
    FPhase: TPhase;
    /// <summary>Records the extension types the sent ClientHello carried, so a server
    /// response extension the client did not offer is rejected (RFC 8446 4.2).</summary>
    procedure RememberOffered(const AFramedClientHello: TBytes);
    /// <summary>Marks the recorded offered extension types on AContext.</summary>
    procedure ApplyOffered(const AContext: TExtensionContext);
    function BuildClientHello: TBytes;
    /// <summary>The (server identity, SNI) key this client caches resumable sessions under.</summary>
    function CacheServerIdentity: string;
    /// <summary>The current time in Unix milliseconds from the injected clock, falling back to
    /// the system clock when none was supplied (a directly-built params record).</summary>
    function NowUnixMillis: UInt64;
    /// <summary>Imports the configured external PSKs (RFC 9258) into the wire PSK offer
    /// list: each spec is imported once per supported KDF hash (SHA-256 then SHA-384), in
    /// spec order, so the server can match whichever the negotiated cipher's hash needs.</summary>
    function ImportExternalOffers: TArray<IPreSharedKey>;
    /// <summary>The digest of AData under AHash (the per-PSK binder transcript on the first
    /// ClientHello, where the transcript is otherwise just this message).</summary>
    function HashUnder(AHash: THashAlgorithm; const AData: TBytes): TBytes;
    /// <summary>After a HelloRetryRequest fixes the cipher (hence hash), drops every offered
    /// PSK whose hash differs, so the second ClientHello offers only the still-eligible ones
    /// (RFC 8446 4.1.4). The server's selected_identity then indexes the pruned list.</summary>
    procedure PruneOffersToHash(AHash: THashAlgorithm);
    /// <summary>
    /// Back-patches the real PSK binders into the ClientHello tail: each binder MACs the
    /// message up to (excluding) the binders vector, computed under its own offered PSK and
    /// that PSK's hash (RFC 8446 4.2.11.2 / RFC 9258 6).
    /// </summary>
    procedure PatchBinder(var AClientHello: TBytes);
    /// <summary>Consumes a post-handshake NewSessionTicket into an IResumableSession and
    /// caches it, returning the SessionTicketReceived effect (RFC 8446 4.6.1).</summary>
    function CacheNewSessionTicket(const AMessage: TTlsHandshakeMessage)
      : TArray<THandshakeEffect>;
    function ProcessServerHello(const AMessage: TTlsHandshakeMessage)
      : TArray<THandshakeEffect>;
    /// <summary>Replaces the transcript with a fresh one under the selected suite's hash and
    /// replays the raw first ClientHello into it, for a 0-RTT reject whose full handshake uses
    /// a different PRF hash than the pre-activated PSK (RFC 8446 4.4.1). Not a message_hash
    /// rebase (that is HelloRetryRequest-only); the full-handshake transcript is the plain
    /// ClientHello || ServerHello || ... under the new hash.</summary>
    procedure RebuildTranscriptUnderSelectedHash;
    /// <summary>Rejects a TLS 1.3 ServerHello that carries any extension other than
    /// supported_versions, key_share or pre_shared_key (RFC 8446 4.1.3).</summary>
    class procedure EnforceTls13ServerHelloExtensions(
      const AExtensions: TBytes); static;
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
    /// <summary>Records a CertificateRequest (RFC 8446 4.3.2): the request context and
    /// the server's accepted signature schemes, folding it into the transcript.</summary>
    procedure ProcessCertificateRequest(const AMessage: TTlsHandshakeMessage);
    /// <summary>Frames the client Certificate for the request context (empty chain when
    /// no usable credential); appends the framed CertificateVerify when a chain is sent.</summary>
    procedure AppendClientAuthFlight(var AEffects: TArray<THandshakeEffect>);
    /// <summary>The one dummy change_cipher_spec, returned the first time it is needed
    /// and empty thereafter, so the caller prepends it to the flight that carries the
    /// client's second flight - the encrypted handshake, or the retry ClientHello.</summary>
    function MiddleboxCcs: TArray<THandshakeEffect>;
    function ProcessServerFinished(const AMessage: TTlsHandshakeMessage)
      : TArray<THandshakeEffect>;
  strict protected
    function Route(const AMessage: TTlsHandshakeMessage)
      : TArray<THandshakeEffect>; override;
    function WriteDirection: TTlsDirection; override;
    function ReadDirection: TTlsDirection; override;
  public
    constructor Create(const AParams: TClientHandshakeParams);
    function Initiates: Boolean; override;
    function Start: TArray<THandshakeEffect>; override;
    /// <summary>The cached TLS 1.2 session this unified ClientHello offered (nil when it
    /// offered none), for a version-dispatching parent to hand to a 1.2 sub-machine when
    /// the server selects 1.2.</summary>
    property Tls12ResumptionSession: IResumableSession read FTls12ResumptionSession;
    /// <summary>The session id this ClientHello offered for 1.2 resumption, so the 1.2
    /// sub-machine can match the server's abbreviated echo.</summary>
    property Tls12OfferedSessionId: TBytes read FTls12OfferedSessionId;
    /// <summary>The legacy_session_id this unified ClientHello actually put on the wire -
    /// the cached 1.2 session id when resuming, otherwise the random TLS 1.3 compatibility-mode
    /// id. A 1.2 sub-machine uses it to detect a server echoing the id, whether that echo is a
    /// genuine resumption or a false one (RFC 5246 7.4.1.3).</summary>
    property SentLegacySessionId: TBytes read FSentLegacySessionId;
  end;

implementation

resourcestring
  SUnofferedSuite = 'the server selected a cipher suite that was not offered';
  SUnknownSelectedSuite = 'the selected cipher suite is not in the registry';
  SBadSessionIdEcho = 'the server echoed a session id that was not offered';
  SDowngradeDetected = 'the ServerHello carries a version downgrade sentinel';
  SUnsupportedSelectedVersion = 'the server did not select TLS 1.3';
  SUnofferedGroup = 'the server selected a key share group that was not offered';
  SBadServerFinished = 'the server Finished did not verify';
  SEmptyCertificate = 'the server sent an empty certificate list';
  SUnsolicitedCertExtension =
    'the server certificate carries an extension that was not requested';
  SDuplicateCertExtension =
    'the server certificate entry repeats an extension';
  SUnofferedScheme = 'the CertificateVerify uses a signature scheme that was not offered';
  SLegacyPkcs1InTls13 = 'the CertificateVerify uses a legacy rsa_pkcs1 scheme, which is ' +
    'certificate-only in TLS 1.3';
  SLeafKeyUsageForbidsSigning = 'the server certificate keyUsage does not permit digitalSignature';
  SPssLeafKeyUnsupported = 'an rsa_pss_rsae scheme was used with an id-RSASSA-PSS certificate key';
  SBadCertificateVerify = 'the CertificateVerify signature did not verify';
  SNoCertificateVerifier = 'no certificate verifier configured (fail-closed)';
  SUntrustedCertificate = 'the server certificate chain was not trusted';
  SUnofferedAlpn = 'the server selected an ALPN protocol that was not offered';
  SEarlyDataSuiteMismatch = 'the server accepted early data under a cipher suite that differs from the resumption ticket';
  SEarlyDataAlpnMismatch = 'the server accepted early data but negotiated a different ALPN protocol than the resumption ticket';
  SBadRecordSizeLimit = 'the server record_size_limit is below the 64-byte minimum';
  SHelloRetryUnoffered = 'the HelloRetryRequest named a group that was not offered';
  SHelloRetrySameGroup = 'the HelloRetryRequest named the already-offered key_share group';
  SHelloRetryTwice = 'the server sent a second HelloRetryRequest';
  SHelloRetryNoGroup = 'the HelloRetryRequest group is not available';
  SHelloRetryNoChange =
    'the HelloRetryRequest changes neither the key_share group nor adds a cookie';
  SRetryCipherChanged =
    'the ServerHello changed the cipher suite the HelloRetryRequest selected';
  SServerHelloExtNotAllowed =
    'the ServerHello carries an extension not permitted in a TLS 1.3 ServerHello';
  SRequestContextNotEmpty = 'the CertificateRequest carried a non-empty request context in the handshake';
  SNoClientAuthScheme = 'no configured client credential scheme satisfies the server signature_algorithms';
  SBadSelectedPskIdentity = 'the server selected a pre_shared_key identity index beyond the offered list';
  SPskHashMismatch = 'the selected cipher suite hash does not match the accepted pre_shared_key hash';
  SPskRequiredNotSelected = 'the server did not select a pre_shared_key and no certificate trust is configured';

const
  PskDheKeMode = Byte(1); // psk_key_exchange_modes: psk_dhe_ke

{ TTls13ClientStateMachine }

constructor TTls13ClientStateMachine.Create(const AParams: TClientHandshakeParams);
begin
  inherited Create(AParams.ExtensionRegistry);
  FParams := AParams;
  FCurrentGroup := AParams.Group;
  FCurrentGroupCode := AParams.GroupCode;
  FRetried := False;
  FGreaseSeed := -1;
  FHrrChangedGroup := False;
  FPhase := TPhase.Initial;
end;

procedure TTls13ClientStateMachine.RememberOffered(
  const AFramedClientHello: TBytes);
var
  LHello: TTlsClientHello;
  LReader, LOuter, LData: TWireReader;
begin
  FOfferedExtensions := nil;
  // strip the 4-byte handshake header (type + uint24 length) to reach the body
  LHello := THandshakeMessages.DecodeClientHello(System.Copy(AFramedClientHello, 4,
    System.Length(AFramedClientHello) - 4));
  LReader := TWireReader.Create(LHello.Extensions);
  LOuter := LReader.OpenVector(2);
  while not LOuter.EndReached do
  begin
    TArrayUtilities.Append<UInt16>(FOfferedExtensions, LOuter.ReadUInt16);
    LData := LOuter.OpenVector(2); // advances past this extension's data
    LData.ReadBytes(LData.Remaining);
  end;
end;

procedure TTls13ClientStateMachine.ApplyOffered(const AContext: TExtensionContext);
var
  LType: UInt16;
begin
  for LType in FOfferedExtensions do
    AContext.MarkOffered(LType);
end;

function TTls13ClientStateMachine.BuildClientHello: TBytes;
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
      // match the first ClientHello exactly (RFC 8446 4.1.4)
      if FGreaseSeed < 0 then
        FGreaseSeed := FParams.Provider.GetRandom.GenerateBytes(1)[0];
      LSeed := FGreaseSeed;
      LContext.SupportedVersions := TGrease.Prepend(LContext.SupportedVersions,
        TGrease.ValueAt(LSeed));
      LGroups := TGrease.Prepend(LGroups, TGrease.ValueAt(LSeed + 1));
      LSchemes := TGrease.Prepend(LSchemes, TGrease.ValueAt(LSeed + 2));
      LSuites := TGrease.Prepend(LSuites, TGrease.ValueAt(LSeed + 3));
      // a group-change retry MUST carry exactly one KeyShareEntry - the requested group
      // (RFC 8446 4.1.2), so drop the GREASE share then. The first ClientHello, and a
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
    // is offered yet (RFC 8446 4.2.9); the pre_shared_key identity and its back-patched
    // binder are added only when actually resuming (pre_shared_key stays the last extension)
    if (FParams.SessionCache <> nil) or (System.Length(FPskOffers) > 0) then
      LContext.PskModes := TBytes.Create(PskDheKeMode);
    // a dual-version client with a cache signals session_ticket support (RFC 5077) so a 1.2
    // server issues a ticket for future resumption; a held 1.2 session adds its ticket. The
    // extended_master_secret offer is kept on (RFC 7627 5.1: a supporting client offers it in
    // every ClientHello, resumption included) so the 1.2 machine catches a server that resumes
    // a non-EMS session yet echoes the extension (RFC 7627 5.3). A 1.3 server ignores these
    // legacy fields.
    if FParams.AlsoOfferTls12 and (FParams.SessionCache <> nil) then
    begin
      LContext.SessionTicketOffered := True;
      if FTls12ResumptionSession <> nil then
        LContext.SessionTicket := FTls12ResumptionSession.SessionTicket;
    end;
    // pre_shared_key: one identity + obfuscated_age + placeholder binder per offered PSK.
    // A resumption ticket carries its obfuscated_ticket_age; an external PSK has none, so
    // it offers 0 (RFC 8446 4.2.11). The binders are back-patched after serialization.
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
            (NowUnixMillis - FPskOffers[LI].IssuedAtMillis) +
            FPskOffers[LI].TicketAgeAdd)
        else
          LContext.OfferedPskAges[LI] := 0;
        SetLength(LContext.OfferedPskBinders[LI],
          FParams.Provider.CreateHash(FPskOffers[LI].Hash).HashSize);
      end;
    end;

    LHello.Random := FParams.ClientRandom;
    // when offering a cached 1.2 session, legacy_session_id carries the id whose echo
    // signals the server's abbreviated (resumed) handshake; otherwise the middlebox id
    if FTls12ResumptionSession <> nil then
      LHello.LegacySessionId := FTls12OfferedSessionId
    else
      LHello.LegacySessionId := FParams.LegacySessionId;
    FSentLegacySessionId := LHello.LegacySessionId;
    LHello.CipherSuites := LSuites;
    LBlock := FCodec.ProduceBlock(LContext, TTlsExtensionContextKind.ClientHello);
    // GREASE injects a trailing extension; never after pre_shared_key (must be last)
    if FParams.Grease and (System.Length(FPskOffers) = 0) then
      LBlock := TGrease.InjectExtension(LBlock, TGrease.ValueAt(LSeed + 5));
    LHello.Extensions := LBlock;
    Result := THandshakeFraming.Frame(TTlsHandshakeType.ClientHello,
      THandshakeMessages.EncodeClientHello(LHello));
  finally
    LContext.Free;
  end;
end;

function TTls13ClientStateMachine.CacheServerIdentity: string;
begin
  if FParams.ServerIdentity <> '' then
    Result := FParams.ServerIdentity
  else
    Result := FParams.ServerName;
end;

function TTls13ClientStateMachine.NowUnixMillis: UInt64;
begin
  // the constructor guarantees a clock, so this never branches on nil
  Result := FParams.Clock.NowUnixMillis;
end;

function TTls13ClientStateMachine.HashUnder(AHash: THashAlgorithm;
  const AData: TBytes): TBytes;
var
  LHash: IHash;
begin
  LHash := FParams.Provider.CreateHash(AHash);
  LHash.Update(AData, 0, System.Length(AData));
  Result := LHash.DoFinal;
end;

procedure TTls13ClientStateMachine.PatchBinder(var AClientHello: TBytes);
var
  LI, LHashLen, LBindersLen, LTotal, LOffset: Int32;
  LPartial, LBinder, LPrefixHash: TBytes;
  LTemp: ITls13KeySchedule;
begin
  // the binders vector: a 2-byte list length, then per PSK a 1-byte entry length + binder
  LBindersLen := 2;
  for LI := 0 to High(FPskOffers) do
    Inc(LBindersLen, 1 + FParams.Provider.CreateHash(FPskOffers[LI].Hash).HashSize);
  LTotal := System.Length(AClientHello);
  LPartial := System.Copy(AClientHello, 0, LTotal - LBindersLen);

  // each binder MACs the ClientHello up to (excluding) the binders vector, under its own
  // PSK and hash. On the first flight the transcript is otherwise empty (deferred while
  // several hashes are in play), so the prefix hash is Hash(LPartial); on a HelloRetryRequest
  // retry the transcript is active (message_hash(CH1), HRR) on the single surviving hash.
  LOffset := (LTotal - LBindersLen) + 2; // past the 2-byte binders list length
  for LI := 0 to High(FPskOffers) do
  begin
    LHashLen := FParams.Provider.CreateHash(FPskOffers[LI].Hash).HashSize;
    if FTranscript.IsActive then
      LPrefixHash := FTranscript.HashPrefixExcludingBinders(LPartial)
    else
      LPrefixHash := HashUnder(FPskOffers[LI].Hash, LPartial);
    // the key length is irrelevant to the binder MAC (only the hash matters)
    LTemp := TTls13KeySchedule.Create(FParams.Provider, FPskOffers[LI].Hash, LHashLen);
    LTemp.SetPsk(FPskOffers[LI].Key);
    LBinder := LTemp.ComputeBinder(FPskOffers[LI].BinderKind, LPrefixHash);
    Move(LBinder[0], AClientHello[LOffset + 1], LHashLen); // +1 past the 1-byte entry length
    Inc(LOffset, 1 + LHashLen);
  end;
end;

function TTls13ClientStateMachine.ImportExternalOffers: TArray<IPreSharedKey>;
var
  LSpec: TExternalPsk;
begin
  Result := nil;
  // import each external PSK once per supported KDF hash (RFC 9258): a SHA-256 and a
  // SHA-384 variant, so whichever the negotiated cipher's hash needs is on offer
  for LSpec in FParams.ExternalPsks do
  begin
    TArrayUtilities.Append<IPreSharedKey>(Result,
      TExternalPskImporter.Import(FParams.Provider, LSpec, TlsWireVersionTls13,
      THashAlgorithm.SHA_256));
    TArrayUtilities.Append<IPreSharedKey>(Result,
      TExternalPskImporter.Import(FParams.Provider, LSpec, TlsWireVersionTls13,
      THashAlgorithm.SHA_384));
  end;
end;

procedure TTls13ClientStateMachine.PruneOffersToHash(AHash: THashAlgorithm);
var
  LKept: TArray<IPreSharedKey>;
  LOffer: IPreSharedKey;
begin
  LKept := nil;
  for LOffer in FPskOffers do
    if LOffer.Hash = AHash then
      TArrayUtilities.Append<IPreSharedKey>(LKept, LOffer);
  FPskOffers := LKept;
end;

function TTls13ClientStateMachine.CacheNewSessionTicket(
  const AMessage: TTlsHandshakeMessage): TArray<THandshakeEffect>;
var
  LNst: TTlsNewSessionTicket;
  LPsk: ISecretBuffer;
  LSession: IResumableSession;
  LContext: TExtensionContext;
  LMaxEarlyData: UInt32;
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
  if FParams.SessionCache = nil then
    Exit;
  LPsk := FSchedule.ResumptionPsk(FResumptionTranscriptHash, LNst.TicketNonce);
  LSession := TResumableSession.CreateTls13(FSelectedSuite.Common.Code,
    FSelectedSuite.Common.Hash, LPsk, FCurrentGroupCode, FNegotiatedAlpn,
    FParams.ServerName, LNst.Ticket,
    LNst.TicketLifetime, LNst.TicketAgeAdd, NowUnixMillis,
    LMaxEarlyData);
  FParams.SessionCache.Store(CacheServerIdentity, FParams.ServerName, LSession);
  Result := TArray<THandshakeEffect>.Create(
    THandshakeEffects.RaiseEvent(TTlsEventKind.SessionTicketReceived));
end;

function TTls13ClientStateMachine.Initiates: Boolean;
begin
  Result := True;
end;

function TTls13ClientStateMachine.Start: TArray<THandshakeEffect>;
var
  LClientHello: TBytes;
  LCached: IResumableSession;
  LPskSuite: TTlsCipherSuite;
  LHint: UInt16;
  LHintGroup: INamedGroup;
begin
  // key-exchange hint: lead the key_share with the group the server last selected for this
  // server, to avoid a HelloRetryRequest. Only an offered, resolvable group is honored.
  if (FParams.SessionCache <> nil) and (FParams.GroupRegistry <> nil) then
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
  // and (if accepted) the handshake continues under it (RFC 8446 4.2.11). A cached 1.2
  // session is instead offered as a legacy session_ticket / session id in this dual-version
  // hello, for a 1.2 server to resume (a 1.3 server ignores it); the taken session is
  // threaded to a 1.2 sub-machine by the version-dispatching parent.
  if (FParams.SessionCache <> nil) and (System.Length(FParams.ClientHelloOverride) = 0)
    and FParams.SessionCache.Take(CacheServerIdentity, FParams.ServerName, LCached) then
  begin
    if LCached.Version.WireValue = TlsWireVersionTls13 then
    begin
      // a ticket past its lifetime is not offered (RFC 8446 4.6.1): the client drops the
      // expired PSK and does a full handshake rather than offer one the server will reject
      if (NowUnixMillis - LCached.IssuedAtMillis) <=
        (UInt64(LCached.TicketLifetime) * 1000) then
        FPskOffers := TArray<IPreSharedKey>.Create(LCached.AsPreSharedKey);
    end
    else if FParams.AlsoOfferTls12 then
    begin
      FTls12ResumptionSession := LCached;
      if System.Length(LCached.SessionId) > 0 then
        FTls12OfferedSessionId := LCached.SessionId
      else
        FTls12OfferedSessionId := FParams.LegacySessionId;
    end;
  end;
  // configured out-of-band external PSKs (RFC 9258) are offered after any cached resumption
  // (each imported for every supported KDF hash), so a server prefers a resumption ticket
  // when it holds one and falls back to the external PSK otherwise (both may be offered in
  // one ClientHello). Several hashes may then be in play, so the transcript stays deferred
  // (activated once the ServerHello fixes the suite) and each binder is MAC'd under its own
  // PSK's hash in PatchBinder.
  if System.Length(FParams.ExternalPsks) > 0 then
    FPskOffers := TArrayUtilities.Concat<IPreSharedKey>(FPskOffers, ImportExternalOffers);
  // a single offered PSK has one known hash, so activate the transcript on it now (the
  // resumption / 0-RTT path relies on it); several offers defer activation to ServerHello
  if System.Length(FPskOffers) = 1 then
  begin
    FTranscript.Activate(FParams.Provider.CreateHash(FPskOffers[0].Hash));
    FTranscriptPreActivated := True;
    FPreActivatedHash := FPskOffers[0].Hash;
  end;
  // 0-RTT is offered only when enabled, resuming a single ticket, and the ticket authorized
  // early data (an external PSK carries no early-data budget)
  FEarlyDataOffered := (System.Length(FPskOffers) = 1) and FParams.EarlyDataEnabled and
    (FPskOffers[0].MaxEarlyData > 0) and
    FParams.CipherSuites.TryGet(FPskOffers[0].CipherSuite, LPskSuite);
  if System.Length(FParams.ClientHelloOverride) > 0 then
    LClientHello := FParams.ClientHelloOverride
  else
    LClientHello := BuildClientHello;
  if System.Length(FPskOffers) > 0 then
    PatchBinder(LClientHello);
  RememberOffered(LClientHello);
  FSentClientHelloRaw := LClientHello;
  FTranscript.Update(LClientHello);
  FPhase := TPhase.WaitServerHello;
  // the middlebox change_cipher_spec is deferred until the client commits to 1.3 and is
  // about to send its second flight; sending it here (before ServerHello) would break a
  // 1.2 negotiation, where the client's change_cipher_spec comes after ServerHelloDone
  Result := TArray<THandshakeEffect>.Create(
    THandshakeEffects.SendHandshake(LClientHello));
  if FEarlyDataOffered then
  begin
    // derive the client_early_traffic keys from the ClientHello transcript and open the
    // early write epoch, after the (plaintext) middlebox CCS
    FSchedule := TTls13KeySchedule.Create(FParams.Provider, LPskSuite.Common.Hash,
      LPskSuite.Common.KeyLength);
    FSchedule.SetPsk(FPskOffers[0].Key);
    FSchedule.DeriveEpochSecrets(TTlsEpoch.EarlyData, FTranscript.CurrentHash);
    // the plaintext CCS precedes the early keys
    Result := TArrayUtilities.Concat<THandshakeEffect>(Result, MiddleboxCcs);
    TArrayUtilities.Append<THandshakeEffect>(Result,
      THandshakeEffects.InstallKeys(FSchedule.TrafficKeys(TTlsEpoch.EarlyData,
      TTlsDirection.ClientWrite), TRecordSide.WriteSide, LPskSuite.Common.Aead,
      TTlsVersion.Tls13));
    // bound the outbound 0-RTT at the ticket's max_early_data; over-budget writes are
    // deferred by the engine to 1-RTT (RFC 8446 4.2.10)
    TArrayUtilities.Append<THandshakeEffect>(Result,
      THandshakeEffects.SetEarlyDataLimit(Int32(FPskOffers[0].MaxEarlyData)));
  end;
end;

class procedure TTls13ClientStateMachine.EnforceTls13ServerHelloExtensions(
  const AExtensions: TBytes);
var
  LReader, LEntries, LData: TWireReader;
  LType: UInt16;
begin
  if System.Length(AExtensions) = 0 then
    Exit;
  LReader := TWireReader.Create(AExtensions);
  LEntries := LReader.OpenVector(2);
  LReader.ExpectEnd;
  while not LEntries.EndReached do
  begin
    LType := LEntries.ReadUInt16;
    LData := LEntries.OpenVector(2);
    LData.ReadBytes(LData.Remaining);
    if (LType <> TExtensionTypes.SupportedVersions) and
      (LType <> TExtensionTypes.KeyShare) and
      (LType <> TExtensionTypes.PreSharedKey) then
      raise EFatalAlertTlsLibException.CreateRes(
        TTlsAlertDescription.UnsupportedExtension, @SServerHelloExtNotAllowed);
  end;
end;

procedure TTls13ClientStateMachine.RebuildTranscriptUnderSelectedHash;
var
  LFresh: ITranscriptHash;
begin
  LFresh := TTranscriptHash.Create(
    FParams.Provider.CreateHash(FSelectedSuite.Common.Hash));
  LFresh.Update(FSentClientHelloRaw);
  FTranscript := LFresh;
end;

function TTls13ClientStateMachine.ProcessServerHello(
  const AMessage: TTlsHandshakeMessage): TArray<THandshakeEffect>;
var
  LHello: TTlsServerHello;
  LContext: TExtensionContext;
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
  // attack (illegal_parameter, RFC 8446 4.1.3), any other lower version is unsupported and
  // reported as protocol_version (RFC 8446 4.2.1), not a cipher/decode error.
  LNegotiatedVersion := THandshakeMessages.ServerHelloSelectedVersion(LHello.Extensions);
  if LNegotiatedVersion <> 0 then
  begin
    // a ServerHello that selects its version via supported_versions is a TLS 1.3 construct
    // whose legacy_version MUST be 0x0303 (RFC 8446 4.1.3); any other value is not a version
    // this client agreed to
    if LHello.LegacyVersion <> TlsWireVersionTls12 then
      raise EFatalAlertTlsLibException.CreateRes(
        TTlsAlertDescription.ProtocolVersion, @SUnsupportedSelectedVersion);
  end
  else
    LNegotiatedVersion := LHello.LegacyVersion;
  if TDowngradeProtection.IsDowngradeAttack(LHello.Random, True, LNegotiatedVersion) then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.IllegalParameter, @SDowngradeDetected);
  if LNegotiatedVersion <> TlsWireVersionTls13 then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.ProtocolVersion, @SUnsupportedSelectedVersion);

  // after a HelloRetryRequest the ServerHello MUST keep the cipher suite the HRR chose (it
  // fixes the transcript hash); a change is illegal (RFC 8446 4.1.4)
  if FRetried and (LHello.CipherSuite <> FSelectedSuite.Common.Code) then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.IllegalParameter, @SRetryCipherChanged);

  // the selected suite must be one this client offered, not merely one it supports
  // (RFC 8446 4.1.3)
  if not (TArrayUtilities.Contains<UInt16>(FParams.OfferedSuites, LHello.CipherSuite)) then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.IllegalParameter, @SUnofferedSuite);
  if not FParams.CipherSuites.TryGet(LHello.CipherSuite, FSelectedSuite) then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.IllegalParameter, @SUnknownSelectedSuite);

  // legacy_session_id_echo must equal the id offered in the ClientHello (RFC 8446 4.1.3)
  if not TArrayUtilities.AreEqual(LHello.LegacySessionIdEcho, FSentLegacySessionId) then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.IllegalParameter, @SBadSessionIdEcho);

  // the hash is now known: activate the transcript (replays the ClientHello) unless a
  // retry already activated it, then add ServerHello. A single offered PSK pre-activated
  // the transcript under its hash; when the server rejects that PSK and selects a suite with
  // a different hash (a 0-RTT reject that changes the PRF), rebuild the transcript from the
  // raw first ClientHello under the newly selected hash so the derivations match the peer.
  if not FTranscript.IsActive then
    FTranscript.Activate(FParams.Provider.CreateHash(FSelectedSuite.Common.Hash))
  else if FTranscriptPreActivated and
    (FPreActivatedHash <> FSelectedSuite.Common.Hash) then
    RebuildTranscriptUnderSelectedHash;
  FTranscript.Update(AMessage.Raw);

  LContext := TExtensionContext.Create;
  try
    ApplyOffered(LContext);
    FCodec.ConsumeBlock(LContext, TTlsExtensionContextKind.ServerHello,
      LHello.Extensions);

    // the negotiated TLS 1.3 was already confirmed before the cipher suite (above); a
    // TLS 1.3 ServerHello may carry only supported_versions, key_share and pre_shared_key;
    // anything else (e.g. ALPN, which belongs in the encrypted EncryptedExtensions) is
    // unsupported_extension (RFC 8446 4.1.3)
    EnforceTls13ServerHelloExtensions(LHello.Extensions);

    // the selected group must be the one we key-shared (the initial group, or the one
    // a HelloRetryRequest moved us to), checked before decapsulation (RFC 8446 4.2.8)
    if LContext.SelectedKeyShare.Group <> FCurrentGroupCode then
      raise EFatalAlertTlsLibException.CreateRes(
        TTlsAlertDescription.IllegalParameter, @SUnofferedGroup);

    FCurrentGroup.Decapsulate(FEphemeralPrivate,
      LContext.SelectedKeyShare.KeyExchange, LShared);

    // the server accepted a PSK iff it echoed pre_shared_key with our identity index; that
    // index must be within the list we offered (RFC 8446 4.2.11), and the selected suite's
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
    end;
    // a PSK-only client requires the server to select one of its PSKs; a ServerHello that
    // falls through to certificate authentication is a fatal missing_extension (RFC 8446
    // 4.2.11), since there is no certificate trust to fall back on
    if (not FPskAccepted) and FParams.RequirePsk then
      raise EFatalAlertTlsLibException.CreateRes(
        TTlsAlertDescription.MissingExtension, @SPskRequiredNotSelected);
  finally
    LContext.Free;
  end;

  // remember the group the server accepted (our key_share, no HelloRetryRequest needed),
  // so the next initial ClientHello to this server leads with it
  if FParams.SessionCache <> nil then
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
    FSchedule := TTls13KeySchedule.Create(FParams.Provider, FSelectedSuite.Common.Hash,
      FSelectedSuite.Common.KeyLength);
    // psk_dhe_ke: seed the accepted PSK before deriving the handshake secret
    if FPskAccepted then
      FSchedule.SetPsk(FAcceptedPsk.Key);
  end;
  FSchedule.SetSharedSecret(LShared);
  FSchedule.DeriveEpochSecrets(TTlsEpoch.Handshake, FTranscript.CurrentHash);

  FPhase := TPhase.WaitEncryptedExtensions;
  // the middlebox change_cipher_spec goes out first (empty here when 0-RTT already sent
  // it), then the server handshake read keys install
  Result := MiddleboxCcs;
  TArrayUtilities.Append<THandshakeEffect>(Result,
    THandshakeEffects.InstallKeys(FSchedule.TrafficKeys(TTlsEpoch.Handshake,
    TTlsDirection.ServerWrite), TRecordSide.ReadSide, FSelectedSuite.Common.Aead, TTlsVersion.Tls13));
  // with an accepted 0-RTT offer the write side stays on the early keys until
  // EndOfEarlyData (sent at EncryptedExtensions); otherwise switch write to handshake now
  if FEarlyDataOffered and FPskAccepted then
    Exit;
  TArrayUtilities.Append<THandshakeEffect>(Result,
    THandshakeEffects.InstallKeys(FSchedule.TrafficKeys(TTlsEpoch.Handshake,
    TTlsDirection.ClientWrite), TRecordSide.WriteSide, FSelectedSuite.Common.Aead, TTlsVersion.Tls13));
  // a PSK-rejected 0-RTT offer means the early data was ignored: the engine replays it
  if FEarlyDataOffered then
    TArrayUtilities.Append<THandshakeEffect>(Result,
      THandshakeEffects.RaiseEvent(TTlsEventKind.EarlyDataRejected));
end;

function TTls13ClientStateMachine.ProcessEncryptedExtensions(
  const AMessage: TTlsHandshakeMessage): TArray<THandshakeEffect>;
var
  LContext: TExtensionContext;
  LOutbound, LInbound: Int32;
  LServerAcceptedEarly: Boolean;
begin
  Result := nil;
  FTranscript.Update(AMessage.Raw);
  LContext := TExtensionContext.Create;
  try
    // a response extension the client did not offer is fatal (RFC 8446 4.2)
    ApplyOffered(LContext);
    FCodec.ConsumeBlock(LContext, TTlsExtensionContextKind.EncryptedExtensions,
      THandshakeMessages.DecodeEncryptedExtensions(AMessage.Body));
    LServerAcceptedEarly := LContext.EarlyDataAccepted;

    // the server's ALPN choice must be one this client offered (RFC 7301 3.2)
    if LContext.SelectedAlpn <> '' then
    begin
      if not (TArrayUtilities.Contains<string>(FParams.AlpnProtocols,
        LContext.SelectedAlpn)) then
        raise EFatalAlertTlsLibException.CreateRes(
          TTlsAlertDescription.IllegalParameter, @SUnofferedAlpn);
      FNegotiatedAlpn := LContext.SelectedAlpn; // stored on any resumption ticket
      TArrayUtilities.Append<THandshakeEffect>(Result,
        THandshakeEffects.SelectAlpn(LContext.SelectedAlpn));
    end;

    // apply the negotiated record_size_limit (RFC 8449): content-byte caps are the
    // negotiated value less the 1.3 inner content-type byte
    if (LContext.RecordSizeLimit > 0) or (FParams.RecordSizeLimit > 0) then
    begin
      if (LContext.RecordSizeLimit > 0) and (LContext.RecordSizeLimit < 64) then
        raise EFatalAlertTlsLibException.CreateRes(
          TTlsAlertDescription.IllegalParameter, @SBadRecordSizeLimit);
      if LContext.RecordSizeLimit > 0 then
        LOutbound := LContext.RecordSizeLimit - 1
      else
        LOutbound := 0;
      if FParams.RecordSizeLimit > 0 then
        LInbound := FParams.RecordSizeLimit - 1
      else
        LInbound := 0;
      TArrayUtilities.Append<THandshakeEffect>(Result,
        THandshakeEffects.SetRecordSizeLimit(LOutbound, LInbound));
    end;
  finally
    LContext.Free;
  end;
  // 0-RTT resolution (only when we offered it and the PSK was accepted): the write side
  // stays on the early keys here. On accept, EndOfEarlyData and the write switch happen
  // after the server Finished (transcript order); on reject we switch off early now and
  // the engine replays the early data as 1-RTT.
  if FEarlyDataOffered and FPskAccepted then
  begin
    if LServerAcceptedEarly then
    begin
      // 0-RTT is bound to the ticket's exact suite; a server that accepts early data
      // under a different suite than the PSK's is illegal (RFC 8446 4.2.10)
      if not FEarlySuiteMatched then
        raise EFatalAlertTlsLibException.CreateRes(
          TTlsAlertDescription.IllegalParameter, @SEarlyDataSuiteMismatch);
      // 0-RTT is likewise bound to the resumed session's ALPN: when the server accepts early
      // data it MUST negotiate the same ALPN protocol as that session (RFC 8446 4.2.11); a
      // changed (or dropped) protocol is illegal (ALPN_MISMATCH_ON_EARLY_DATA)
      if FNegotiatedAlpn <> FAcceptedPsk.Alpn then
        raise EFatalAlertTlsLibException.CreateRes(
          TTlsAlertDescription.IllegalParameter, @SEarlyDataAlpnMismatch);
      FEarlyDataAccepted := True;
      TArrayUtilities.Append<THandshakeEffect>(Result,
        THandshakeEffects.RaiseEvent(TTlsEventKind.EarlyDataAccepted));
    end
    else
    begin
      TArrayUtilities.Append<THandshakeEffect>(Result,
        THandshakeEffects.RaiseEvent(TTlsEventKind.EarlyDataRejected));
      TArrayUtilities.Append<THandshakeEffect>(Result,
        THandshakeEffects.InstallKeys(FSchedule.TrafficKeys(TTlsEpoch.Handshake,
        TTlsDirection.ClientWrite), TRecordSide.WriteSide, FSelectedSuite.Common.Aead,
        TTlsVersion.Tls13));
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
  LClientHello2: TBytes;
  LOffered: TArray<UInt16>;
  LCh1Hash: IHash;
  LEarlyDataWasOffered: Boolean;
begin
  // at most one HelloRetryRequest per handshake (RFC 8446 4.1.4)
  if FRetried then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.UnexpectedMessage, @SHelloRetryTwice);

  // the selected suite must be one we offered (RFC 8446 4.1.3)
  if not (TArrayUtilities.Contains<UInt16>(FParams.OfferedSuites, AHello.CipherSuite)) then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.IllegalParameter, @SUnofferedSuite);
  if not FParams.CipherSuites.TryGet(AHello.CipherSuite, FSelectedSuite) then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.IllegalParameter, @SUnknownSelectedSuite);
  if not TArrayUtilities.AreEqual(AHello.LegacySessionIdEcho, FSentLegacySessionId) then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.IllegalParameter, @SBadSessionIdEcho);

  // the cipher (hence hash) is now fixed: drop any offered PSK bound to a different hash, so
  // the second ClientHello offers only the still-eligible PSKs (RFC 8446 4.1.4). A single
  // resumption offer already matches; a multi-hash external offer shrinks to one entry.
  PruneOffersToHash(FSelectedSuite.Common.Hash);

  // the hash is known: rebase the transcript to message_hash(Hash(ClientHello1)) under the
  // retry-selected hash (RFC 8446 4.4.1), computed from the RAW first ClientHello. Using the
  // raw bytes keeps this correct even when a single-PSK resumption pre-activated the transcript
  // under a different hash the retry then rejects (a non-resumable-cipher HRR). Then add the HRR.
  LCh1Hash := FParams.Provider.CreateHash(FSelectedSuite.Common.Hash);
  LCh1Hash.Update(FSentClientHelloRaw, 0, System.Length(FSentClientHelloRaw));
  FTranscript.SeedWithMessageHash(
    FParams.Provider.CreateHash(FSelectedSuite.Common.Hash), LCh1Hash.DoFinal);
  FTranscript.Update(AMessage.Raw);
  // the retry-selected hash is now the transcript's hash, so the pre-activation reconciliation
  // (the different-PRF rebuild in ProcessServerHello) no longer applies to the next ServerHello
  FTranscriptPreActivated := False;

  LContext := TExtensionContext.Create;
  try
    // the cookie is the response the client did not offer but must accept in a HRR
    ApplyOffered(LContext);
    LContext.MarkOffered(TExtensionTypes.Cookie);
    FCodec.ConsumeBlock(LContext, TTlsExtensionContextKind.HelloRetryRequest,
      AHello.Extensions);

    // a HelloRetryRequest may request a different key_share group, or carry only a cookie
    // (RFC 8446 4.1.4). When it names a group, it must be one we advertised and must differ
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
      // must produce some change, else it is illegal (RFC 8446 4.1.4)
      raise EFatalAlertTlsLibException.CreateRes(
        TTlsAlertDescription.IllegalParameter, @SHelloRetryNoChange);
    FCookie := LContext.Cookie;
    FRetried := True;
  finally
    LContext.Free;
  end;

  // a HelloRetryRequest rejects any offered 0-RTT (RFC 8446 4.2.10): the second ClientHello
  // MUST NOT re-offer early_data, so clear the offer before rebuilding it
  LEarlyDataWasOffered := FEarlyDataOffered;
  FEarlyDataOffered := False;

  LClientHello2 := BuildClientHello;
  // recompute the binder over the retry transcript (message_hash(CH1), HRR, this
  // ClientHello up to the binders): the first flight's binder does not vouch for it
  if System.Length(FPskOffers) > 0 then
    PatchBinder(LClientHello2);
  RememberOffered(LClientHello2);
  FTranscript.Update(LClientHello2);
  FPhase := TPhase.WaitServerHello;
  // on a retry the client's second flight is the second ClientHello, so the middlebox
  // change_cipher_spec goes immediately before it (RFC 8446 D.4)
  Result := MiddleboxCcs;
  // when this ClientHello had opened the 0-RTT write window, the early data is now rejected:
  // signal it and drop the write epoch back to plaintext so the second ClientHello onward is
  // sent in the clear (the middlebox change_cipher_spec was already emitted with the first flight)
  if LEarlyDataWasOffered then
  begin
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
  LSeenCertExtTypes: TArray<UInt16>;
  LAlert: TTlsAlertDescription;
begin
  LCert := THandshakeMessages.DecodeCertificate(ACertificateBody);
  if System.Length(LCert.Entries) = 0 then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.DecodeError, @SEmptyCertificate);
  // RFC 8446 4.4.2: a leaf CertificateEntry extension must correspond to one offered in the
  // ClientHello, and only status_request / SCT are defined for a certificate entry; an
  // unsolicited or unknown extension is unsupported_extension. Intermediate entries' extensions
  // are allowed but ignored.
  LSeenCertExtTypes := nil;
  for LExtType in THandshakeMessages.CertificateEntryExtensionTypes(
    LCert.Entries[0].Extensions) do
  begin
    // a repeated extension in a CertificateEntry is illegal (RFC 8446 4.2), reported before
    // the solicitation check so a duplicated - even solicited - extension is caught as the
    // duplicate it is (consistent with the ClientHello/ServerHello duplicate-extension policy)
    if TArrayUtilities.Contains<UInt16>(LSeenCertExtTypes, LExtType) then
      raise EFatalAlertTlsLibException.CreateRes(
        TTlsAlertDescription.IllegalParameter, @SDuplicateCertExtension);
    TArrayUtilities.Append<UInt16>(LSeenCertExtTypes, LExtType);
    if not (((LExtType = StatusRequestExtensionCode) or (LExtType = SctExtensionCode)) and
      (TArrayUtilities.Contains<UInt16>(FOfferedExtensions, LExtType))) then
      raise EFatalAlertTlsLibException.CreateRes(
        TTlsAlertDescription.UnsupportedExtension, @SUnsolicitedCertExtension);
  end;
  // keep the chain (leaf first) for the CertificateVerify and the trust verdict
  FCertificateChain := nil;
  SetLength(FCertificateChain, System.Length(LCert.Entries));
  for LI := 0 to High(LCert.Entries) do
    FCertificateChain[LI] := LCert.Entries[LI].CertData;

  // a server leaf that is not a well-formed certificate is a decode error, caught before
  // the CertificateVerify signature check and the trust verdict
  TCertificateVerify.EnsureWellFormedLeaf(FParams.Provider, FCertificateChain[0]);

  // capture any stapled OCSP response carried in the leaf entry (RFC 8446 4.4.2.1)
  FReceivedOcspStaple := nil;
  THandshakeMessages.TryExtractLeafStaple(LCert.Entries[0].Extensions,
    FReceivedOcspStaple);

  // the trust verdict is fail-closed: no configured verifier, or a negative verdict,
  // aborts the handshake with the reason's alert
  if FParams.CertificateVerifier = nil then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.InternalError, @SNoCertificateVerifier);
  if not FParams.CertificateVerifier.Verify(FCertificateChain,
    FParams.ExpectedHostName, FReceivedOcspStaple, LAlert) then
    raise EFatalAlertTlsLibException.CreateRes(LAlert, @SUntrustedCertificate);

  // the on-the-wire message (compressed, when compressed) is what feeds the transcript
  FTranscript.Update(ATranscriptRaw);
  FPhase := TPhase.WaitCertificateVerify;
  // surface the validated chain for connection info (read-only; both inline and async paths)
  Result := TArray<THandshakeEffect>.Create(
    THandshakeEffects.PeerCertificateChain(FCertificateChain));
  // surface any accepted staple so an integration can inspect it
  if System.Length(FReceivedOcspStaple) > 0 then
    TArrayUtilities.Append<THandshakeEffect>(Result,
      THandshakeEffects.PeerOcspStaple(FReceivedOcspStaple));
  // async verdict: the pipeline has accepted the chain; park for the host's out-of-band
  // decision. The rest of the flight stays buffered until SetCertificateVerdict resumes it.
  if FParams.AsyncVerdict then
    TArrayUtilities.Append<THandshakeEffect>(Result,
      THandshakeEffects.AwaitCertificateVerdict(FCertificateChain,
      FParams.ExpectedHostName));
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
  // decompression runs through the injected decompressors under one bomb defense
  // (declared-length ceiling, ratio guard, exact-length match)
  LCertificateBody := TCertificateCompression.Decompress(
    FParams.CertificateDecompressors, LCompressed.Algorithm,
    LCompressed.Compressed, LCompressed.UncompressedLength);
  Result := HandleCertificate(LCertificateBody, AMessage.Raw);
end;

procedure TTls13ClientStateMachine.VerifyCertificateVerify(
  const AMessage: TTlsHandshakeMessage);
var
  LCertVerify: TTlsCertificateVerify;
  LScheme: TSignatureScheme;
  LContent, LPublicKeyInfo: TBytes;
  LVerifier: ISignatureVerifier;
begin
  LCertVerify := THandshakeMessages.DecodeCertificateVerify(AMessage.Body);
  // the server must sign with a scheme the client offered
  if not (TArrayUtilities.Contains<UInt16>(FParams.OfferedSchemes,
    LCertVerify.Algorithm)) then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.IllegalParameter, @SUnofferedScheme);
  if not TSignatureScheme.TryFromCode(LCertVerify.Algorithm, LScheme) then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.IllegalParameter, @SUnofferedScheme);
  // rsa_pkcs1_* are certificate-only in TLS 1.3: they may be offered for backward
  // compatibility but MUST NOT sign a CertificateVerify (RFC 8446 4.2.3)
  if not LScheme.IsValidForHandshake(TTlsVersion.Tls13) then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.IllegalParameter, @SLegacyPkcs1InTls13);

  // the server leaf must permit digitalSignature and, for an rsa_pss_rsae_* scheme, not
  // be an id-RSASSA-PSS key (shared with the server verifying the client leaf)
  TCertificateVerify.EnforceSigningLeafPolicy(FParams.Provider,
    FCertificateChain[0], LScheme, True);

  // the signature is over the transcript through the Certificate (this message not yet folded in)
  LContent := TCertificateVerify.SignatureContent(True, FTranscript.CurrentHash);
  LPublicKeyInfo := FParams.Provider.CertificatePublicKeyInfo(FCertificateChain[0]);
  LVerifier := FParams.Provider.CreateSignatureVerifier(LScheme, LPublicKeyInfo);
  LVerifier.Update(LContent, 0, System.Length(LContent));
  if not LVerifier.Verify(LCertVerify.Signature) then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.DecryptError, @SBadCertificateVerify);
end;

procedure TTls13ClientStateMachine.ProcessCertificateRequest(
  const AMessage: TTlsHandshakeMessage);
var
  LRequest: TTlsCertificateRequest13;
  LContext: TExtensionContext;
begin
  LRequest := THandshakeMessages.DecodeCertificateRequest13(AMessage.Body);
  // the certificate_request_context is zero-length in the handshake CertificateRequest;
  // a non-empty one is only valid in post-handshake auth, which is not offered (RFC 8446 4.3.2)
  if System.Length(LRequest.RequestContext) <> 0 then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.DecodeError, @SRequestContextNotEmpty);
  FRequestContext := LRequest.RequestContext;
  LContext := TExtensionContext.Create;
  try
    // signature_algorithms is expected inside a CertificateRequest (RFC 8446 4.3.2)
    LContext.MarkOffered(TExtensionTypes.SignatureAlgorithms);
    FCodec.ConsumeBlock(LContext, TTlsExtensionContextKind.CertificateRequest,
      LRequest.Extensions);
    FClientAuthSchemes := LContext.SignatureSchemes;
    FRequestedCertificateAuthorities := LContext.CertificateAuthorities;
  finally
    LContext.Free;
  end;
  FCertificateRequested := True;
  FTranscript.Update(AMessage.Raw);
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
  // choose a credential scheme the server accepts; with no credential at all the client
  // legitimately declines with an empty Certificate
  LHasScheme := False;
  if System.Length(FParams.ClientCredential.CertificateChain) > 0 then
  begin
    for LScheme in FParams.ClientCredential.PrivateKey.CapableSchemes do
      if LScheme.IsValidForHandshake(TTlsVersion.Tls13) and
        (TArrayUtilities.Contains<UInt16>(FClientAuthSchemes, LScheme.ToCode)) then
      begin
        LHasScheme := True;
        Break;
      end;
    // a credential is configured but none of its schemes satisfies the server's
    // signature_algorithms: fail rather than decline
    if not LHasScheme then
      raise EFatalAlertTlsLibException.CreateRes(
        TTlsAlertDescription.HandshakeFailure, @SNoClientAuthScheme);
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
  LCertBytes := THandshakeFraming.Frame(TTlsHandshakeType.Certificate,
    THandshakeMessages.EncodeCertificate(LCert));
  FTranscript.Update(LCertBytes);
  TArrayUtilities.Append<THandshakeEffect>(AEffects,
    THandshakeEffects.SendHandshake(LCertBytes));

  if not LHasScheme then
    Exit;
  // the CertificateVerify signs the transcript through the client Certificate
  LContent := TCertificateVerify.SignatureContent(False, FTranscript.CurrentHash);
  LSigner := FParams.Provider.CreateSignatureSigner(LScheme,
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

function TTls13ClientStateMachine.ProcessServerFinished(
  const AMessage: TTlsHandshakeMessage): TArray<THandshakeEffect>;
var
  LHashBeforeFinished, LHashAfterFinished, LClientVerifyData, LClientFinished,
    LEndOfEarlyData: TBytes;
begin
  // the server Finished is over the transcript EXCLUDING itself
  LHashBeforeFinished := FTranscript.CurrentHash;
  if not FSchedule.VerifyFinished(TTlsDirection.ServerWrite, LHashBeforeFinished,
    AMessage.Body) then
    raise EFatalAlertTlsLibException.CreateRes(TTlsAlertDescription.DecryptError,
      @SBadServerFinished);
  FTranscript.Update(AMessage.Raw);

  // application secrets are over the transcript through the server Finished (before any
  // EndOfEarlyData or the client Finished)
  LHashAfterFinished := FTranscript.CurrentHash;
  FSchedule.DeriveEpochSecrets(TTlsEpoch.Application, LHashAfterFinished);

  Result := nil;
  // accepted 0-RTT: EndOfEarlyData (under the early keys) closes early data and folds
  // into the transcript, then the write side moves to the handshake keys (RFC 8446 4.5)
  if FEarlyDataAccepted then
  begin
    LEndOfEarlyData := THandshakeFraming.Frame(TTlsHandshakeType.EndOfEarlyData, nil);
    FTranscript.Update(LEndOfEarlyData);
    TArrayUtilities.Append<THandshakeEffect>(Result,
      THandshakeEffects.SendHandshake(LEndOfEarlyData));
    TArrayUtilities.Append<THandshakeEffect>(Result,
      THandshakeEffects.InstallKeys(FSchedule.TrafficKeys(TTlsEpoch.Handshake,
      TTlsDirection.ClientWrite), TRecordSide.WriteSide, FSelectedSuite.Common.Aead,
      TTlsVersion.Tls13));
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
  // the resumption master secret (for caching future tickets) is over the transcript
  // through the client Finished
  FResumptionTranscriptHash := FTranscript.CurrentHash;

  FPhase := TPhase.Connected;
  // the client auth flight and Finished are sent under the handshake write keys, THEN
  // the write side moves to the application keys - order matters
  TArrayUtilities.Append<THandshakeEffect>(Result,
    THandshakeEffects.SendHandshake(LClientFinished));
  TArrayUtilities.Append<THandshakeEffect>(Result,
    THandshakeEffects.InstallKeys(FSchedule.TrafficKeys(TTlsEpoch.Application,
    TTlsDirection.ClientWrite), TRecordSide.WriteSide, FSelectedSuite.Common.Aead,
    TTlsVersion.Tls13));
  TArrayUtilities.Append<THandshakeEffect>(Result,
    THandshakeEffects.InstallKeys(FSchedule.TrafficKeys(TTlsEpoch.Application,
    TTlsDirection.ServerWrite), TRecordSide.ReadSide, FSelectedSuite.Common.Aead,
    TTlsVersion.Tls13));
  TArrayUtilities.Append<THandshakeEffect>(Result,
    THandshakeEffects.ConnectionParams(FSelectedSuite.Common.Code,
    FCurrentGroupCode, FPskAccepted, FParams.ServerName));
  if System.Length(FRequestedCertificateAuthorities) > 0 then
    TArrayUtilities.Append<THandshakeEffect>(Result,
      THandshakeEffects.RequestedCertificateAuthorities(
      FRequestedCertificateAuthorities));
  TArrayUtilities.Append<THandshakeEffect>(Result,
    THandshakeEffects.HandshakeEstablished);
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
      // and keep waiting for the Certificate (RFC 8446 4.3.2)
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
      begin
        // verify the proof-of-possession over the transcript through Certificate,
        // then fold the message in
        VerifyCertificateVerify(AMessage);
        FTranscript.Update(AMessage.Raw);
        FPhase := TPhase.WaitServerFinished;
        Result := nil;
      end
      else
        Result := Unexpected;
    TPhase.WaitServerFinished:
      if LKnown and (LType = TTlsHandshakeType.Finished) then
        Result := ProcessServerFinished(AMessage)
      else
        Result := Unexpected;
    TPhase.Connected:
      // post-handshake: a NewSessionTicket is cached (RFC 8446 4.6.1), a KeyUpdate rekeys
      // the read epoch and may trigger one responding update (RFC 8446 4.6.3)
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

end.
