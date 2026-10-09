{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpTls12ServerStateMachine;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  Classes,
  TlpArrayUtilities,
  TlpTlsAlert,
  TlpTlsVersion,
  TlpTlsLibExceptions,
  TlpISecretBuffer,
  TlpISigningKey,
  TlpICryptoProvider,
  TlpIPkixProvider,
  TlpINamedGroup,
  TlpIKeyExchangePrivateKey,
  TlpIKeySchedule,
  TlpTls12KeySchedule,
  TlpITranscriptHash,
  TlpCryptoDomainTypes,
  TlpNegotiationTypes,
  TlpINegotiation,
  TlpNegotiationPolicy,
  TlpExtensionContext,
  TlpITlsExtension,
  TlpHandshakeMessage,
  TlpHandshakeMessages,
  TlpCertificateVerify,
  TlpPeerAuthentication,
  TlpICertificateTrust,
  TlpTrustTypes,
  TlpTlsCredential,
  TlpITlsCredentialResolver,
  TlpServerOfferSelection,
  TlpClientSessionPolicy,
  TlpISession,
  TlpIClock,
  TlpIKeyLog,
  TlpSession,
  TlpSessionTicketStrategy,
  TlpHandshakeEffect,
  TlpHandshakeStage,
  TlpHandshakeMachineBase;

type
  /// <summary>The inputs a TLS 1.2 server handshake needs to negotiate and drive its flight.</summary>
  TServer12HandshakeParams = record
    Crypto: ICryptoProvider;
    Inspector: ICertificateInspector;
    CipherSuites: ICipherSuiteRegistry;
    /// <summary>The suite-selection authority, shared with the 1.3 server so the configured
    /// cipher preference (server order, or client order) governs a 1.2 handshake identically.</summary>
    Policy: INegotiationPolicy;
    ExtensionRegistry: IExtensionRegistry;
    /// <summary>Resolves the ECDHE group code the negotiation policy selects to its INamedGroup;
    /// required when Group is nil (the normal factory path).</summary>
    GroupRegistry: INamedGroupRegistry;
    /// <summary>Pins a single fixed ECDHE group (the low-level sans-IO entry point; tests). When
    /// nil the negotiation policy selects by server preference among the client's supported_groups,
    /// resolved via GroupRegistry.</summary>
    Group: INamedGroup;
    ServerRandom: TBytes;
    /// <summary>Selects the credential (per handshake, from the client's SNI - virtual hosting)
    /// the Certificate chain is sent from and whose private key signs the ServerKeyExchange under
    /// the negotiated scheme. When the client offered status_request, the server echoes an empty
    /// status_request in the ServerHello and sends a CertificateStatus message (RFC 6066 8)
    /// carrying the selected credential's OCSP staple. nil for a PSK-only server.</summary>
    CredentialResolver: ITlsServerCredentialResolver;
    /// <summary>When a 1.3-capable server negotiates 1.2 it stamps the RFC 8446 4.1.3
    /// downgrade sentinel into the last 8 bytes of the server random.</summary>
    EmitDowngradeSentinel: Boolean;
    /// <summary>When set, a client that did not offer extended_master_secret (RFC 7627)
    /// is refused rather than falling back to a plain master secret.</summary>
    RequireExtendedMasterSecret: Boolean;
    /// <summary>How a resumption of a session established without extended_master_secret is
    /// treated when the new hello does not offer it either (RFC 7627 5.3); Decline when
    /// unassigned. Decline and Abort also stop issuing resumable sessions from a non-EMS
    /// full handshake.</summary>
    NonEmsResumption: TNonEmsResumption;
    /// <summary>Whether the server echoes the empty server_name acknowledgement (RFC 6066 3)
    /// when the client offered a host_name.</summary>
    ServerNameAck: Boolean;
    /// <summary>Whether the server rejects any client ALPN offer with no_application_protocol
    /// (RFC 7301) instead of selecting or declining.</summary>
    AlpnRejectAll: Boolean;
    /// <summary>The server's ALPN preferences (RFC 7301); the first that the client also
    /// offered is selected and echoed in the ServerHello. Empty declines ALPN.</summary>
    AlpnProtocols: TArray<string>;
    /// <summary>Whether the server requests a client certificate (mutual TLS) and how
    /// strictly it is enforced.</summary>
    ClientAuth: TClientAuthMode;
    /// <summary>The signature algorithms advertised in CertificateRequest and accepted
    /// for the client CertificateVerify (RFC 5246 7.4.4).</summary>
    ClientAuthSignatureSchemes: TArray<UInt16>;
    /// <summary>The DER-encoded DistinguishedName issuers named in the CertificateRequest's
    /// certificate_authorities (RFC 5246 7.4.4); empty names none.</summary>
    ClientCertificateAuthorities: TArray<TBytes>;
    /// <summary>Trusts (or rejects) the client certificate chain; required whenever
    /// ClientAuth is not None.</summary>
    ClientCertificateVerifier: IClientCertificateVerifier;
    /// <summary>How a peer-certificate verdict is deferred out-of-band (see TVerdictDeferral):
    /// augment-only and fail-closed, None by default.</summary>
    Deferral: TVerdictDeferral;
    /// <summary>The stateful store backing TLS 1.2 session-id resumption (RFC 5246 7.3):
    /// on a full handshake the server echoes a fresh session id and stores the session
    /// under it, then resumes on a later ClientHello that offers it. nil disables the
    /// session-id path.</summary>
    SessionStore: ISessionStore;
    /// <summary>The session-ticket keys backing stateless RFC 5077 ticket resumption: the
    /// server seals the session under the current key and re-presents it in a
    /// NewSessionTicket. nil disables ticket issuance.</summary>
    SessionTicketKeys: ISessionTicketKeyManager;
    /// <summary>An opaque scope sealed into issued tickets/sessions and required to match on
    /// resumption, partitioning configurations that share a ticket key or store; empty does not
    /// partition.</summary>
    ResumptionScope: TBytes;
    /// <summary>The lifetime advertised for issued sessions and tickets, in seconds.</summary>
    TicketLifetimeSeconds: UInt32;
    /// <summary>The clock read for a cached session's issue time and freshness (RFC 5077). A
    /// required input, like Crypto: the engine factory supplies one from the config, and a
    /// direct sans-IO caller must set it.</summary>
    Clock: ITlsClock;
    /// <summary>The dangerous key-log sink; nil reports nothing.</summary>
    KeyLog: IKeyLog;
    /// <summary>The record_size_limit (RFC 8449) plaintext value the server advertises in its
    /// ServerHello, in [64, 2^14], echoed only when the client offered one; 0 disables it.</summary>
    RecordSizeLimit: Int32;
  end;

  /// <summary>
  /// The hardened TLS 1.2 server machine (RFC 5246 + RFC 4492/8422 ECDHE + RFC 7627
  /// Extended Master Secret). It kicks on the ClientHello: it negotiates an AEAD ECDHE
  /// suite and a signature scheme its credential can produce, sends ServerHello,
  /// Certificate, a signed ServerKeyExchange and ServerHelloDone, then on the client's
  /// ClientKeyExchange derives the (extended) master secret and key block, and finally
  /// verifies the client Finished and sends its own. It returns effects and never
  /// touches the record layer.
  /// </summary>
  TTls12ServerStateMachine = class sealed(THandshakeMachineBase)
  strict private
  type
    TPhase = (Initial, WaitClientCertificate, WaitClientKeyExchange,
      WaitClientCertVerify, WaitClientFinished, WaitAbbreviatedClientFinished,
      Connected);
  var
    FParams: TServer12HandshakeParams;
    FPhase: TPhase;
    FClientRandom: TBytes;
    FServerRandom: TBytes;
    FGroupCode: UInt16;
    FSelectedGroup: INamedGroup;
    FEcdhePrivate: IKeyExchangePrivateKey;
    FEcdhePublic: TBytes;
    FUseExtendedMasterSecret: Boolean;
    FEchoRenegotiationInfo: Boolean;
    FClientSentServerName: Boolean;
    // the credential the resolver selected for this handshake, from the client's SNI
    FResolvedCredential: TTlsCredential;
    FRequestedServerName: string;
    FSelectedScheme: TSignatureScheme;
    FSchedule: ITls12KeySchedule;
    /// <summary>The stateless ticket strategy (STEK) when configured; session-id
    /// resumption uses FParams.SessionStore directly.</summary>
    FTicketStrategy: ISessionTicketStrategy;
    /// <summary>The session id echoed in the ServerHello: freshly generated for a full
    /// handshake with a store, or the id the client offered on an abbreviated handshake.</summary>
    FSessionId: TBytes;
    /// <summary>Whether the client offered the session_ticket extension (RFC 5077).</summary>
    FClientOfferedSessionTicket: Boolean;
    /// <summary>Whether the client offered status_request (RFC 6066).</summary>
    FStatusRequestOffered: Boolean;
    /// <summary>The client's offered record_size_limit (RFC 8449); 0 when unoffered. The server
    /// echoes its own limit only when this is non-zero.</summary>
    FPeerRecordSizeLimit: Int32;
    /// <summary>Whether the server will staple: the client offered status_request and a
    /// staple is configured. Drives the ServerHello echo and the CertificateStatus message.</summary>
    FWillStaple: Boolean;
    /// <summary>Whether a NewSessionTicket is issued (echoed as an empty session_ticket).</summary>
    FIssueNewTicket: Boolean;
    /// <summary>The application protocol selected from the client's ALPN offer, or empty when
    /// none was offered/configured (RFC 7301); echoed in the ServerHello.</summary>
    FSelectedAlpn: string;
    /// <summary>Resumption state: whether the handshake resumes, and the accepted session.</summary>
    FResuming: Boolean;
    FResumedSession: ITls12ResumableSession;
    /// <summary>The client's certificate chain (leaf first) and whether it sent one, for
    /// the client CertificateVerify and the required-auth policy.</summary>
    FClientCertChain: TArray<TBytes>;
    // the client leaf parsed once for the well-formed gate, reused for the signing-policy
    // check and its SubjectPublicKeyInfo; released once the signature is verified
    FParsedClientLeaf: IInspectedCertificate;
    FClientSentCertificate: Boolean;
    /// <summary>The raw concatenation of every handshake message, which the TLS 1.2
    /// client CertificateVerify is signed over (RFC 5246 7.4.8) - its scheme hashes this,
    /// independent of the suite PRF hash the transcript uses.</summary>
    FHandshakeLog: TBytesStream;
    /// <summary>Selects the first registry 1.2 suite the client offered whose auth the
    /// credential can satisfy against the client's signature_algorithms; sets
    /// FSelectedSuite and FSelectedScheme. False when nothing is compatible.</summary>
    function SelectSuiteAndScheme(const AClientSuites, AClientSchemes: TArray<UInt16>;
      AEcdsaAuthEligible: Boolean; out ASuite: TTlsCipherSuite;
      out AScheme: TSignatureScheme): Boolean;
    /// <summary>Chooses the ECDHE group (into FSelectedGroup/FGroupCode): the first
    /// server-preferred group the client also advertised, tolerating unknown/non-ECDHE
    /// codes by skipping them. Aborts with handshake_failure when none is common.</summary>
    procedure SelectEcdheGroup(const AClientGroups: TArray<UInt16>);
    /// <summary>Whether an ECDSA-authenticated suite may be selected: true unless the
    /// leaf credential is ECDSA and its curve is absent from the client's supported_groups
    /// (RFC 8422 5.3 / 5.1). A non-ECDSA leaf is unconstrained here.</summary>
    function EcdsaCredentialCurveOffered(const AClientGroups: TArray<UInt16>): Boolean;
    /// <summary>Whether AScheme's signature algorithm matches the suite auth method.</summary>
    class function SchemeMatchesAuth(AScheme: TSignatureScheme;
      AAuth: TAuthMethod): Boolean; static;
    /// <summary>Folds a message into both the transcript hash and the raw handshake log.</summary>
    procedure Absorb(const ARaw: TBytes);
    /// <summary>Installs the read side (client write keys) once the client's plaintext
    /// flight is complete.</summary>
    function InstallReadKeys: THandshakeEffect;
    function ProcessClientHello(const AMessage: TTlsHandshakeMessage)
      : TArray<THandshakeEffect>;
    function ProcessClientCertificate(const AMessage: TTlsHandshakeMessage)
      : TArray<THandshakeEffect>;
    function ProcessClientKeyExchange(const AMessage: TTlsHandshakeMessage)
      : TArray<THandshakeEffect>;
    function ProcessClientCertVerify(const AMessage: TTlsHandshakeMessage)
      : TArray<THandshakeEffect>;
    function ProcessClientFinished(const AMessage: TTlsHandshakeMessage)
      : TArray<THandshakeEffect>;
    /// <summary>Attempts to resume a TLS 1.2 session from the offered ticket (RFC 5077)
    /// or session id (RFC 5246). Validates version, freshness, suite and Extended Master
    /// Secret consistency; a mismatch returns False so the caller falls through to a full
    /// handshake, except that an EMS session offered without EMS raises (RFC 7627 5.3), as does a
    /// non-EMS session under the Abort policy; a non-EMS session under Decline falls through. On
    /// success it fixes the suite, EMS use and the echoed session id.</summary>
    function TryAcceptResumption(const AHello: TTlsClientHello;
      const AContext: TExtensionContext): Boolean;
    /// <summary>Sends the abbreviated server flight (ServerHello, an optional
    /// NewSessionTicket, ChangeCipherSpec, Finished) reusing the resumed master secret,
    /// and installs the write and read epochs.</summary>
    function EmitAbbreviatedFlight(const AClientHelloRaw: TBytes)
      : TArray<THandshakeEffect>;
    function ProcessAbbreviatedClientFinished(const AMessage: TTlsHandshakeMessage)
      : TArray<THandshakeEffect>;
    /// <summary>Seals the current session under the STEK and frames a NewSessionTicket
    /// (RFC 5077 3.3), with a freshly stamped issue time; frames a zero-length ticket when the
    /// strategy declines to seal.</summary>
    function BuildNewSessionTicketMessage: TBytes;
    /// <summary>The configured ticket lifetime, capped at the RFC 8446 4.6.1 ceiling.</summary>
    function EmittedTicketLifetime: UInt32;
    /// <summary>The resumable session for the current connection, under ASessionId.</summary>
    function BuildStoredSession(const ASessionId: TBytes): IResumableSession;
    function BuildServerHello: TBytes;
    procedure StampServerRandom;
    function BuildCertificate: TBytes;
    function BuildCertificateRequest: TBytes;
    function BuildServerKeyExchange: TBytes;
    function SignServerParams(const AParams: TBytes): TBytes;
    procedure DeriveSecrets(const APreMaster: ISecretBuffer;
      const ASessionHash: TBytes);
  strict protected
    function Route(const AMessage: TTlsHandshakeMessage)
      : TArray<THandshakeEffect>; override;
  public
    constructor Create(const AParams: TServer12HandshakeParams);
    destructor Destroy; override;
    function Start: TArray<THandshakeEffect>; override;
    function ExportKeyingMaterial(const ALabel: string;
      ALength: Int32): TBytes; overload; override;
    function ExportKeyingMaterial(const ALabel: string; const AContext: TBytes;
      ALength: Int32): TBytes; overload; override;
    function CanExportKeyingMaterial: Boolean; override;
  end;

implementation

resourcestring
  SClockRequired = 'a clock is required (the handshake reads time for tickets and freshness)';
  SNoTls12Offered = 'the client offered no protocol version this server supports';
  SNoCompatibleSuite =
    'no mutually supported TLS 1.2 ECDHE suite the credential can authenticate';
  SNoSignatureAlgorithms = 'the client offered no signature_algorithms';
  SBadRecordSizeLimit = 'the client record_size_limit is below the 64-byte minimum';
  SGroupNotOffered = 'the client did not offer the server''s ECDHE group';
  SGroupNotEcdhe = 'the configured 1.2 group is not an ECDHE group';
  SGroupNotResolvable = 'the selected ECDHE group has no registered key agreement';
  SPolicyRequired = 'a negotiation policy is required (it selects the suite and the group)';
  SNoExtendedMasterSecret =
    'the client did not offer extended_master_secret and it is required';
  SNonEmsResumptionRefused =
    'a session established without extended_master_secret is not resumed (RFC 7627 5.3)';
  SBadClientFinished = 'the client Finished did not verify';
  SClientCertificateRequired = 'client authentication is required but none was sent';
  SUntrustedClientCertificate = 'the client certificate chain was not trusted';
  SResumedEmsDowngrade =
    'a session established with extended_master_secret cannot resume without it (RFC 7627 5.3)';

const
  SessionIdLength = Int32(32);

{ TTls12ServerStateMachine }

constructor TTls12ServerStateMachine.Create(const AParams: TServer12HandshakeParams);
begin
  inherited Create(AParams.ExtensionRegistry);
  if AParams.Clock = nil then
    raise EArgumentTlsLibException.CreateRes(@SClockRequired);
  if AParams.Policy = nil then
    raise EArgumentTlsLibException.CreateRes(@SPolicyRequired);
  FParams := AParams;
  FPhase := TPhase.Initial;
  FSelectedGroup := AParams.Group;
  if AParams.Group <> nil then
    FGroupCode := AParams.Group.Code;
  // TLS 1.2 tickets are stateless STEK only; the session-id path uses SessionStore
  FTicketStrategy := TSessionTicketStrategies.ForServer(AParams.Crypto,
    AParams.SessionTicketKeys, nil);
  FHandshakeLog := TBytesStream.Create;
end;

destructor TTls12ServerStateMachine.Destroy;
begin
  FHandshakeLog.Free;
  inherited Destroy;
end;

function TTls12ServerStateMachine.Start: TArray<THandshakeEffect>;
begin
  // a server does not initiate; it starts on the ClientHello
  Result := nil;
end;

class function TTls12ServerStateMachine.SchemeMatchesAuth(
  AScheme: TSignatureScheme; AAuth: TAuthMethod): Boolean;
begin
  case AAuth of
    TAuthMethod.Ecdsa:
      // an ECDHE_ECDSA suite accepts an ECDSA or an EdDSA (Ed25519/Ed448) credential: RFC 8422
      // 2.1 requires the certificate to hold an "ECDSA- or EdDSA-capable public key"
      Result := AScheme in [TSignatureScheme.ECDSA_SECP256R1_SHA256,
        TSignatureScheme.ECDSA_SECP384R1_SHA384,
        TSignatureScheme.ECDSA_SECP521R1_SHA512, TSignatureScheme.ED25519,
        TSignatureScheme.ED448];
    TAuthMethod.Rsa:
      // an ECDHE_RSA suite signs the ServerKeyExchange with an rsaEncryption key: TLS 1.2
      // accepts RSA-PSS and the legacy RSASSA-PKCS1-v1_5 schemes (RFC 5246 / RFC 8446 4.2.3)
      Result := AScheme in [TSignatureScheme.RSA_PSS_RSAE_SHA256,
        TSignatureScheme.RSA_PSS_RSAE_SHA384, TSignatureScheme.RSA_PSS_RSAE_SHA512,
        TSignatureScheme.RSA_PKCS1_SHA256, TSignatureScheme.RSA_PKCS1_SHA384,
        TSignatureScheme.RSA_PKCS1_SHA512];
  else
    Result := False;
  end;
end;

function TTls12ServerStateMachine.SelectSuiteAndScheme(
  const AClientSuites, AClientSchemes: TArray<UInt16>; AEcdsaAuthEligible: Boolean;
  out ASuite: TTlsCipherSuite; out AScheme: TSignatureScheme): Boolean;
var
  LCode: UInt16;
  LSuite: TTlsCipherSuite;
  LScheme: TSignatureScheme;
  LCandidates: TArray<UInt16>;
begin
  Result := False;
  // the mutually supported 1.2 suites in the configured preference order, so
  // WithCipherSuitePreference - server or client order - governs 1.2 exactly as 1.3
  LCandidates := FParams.Policy.CandidateSuites(AClientSuites, TlsWireVersionTls12);
  // a candidate is eligible only if the client offered it and the credential can sign its auth
  // with a scheme the client also offered
  for LCode in LCandidates do
  begin
    if not FParams.CipherSuites.TryGet(LCode, LSuite) then
      Continue;
    if LSuite.Protocol <> TSuiteProtocol.Tls12 then
      Continue;
    if not (TArrayUtilities.Contains<UInt16>(AClientSuites, LSuite.Common.Code)) then
      Continue;
    // an ECDSA suite is ineligible when the leaf's curve is not in supported_groups
    if (LSuite.Auth = TAuthMethod.Ecdsa) and not AEcdsaAuthEligible then
      Continue;
    for LScheme in FResolvedCredential.PrivateKey.CapableSchemes do
      if SchemeMatchesAuth(LScheme, LSuite.Auth) and
        (TArrayUtilities.Contains<UInt16>(AClientSchemes, LScheme.ToCode)) then
      begin
        ASuite := LSuite;
        AScheme := LScheme;
        Exit(True);
      end;
  end;
end;

procedure TTls12ServerStateMachine.SelectEcdheGroup(
  const AClientGroups: TArray<UInt16>);
begin
  if FParams.Group <> nil then
  begin
    // low-level sans-IO fallback: the single fixed group must be ECDHE and offered
    if FParams.Group.Kind <> TNamedGroupKind.Ecdhe then
      raise EFatalAlertTlsLibException.CreateRes(
        TTlsAlertDescription.InternalError, @SGroupNotEcdhe);
    if not (TArrayUtilities.Contains<UInt16>(AClientGroups, FGroupCode)) then
      raise EFatalAlertTlsLibException.CreateRes(
        TTlsAlertDescription.HandshakeFailure, @SGroupNotOffered);
    Exit;
  end;
  // the negotiation policy selects the ECDHE group by server preference among the client's groups
  // (1.2 excludes KEM/hybrid); it raises handshake_failure when none is common
  FGroupCode := FParams.Policy.SelectGroup(AClientGroups, TlsWireVersionTls12);
  if not FParams.GroupRegistry.TryGet(FGroupCode, FSelectedGroup) then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.InternalError, @SGroupNotResolvable);
end;

function TTls12ServerStateMachine.EcdsaCredentialCurveOffered(
  const AClientGroups: TArray<UInt16>): Boolean;
var
  LKind: TSignatureKeyKind;
  LCurve: UInt16;
begin
  // RFC 8422 5.3 / 5.1: an ECDSA server certificate is usable only when its
  // curve appears in the client's supported_groups. A non-ECDSA leaf (or a leaf whose
  // key we cannot classify) is not constrained here.
  Result := True;
  if System.Length(FResolvedCredential.CertificateChain) = 0 then
    Exit;
  if not FParams.Inspector.KeyKind(
    FResolvedCredential.CertificateChain[0], LKind, LCurve) then
    Exit;
  if LKind <> TSignatureKeyKind.Ecdsa then
    Exit;
  Result := TArrayUtilities.Contains<UInt16>(AClientGroups, LCurve);
end;

function TTls12ServerStateMachine.ProcessClientHello(
  const AMessage: TTlsHandshakeMessage): TArray<THandshakeEffect>;
var
  LHello: TTlsClientHello;
  LContext: TExtensionContext;
  LServerHello, LCertificate, LCertificateStatus, LServerKeyExchange, LCertRequest,
    LServerHelloDone, LStaple: TBytes;
  LIssueSession: Boolean;
begin
  LHello := THandshakeMessages.DecodeClientHello(AMessage.Body);
  FClientRandom := LHello.Random;
  LContext := TExtensionContext.Create;
  try
    FCodec.ConsumeBlock(LContext, TTlsExtensionContextKind.ClientHello,
      LHello.Extensions);

    // this machine only speaks TLS 1.2, so a client that offered supported_versions without 1.2,
    // or (absent the extension) a legacy_version below 1.2, shares no version with it: the client
    // selected nothing this server supports (RFC 8446 4.2.1)
    if System.Length(LContext.SupportedVersions) > 0 then
    begin
      if not (TArrayUtilities.Contains<UInt16>(LContext.SupportedVersions,
        TlsWireVersionTls12)) then
        raise EFatalAlertTlsLibException.CreateRes(
          TTlsAlertDescription.ProtocolVersion, @SNoTls12Offered);
    end
    else if LHello.LegacyVersion < TlsWireVersionTls12 then
      raise EFatalAlertTlsLibException.CreateRes(
        TTlsAlertDescription.ProtocolVersion, @SNoTls12Offered);

    // select (or reject) the application protocol from the client's ALPN offer (RFC 7301)
    FSelectedAlpn := TServerOfferSelection.SelectAlpn(FParams.AlpnProtocols,
      LContext.AlpnProtocols, FParams.AlpnRejectAll);

    // echo renegotiation_info if the client signalled secure renegotiation by either the
    // extension or the TLS_EMPTY_RENEGOTIATION_INFO_SCSV cipher suite (RFC 5746 3.4/3.6)
    FEchoRenegotiationInfo := LContext.RenegotiationInfo or
      (TArrayUtilities.Contains<UInt16>(LHello.CipherSuites, $00FF));
    FClientOfferedSessionTicket := LContext.SessionTicketOffered;
    FStatusRequestOffered := LContext.StatusRequestOffered;
    // record_size_limit (RFC 8449): remember the client's offer so the ServerHello echoes ours; a
    // value below 64 is fatal
    if LContext.RecordSizeLimit > 0 then
    begin
      if LContext.RecordSizeLimit < 64 then
        raise EFatalAlertTlsLibException.CreateRes(
          TTlsAlertDescription.IllegalParameter, @SBadRecordSizeLimit);
      FPeerRecordSizeLimit := LContext.RecordSizeLimit;
    end;
    // a client host_name is acknowledged with an empty server_name in the ServerHello
    // (RFC 6066 3)
    FClientSentServerName := LContext.ServerName <> '';
    FRequestedServerName := LContext.ServerName;

    // resumption is attempted before any full-handshake negotiation; a mismatch (bad/expired
    // ticket or session id, suite conflict, EMS now offered for a non-EMS session, or a non-EMS
    // session under the Decline policy) falls through to a full handshake rather than failing
    // (RFC 5077 3.4 / RFC 5246 7.3); the exceptions that abort are an EMS session offered without
    // EMS (RFC 7627 5.3) and a non-EMS session under the Abort policy
    FResuming := TryAcceptResumption(LHello, LContext);
    if not FResuming then
    begin
      // select the server certificate for this handshake from the client's SNI (virtual hosting),
      // before suite/scheme negotiation which depends on the selected leaf's key
      FResolvedCredential := TServerOfferSelection.ResolveCredential(
        FParams.CredentialResolver, LContext, LHello.CipherSuites, TTlsVersion.Tls12);
      // select the ECDHE group: the first server-preferred group the client also
      // advertised in supported_groups (RFC 8422 5.1). Unknown/non-ECDHE offered
      // codes are simply not chosen, so a client mixing bogus curves still succeeds.
      SelectEcdheGroup(LContext.SupportedGroups);
      // RFC 5246 7.4.1.4.1 makes omitting signature_algorithms legal in TLS 1.2 (it implies
      // SHA-1); refusing it is a hardened-posture policy choice, so handshake_failure, not the
      // TLS 1.3 missing_extension (which is mandatory there)
      if System.Length(LContext.SignatureSchemes) = 0 then
        raise EFatalAlertTlsLibException.CreateRes(
          TTlsAlertDescription.HandshakeFailure, @SNoSignatureAlgorithms);
      if not SelectSuiteAndScheme(LHello.CipherSuites, LContext.SignatureSchemes,
        EcdsaCredentialCurveOffered(LContext.SupportedGroups),
        FSelectedSuite, FSelectedScheme) then
        raise EFatalAlertTlsLibException.CreateRes(
          TTlsAlertDescription.HandshakeFailure, @SNoCompatibleSuite);

      // extended_master_secret is used when the client offered it (RFC 7627), and may
      // be required by policy
      FUseExtendedMasterSecret := LContext.ExtendedMasterSecret;
      if FParams.RequireExtendedMasterSecret and not FUseExtendedMasterSecret then
        raise EFatalAlertTlsLibException.CreateRes(
          TTlsAlertDescription.HandshakeFailure, @SNoExtendedMasterSecret);
    end;
  finally
    LContext.Free;
  end;

  if FResuming then
    Exit(EmitAbbreviatedFlight(AMessage.Raw));

  // a full handshake issues a fresh session id (when a store is configured) and, when
  // the client supports tickets, a NewSessionTicket sealed under the STEK. A session set up without
  // extended_master_secret is issued only when this server resumes such sessions: otherwise the id
  // would be empty, which is not resumable (RFC 5246 7.4.1.3), and no NewSessionTicket follows, so
  // the ticket extension is not echoed (RFC 5077 3.2)
  LIssueSession := FUseExtendedMasterSecret or
    (FParams.NonEmsResumption = TNonEmsResumption.Resume);
  if (FParams.SessionStore <> nil) and LIssueSession then
    FSessionId := FParams.Crypto.Primitives.GetRandom.GenerateBytes(SessionIdLength)
  else
    FSessionId := nil;
  FIssueNewTicket := (FTicketStrategy <> nil) and FClientOfferedSessionTicket and LIssueSession;

  StampServerRandom;

  // the server's ECDHE ephemeral: its public value is signed into the ServerKeyExchange
  FSelectedGroup.GenerateKeyPair(FEcdhePrivate, FEcdhePublic);

  // the transcript hash is now known; the plaintext flight is folded into both the
  // transcript and the raw handshake log (the client CertificateVerify signs the log)
  FHandshakeLog.Clear;
  if System.Length(AMessage.Raw) > 0 then
    FHandshakeLog.Write(AMessage.Raw[0], System.Length(AMessage.Raw));
  FTranscript.Update(AMessage.Raw);
  FTranscript.Activate(FParams.Crypto.Primitives.CreateHash(FSelectedSuite.Common.Hash));
  // staple when the client offered status_request and a staple is configured; the
  // ServerHello echoes an empty status_request and a CertificateStatus follows the
  // Certificate (RFC 6066 8)
  LStaple := FResolvedCredential.CurrentOcspStaple;
  FWillStaple := FStatusRequestOffered and (System.Length(LStaple) > 0);

  LServerHello := BuildServerHello;
  Absorb(LServerHello);
  LCertificate := BuildCertificate;
  Absorb(LCertificate);
  if FWillStaple then
  begin
    LCertificateStatus := THandshakeFraming.Frame(TTlsHandshakeType.CertificateStatus,
      THandshakeMessages.EncodeCertificateStatus(LStaple));
    Absorb(LCertificateStatus);
  end;
  LServerKeyExchange := BuildServerKeyExchange;
  Absorb(LServerKeyExchange);
  // CertificateRequest (mutual TLS) follows ServerKeyExchange (RFC 5246 7.4.4)
  if FParams.ClientAuth <> TClientAuthMode.None then
  begin
    LCertRequest := BuildCertificateRequest;
    Absorb(LCertRequest);
  end;
  LServerHelloDone := THandshakeFraming.Frame(TTlsHandshakeType.ServerHelloDone, nil);
  Absorb(LServerHelloDone);

  if FParams.ClientAuth <> TClientAuthMode.None then
    FPhase := TPhase.WaitClientCertificate
  else
    FPhase := TPhase.WaitClientKeyExchange;
  Result := TArray<THandshakeEffect>.Create(
    THandshakeEffects.SendHandshake(LServerHello));
  // once the client offered record_size_limit, cap outbound records to its limit (and the client's
  // to ours; 0 = no inbound cap) BEFORE the possibly large Certificate is framed. The ServerHello
  // that announced the limit is itself unrestricted (RFC 8449 4).
  if FPeerRecordSizeLimit > 0 then
    TArrayUtilities.Append<THandshakeEffect>(Result,
      THandshakeEffects.SetRecordSizeLimit(FPeerRecordSizeLimit, FParams.RecordSizeLimit));
  TArrayUtilities.Append<THandshakeEffect>(Result,
    THandshakeEffects.SendHandshake(LCertificate));
  if FWillStaple then
    TArrayUtilities.Append<THandshakeEffect>(Result,
      THandshakeEffects.SendHandshake(LCertificateStatus));
  TArrayUtilities.Append<THandshakeEffect>(Result,
    THandshakeEffects.SendHandshake(LServerKeyExchange));
  if System.Length(LCertRequest) > 0 then
    TArrayUtilities.Append<THandshakeEffect>(Result,
      THandshakeEffects.SendHandshake(LCertRequest));
  TArrayUtilities.Append<THandshakeEffect>(Result,
    THandshakeEffects.SendHandshake(LServerHelloDone));
end;

procedure TTls12ServerStateMachine.StampServerRandom;
begin
  // a server that can speak TLS 1.3 stamps the downgrade sentinel into ServerHello.random on
  // every TLS 1.2 negotiation, full or abbreviated (RFC 8446 4.1.3)
  FServerRandom := System.Copy(FParams.ServerRandom);
  if FParams.EmitDowngradeSentinel then
    Move(Tls12DowngradeSentinel[0], FServerRandom[24], 8);
end;

function TTls12ServerStateMachine.BuildServerHello: TBytes;
var
  LContext: TExtensionContext;
  LHello: TTlsServerHello;
begin
  LContext := TExtensionContext.Create;
  try
    LContext.ExtendedMasterSecret := FUseExtendedMasterSecret;
    LContext.SelectedAlpn := FSelectedAlpn;
    LContext.RenegotiationInfo := FEchoRenegotiationInfo;
    // no acknowledgement in a resumed session (RFC 6066 3): the server MUST NOT include
    // server_name in the ServerHello of an abbreviated handshake
    LContext.ServerNameAck := FClientSentServerName and
      FParams.ServerNameAck and not FResuming;
    // an empty session_ticket echo announces a forthcoming NewSessionTicket (RFC 5077 3.3)
    LContext.SessionTicketOffered := FIssueNewTicket;
    // an empty status_request echo announces a forthcoming CertificateStatus (RFC 6066 8)
    LContext.StatusRequestResponsePending := FWillStaple;
    // record_size_limit is answered only when the client offered one (RFC 8449 4)
    if FPeerRecordSizeLimit > 0 then
      LContext.RecordSizeLimit := FParams.RecordSizeLimit;
    LHello.Random := FServerRandom;
    LHello.LegacySessionIdEcho := FSessionId;
    LHello.CipherSuite := FSelectedSuite.Common.Code;
    LHello.Extensions := FCodec.ProduceBlock(LContext,
      TTlsExtensionContextKind.ServerHello);
    Result := THandshakeFraming.Frame(TTlsHandshakeType.ServerHello,
      THandshakeMessages.EncodeServerHello(LHello));
  finally
    LContext.Free;
  end;
end;

procedure TTls12ServerStateMachine.Absorb(const ARaw: TBytes);
begin
  FTranscript.Update(ARaw);
  if System.Length(ARaw) > 0 then
    FHandshakeLog.Write(ARaw[0], System.Length(ARaw));
end;

function TTls12ServerStateMachine.BuildCertificate: TBytes;
begin
  Result := THandshakeFraming.Frame(TTlsHandshakeType.Certificate,
    THandshakeMessages.EncodeCertificate12(FResolvedCredential.CertificateChain));
end;

function TTls12ServerStateMachine.BuildCertificateRequest: TBytes;
var
  LRequest: TTlsCertificateRequest12;
begin
  // accepted client certificate types: ecdsa_sign (64) and rsa_sign (1)
  LRequest.CertificateTypes := TBytes.Create(64, 1);
  LRequest.SupportedSignatureAlgorithms := FParams.ClientAuthSignatureSchemes;
  LRequest.CertificateAuthorities := FParams.ClientCertificateAuthorities;
  Result := THandshakeFraming.Frame(TTlsHandshakeType.CertificateRequest,
    THandshakeMessages.EncodeCertificateRequest12(LRequest));
end;

function TTls12ServerStateMachine.SignServerParams(const AParams: TBytes): TBytes;
var
  LSigner: ISignatureSigner;
  LContent: TBytes;
begin
  // the SKE signature covers client_random + server_random + the ECDHE params (RFC 8422 5.4)
  LContent := TArrayUtilities.Concat(
    TArrayUtilities.Concat(FClientRandom, FServerRandom), AParams);
  LSigner := FParams.Crypto.Signing.CreateSignatureSigner(FSelectedScheme,
    FResolvedCredential.PrivateKey);
  LSigner.Update(LContent, 0, System.Length(LContent));
  Result := LSigner.Sign;
end;

function TTls12ServerStateMachine.BuildServerKeyExchange: TBytes;
var
  LMsg: TTlsServerKeyExchangeEcdhe;
begin
  LMsg.NamedCurve := FGroupCode;
  LMsg.PublicKey := FEcdhePublic;
  LMsg.SignatureScheme := FSelectedScheme.ToCode;
  LMsg.Signature := SignServerParams(
    THandshakeMessages.EcdheServerParams(FGroupCode, FEcdhePublic));
  Result := THandshakeFraming.Frame(TTlsHandshakeType.ServerKeyExchange,
    THandshakeMessages.EncodeServerKeyExchangeEcdhe(LMsg));
end;

procedure TTls12ServerStateMachine.DeriveSecrets(const APreMaster: ISecretBuffer;
  const ASessionHash: TBytes);
begin
  FSchedule := TTls12KeySchedule.Create(FParams.Crypto,
    FSelectedSuite.Common.Hash, FSelectedSuite.Common.KeyLength, FSelectedSuite.Common.Aead);
  FSchedule.SetRandoms(FClientRandom, FServerRandom);
  FSchedule.SetKeyLog(FParams.KeyLog, FClientRandom);
  FSchedule.SetPreMasterSecret(APreMaster);
  if FUseExtendedMasterSecret then
    FSchedule.DeriveExtendedMasterSecret(ASessionHash)
  else
    FSchedule.DeriveMasterSecret;
  FSchedule.DeriveKeyBlock;
end;

function TTls12ServerStateMachine.InstallReadKeys: THandshakeEffect;
begin
  // the read side is the client write keys, installed once the client's plaintext
  // flight (ClientKeyExchange, plus CertificateVerify under mutual TLS) is complete
  Result := THandshakeEffects.InstallKeys(FSchedule.TrafficKeys(TTlsEpoch.Application,
    TTlsDirection.ClientWrite), TRecordSide.ReadSide, FSelectedSuite.Common.Aead,
    TTlsVersion.Tls12, TTlsEpoch.Application);
end;

function TTls12ServerStateMachine.ProcessClientCertificate(
  const AMessage: TTlsHandshakeMessage): TArray<THandshakeEffect>;
var
  LAlert: TTlsAlertDescription;
  LVerified: TVerifiedChain;
begin
  Result := nil;
  FClientCertChain := THandshakeMessages.DecodeCertificate12(AMessage.Body);
  FParsedClientLeaf := nil;
  Absorb(AMessage.Raw);
  FClientSentCertificate := System.Length(FClientCertChain) > 0;

  if not FClientSentCertificate then
  begin
    if FParams.ClientAuth = TClientAuthMode.Required then
      raise EFatalAlertTlsLibException.CreateRes(
        TTlsAlertDescription.HandshakeFailure, @SClientCertificateRequired);
  end
  else
  begin
    // a client leaf that is not a well-formed certificate is a decode error, caught before
    // the verifier (which, for -require-any-client-certificate, does not parse the chain)
    FParsedClientLeaf := TCertificateVerify.ParseWellFormedLeaf(FParams.Inspector,
      FClientCertChain[0]);
    if not TCertificateVerify.VerifyClientChain(FParams.ClientCertificateVerifier,
      FClientCertChain, LVerified, LAlert) then
      raise EFatalAlertTlsLibException.CreateRes(LAlert, @SUntrustedClientCertificate);
    // surface the presented client chain and the validated path for connection info (read-only)
    Result := TArray<THandshakeEffect>.Create(
      THandshakeEffects.PeerCertificateChain(FClientCertChain, LVerified.Path));
    // async verdict: the pipeline accepted the client chain; park for the host's out-of-band
    // decision. Carry both the presented chain and the validated path (issuer at index 1), so a
    // live resolver authenticates against the PKIX issuer, never a guess. The buffered
    // ClientKeyExchange/CertificateVerify/Finished resume on accept.
    if TPeerAuthentication.ShouldPark(FParams.Deferral, LVerified.Outcome) then
      TArrayUtilities.Append<THandshakeEffect>(Result,
        ParkForVerdict(FClientCertChain, LVerified.Path, '', nil));
  end;

  FPhase := TPhase.WaitClientKeyExchange;
end;

function TTls12ServerStateMachine.ProcessClientKeyExchange(
  const AMessage: TTlsHandshakeMessage): TArray<THandshakeEffect>;
var
  LCke: TTlsClientKeyExchangeEcdhe;
  LShared: ISecretBuffer;
begin
  LCke := THandshakeMessages.DecodeClientKeyExchangeEcdhe(AMessage.Body);
  // the ECDHE shared secret is the TLS 1.2 premaster secret (RFC 8422 5.10)
  FSelectedGroup.Decapsulate(FEcdhePrivate, LCke.PublicKey, LShared);
  Absorb(AMessage.Raw);
  // session_hash for extended_master_secret is over ClientHello..ClientKeyExchange
  DeriveSecrets(LShared, FTranscript.CurrentHash);

  if FClientSentCertificate then
  begin
    // a CertificateVerify (still plaintext) follows, so the read side waits for it
    FPhase := TPhase.WaitClientCertVerify;
    Result := nil;
  end
  else
  begin
    FPhase := TPhase.WaitClientFinished;
    Result := TArray<THandshakeEffect>.Create(InstallReadKeys);
  end;
end;

function TTls12ServerStateMachine.ProcessClientCertVerify(
  const AMessage: TTlsHandshakeMessage): TArray<THandshakeEffect>;
var
  LCertVerify: TTlsCertificateVerify;
  LScheme: TSignatureScheme;
  LHandshakeLog: TBytes;
begin
  LCertVerify := THandshakeMessages.DecodeCertificateVerify(AMessage.Body);
  // the client may sign only with a scheme the CertificateRequest advertised (RFC 5246 7.4.8) whose
  // key family the client leaf can produce; one outside that set is a wrong signature type
  LScheme := TPeerAuthentication.RequirePeerScheme(FParams.ClientAuthSignatureSchemes,
    LCertVerify.Algorithm, TTlsVersion.Tls12, FParsedClientLeaf);
  // the 1.2 CertificateVerify signs the raw handshake log through ClientKeyExchange; the scheme
  // applies its own hash, so the suite PRF hash does not matter here (the stream buffer is capacity-
  // sized, so verify over exactly the logged bytes)
  LHandshakeLog := System.Copy(FHandshakeLog.Bytes, 0, FHandshakeLog.Size);
  TPeerAuthentication.VerifyPeerSignature(FParams.Crypto, FParsedClientLeaf, LScheme,
    LHandshakeLog, LCertVerify.Signature);
  Absorb(AMessage.Raw);

  FPhase := TPhase.WaitClientFinished;
  Result := TArray<THandshakeEffect>.Create(InstallReadKeys);
end;

function TTls12ServerStateMachine.TryAcceptResumption(
  const AHello: TTlsClientHello; const AContext: TExtensionContext): Boolean;
var
  LSession: IResumableSession;
  L12: ITls12ResumableSession;
  LViaTicket: Boolean;
  LNowMs: UInt64;
  LSuite: TTlsCipherSuite;
begin
  Result := False;
  LSession := nil;
  LViaTicket := False;
  // a presented ticket (stateless) is tried before a session id (stateful)
  if (FTicketStrategy <> nil) and AContext.SessionTicketOffered and
    (System.Length(AContext.SessionTicket) > 0) then
    LViaTicket := FTicketStrategy.Open(AContext.SessionTicket, LSession);
  if (LSession = nil) and (FParams.SessionStore <> nil) and
    (System.Length(AHello.LegacySessionId) > 0) then
  begin
    // a session id is reusable (RFC 5246 7.4.1.2) and travels in the clear, so it is looked up
    // without being removed: a replayed id cannot evict the victim's stored session
    if FParams.SessionStore.Peek(AHello.LegacySessionId, LSession) then
      LViaTicket := False;
  end;
  if LSession = nil then
    Exit;

  // a ticket/session issued under one SNI host must not resume as another (virtual-hosting
  // guard): a host mismatch falls through to a full handshake under the requested name
  if not SameText(LSession.ServerName, FRequestedServerName) then
    Exit;
  // resumption-scope guard: a ticket/session minted under a different scope belongs to a
  // configuration that may not share this one's client-auth trust, so decline it to a full
  // handshake rather than reuse its stored identity
  if not TArrayUtilities.AreEqual(LSession.ResumptionScope, FParams.ResumptionScope) then
    Exit;
  // the recovered session must be a live 1.2 session whose suite the client still offers
  if LSession.Version.WireValue <> TlsWireVersionTls12 then
    Exit;
  if not Supports(LSession, ITls12ResumableSession, L12) then
    Exit;
  LNowMs := FParams.Clock.NowUnixMillis;
  if LNowMs >= LSession.IssuedAtMillis + UInt64(LSession.TicketLifetime) * 1000 then
    Exit;
  if not FParams.CipherSuites.TryGet(LSession.CipherSuite, LSuite) then
    Exit;
  if LSuite.Protocol <> TSuiteProtocol.Tls12 then
    Exit;
  if not (TArrayUtilities.Contains<UInt16>(AHello.CipherSuites,
    LSession.CipherSuite)) then
    Exit;
  // RFC 7627 5.3: an EMS session offered again without EMS MUST abort (a handshake_failure, 5.2) -
  // the omission signals a downgrade (or an attacker stripping the extension) - while a non-EMS
  // session now offered with EMS simply declines to a full handshake
  if L12.ExtendedMasterSecret and not AContext.ExtendedMasterSecret then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.HandshakeFailure, @SResumedEmsDowngrade);
  if AContext.ExtendedMasterSecret and not L12.ExtendedMasterSecret then
    Exit;
  // a server that requires EMS must not resume a session established without it; decline to a full
  // handshake, which then enforces the requirement (RFC 7627 5.3)
  if FParams.RequireExtendedMasterSecret and not L12.ExtendedMasterSecret then
    Exit;
  // mutual-TLS resumption gate (an abbreviated handshake re-runs no client auth): a Required
  // server offered a ticket/session with no stored client identity falls through to a full
  // handshake that requests the certificate. Verification is otherwise not repeated on resume
  if (FParams.ClientAuth = TClientAuthMode.Required) and
    (System.Length(LSession.PeerCertificates) = 0) then
    Exit;
  // neither the session nor this hello used EMS (the checks above settled that): RFC 7627 5.3 says a
  // server SHOULD abort, or continue only for legacy insecure resumption (5.4). Placed after the
  // gates so an abort replaces only a resumption that would otherwise happen, and before the ticket
  // is consumed so an abort does not use up a single-use ticket
  if not L12.ExtendedMasterSecret then
    case FParams.NonEmsResumption of
      TNonEmsResumption.Decline:
        Exit;
      TNonEmsResumption.Abort:
        raise EFatalAlertTlsLibException.CreateRes(
          TTlsAlertDescription.HandshakeFailure, @SNonEmsResumptionRefused);
    end;

  // commit the ticket only now that every check passed; a single-use strategy declines one that
  // another connection already used up
  if LViaTicket and not FTicketStrategy.Consume(AContext.SessionTicket) then
    Exit;

  FResumedSession := L12;
  FSelectedSuite := LSuite;
  FUseExtendedMasterSecret := L12.ExtendedMasterSecret;
  FSessionId := System.Copy(AHello.LegacySessionId);
  // renew the ticket on an abbreviated handshake so single-use tickets stay resumable
  FIssueNewTicket := (FTicketStrategy <> nil) and AContext.SessionTicketOffered;
  Result := True;
end;

function TTls12ServerStateMachine.EmittedTicketLifetime: UInt32;
begin
  // apply the TLS 1.3 seven-day ceiling (RFC 8446 4.6.1) to TLS 1.2 tickets as policy; RFC 5077 sets none
  Result := TClientSessionPolicy.ClampTicketLifetime(FParams.TicketLifetimeSeconds);
end;

function TTls12ServerStateMachine.BuildStoredSession(
  const ASessionId: TBytes): IResumableSession;
var
  LChainForTicket: TArray<TBytes>;
begin
  // carry the client chain forward so a re-issued ticket does not drop the client identity and
  // force the next connection to a full handshake; a resumed chain is only ever one accepted under
  // this configuration's own scope, so re-sealing it launders no foreign identity. Empty on a
  // non-mTLS handshake.
  if System.Length(FClientCertChain) > 0 then
    LChainForTicket := FClientCertChain
  else if FResumedSession <> nil then
    LChainForTicket := FResumedSession.PeerCertificates
  else
    LChainForTicket := nil;
  Result := TTls12ResumableSession.Create(FSelectedSuite.Common.Code,
    FSelectedSuite.Common.Hash, FSchedule.MasterSecret, ASessionId, nil,
    FUseExtendedMasterSecret, '', FRequestedServerName, EmittedTicketLifetime,
    FParams.Clock.NowUnixMillis, LChainForTicket, FParams.ResumptionScope);
end;

function TTls12ServerStateMachine.BuildNewSessionTicketMessage: TBytes;
var
  LMsg: TTls12NewSessionTicket;
  LTicket: TBytes;
begin
  // the ticket seals the session (no session id) under the current STEK. Having echoed the
  // session_ticket extension, the server MUST still send a NewSessionTicket; when the strategy
  // declines (e.g. an oversized chain over the cap) it sends a zero-length ticket with an
  // unspecified lifetime rather than nothing, so the client is not left awaiting one (RFC 5077 3.3)
  LTicket := FTicketStrategy.Seal(BuildStoredSession(nil));
  if System.Length(LTicket) = 0 then
    LMsg.TicketLifetimeHint := 0
  else
    LMsg.TicketLifetimeHint := EmittedTicketLifetime;
  LMsg.Ticket := LTicket;
  Result := THandshakeFraming.Frame(TTlsHandshakeType.NewSessionTicket,
    THandshakeMessages.EncodeTls12NewSessionTicket(LMsg));
end;

function TTls12ServerStateMachine.EmitAbbreviatedFlight(
  const AClientHelloRaw: TBytes): TArray<THandshakeEffect>;
var
  LServerHello, LNst, LServerFinished, LVerifyData: TBytes;
begin
  StampServerRandom;

  // the abbreviated transcript is ClientHello, ServerHello, [NewSessionTicket]; the raw
  // handshake log is unused (no CertificateVerify on an abbreviated handshake)
  FTranscript.Update(AClientHelloRaw);
  FTranscript.Activate(FParams.Crypto.Primitives.CreateHash(FSelectedSuite.Common.Hash));
  LServerHello := BuildServerHello;
  FTranscript.Update(LServerHello);

  // reuse the stored master secret; the key block re-expands under the new randoms
  FSchedule := TTls12KeySchedule.Create(FParams.Crypto,
    FSelectedSuite.Common.Hash, FSelectedSuite.Common.KeyLength, FSelectedSuite.Common.Aead);
  FSchedule.SetRandoms(FClientRandom, FServerRandom);
  FSchedule.SetKeyLog(FParams.KeyLog, FClientRandom);
  FSchedule.SetMasterSecret(FResumedSession.MasterSecret);
  FSchedule.DeriveKeyBlock;

  Result := TArray<THandshakeEffect>.Create(
    THandshakeEffects.SendHandshake(LServerHello));
  // cap outbound records to the client's limit (and its to ours) right after the ServerHello that
  // announced it, so the resumed flight's NewSessionTicket / Finished are bounded (RFC 8449 4)
  if FPeerRecordSizeLimit > 0 then
    TArrayUtilities.Append<THandshakeEffect>(Result,
      THandshakeEffects.SetRecordSizeLimit(FPeerRecordSizeLimit, FParams.RecordSizeLimit));
  // a resumed handshake sends no Certificate, so surface the client chain the session carried
  // (mutual-TLS resumption); empty on a non-mTLS session
  if System.Length(FResumedSession.PeerCertificates) > 0 then
    TArrayUtilities.Append<THandshakeEffect>(Result,
      THandshakeEffects.PeerCertificateChain(FResumedSession.PeerCertificates, nil));
  if FIssueNewTicket then
  begin
    LNst := BuildNewSessionTicketMessage;
    FTranscript.Update(LNst);
    TArrayUtilities.Append<THandshakeEffect>(Result,
      THandshakeEffects.SendHandshake(LNst));
  end;

  // the server Finished is over ClientHello, ServerHello, [NewSessionTicket]
  LVerifyData := FSchedule.ComputeVerifyData(TTlsDirection.ServerWrite,
    FTranscript.CurrentHash);
  LServerFinished := THandshakeFraming.Frame(TTlsHandshakeType.Finished,
    THandshakeMessages.EncodeFinished(LVerifyData));
  FTranscript.Update(LServerFinished);

  TArrayUtilities.Append<THandshakeEffect>(Result,
    THandshakeEffects.SendChangeCipherSpec);
  TArrayUtilities.Append<THandshakeEffect>(Result,
    THandshakeEffects.InstallKeys(FSchedule.TrafficKeys(TTlsEpoch.Application,
    TTlsDirection.ServerWrite), TRecordSide.WriteSide, FSelectedSuite.Common.Aead,
    TTlsVersion.Tls12, TTlsEpoch.Application));
  TArrayUtilities.Append<THandshakeEffect>(Result,
    THandshakeEffects.SendHandshake(LServerFinished));
  // the read side (client write keys) awaits the client's encrypted Finished
  TArrayUtilities.Append<THandshakeEffect>(Result, InstallReadKeys);
  FPhase := TPhase.WaitAbbreviatedClientFinished;
end;

function TTls12ServerStateMachine.ProcessAbbreviatedClientFinished(
  const AMessage: TTlsHandshakeMessage): TArray<THandshakeEffect>;
begin
  // the client Finished is over ClientHello, ServerHello, [NewSessionTicket], server Finished
  if not FSchedule.VerifyFinished(TTlsDirection.ClientWrite,
    FTranscript.CurrentHash, AMessage.Body) then
    raise EFatalAlertTlsLibException.CreateRes(TTlsAlertDescription.DecryptError,
      @SBadClientFinished);
  FPhase := TPhase.Connected;
  MarkConnected;
  // an abbreviated resumption performs no fresh key exchange, so there is no negotiated group
  Result := TArray<THandshakeEffect>.Create(
    THandshakeEffects.ConnectionParams(FSelectedSuite.Common.Code, 0, True,
    FUseExtendedMasterSecret, FRequestedServerName),
    THandshakeEffects.HandshakeEstablished);
  // the read keys are installed; release the handshake-stage material
  FSchedule.ForgetHandshakeSecrets;
end;

function TTls12ServerStateMachine.ProcessClientFinished(
  const AMessage: TTlsHandshakeMessage): TArray<THandshakeEffect>;
var
  LVerifyData, LServerFinished, LNst: TBytes;
begin
  // the client Finished is over the transcript through ClientKeyExchange
  if not FSchedule.VerifyFinished(TTlsDirection.ClientWrite,
    FTranscript.CurrentHash, AMessage.Body) then
    raise EFatalAlertTlsLibException.CreateRes(TTlsAlertDescription.DecryptError,
      @SBadClientFinished);
  FTranscript.Update(AMessage.Raw);

  Result := nil;
  // a NewSessionTicket (RFC 5077) is sent plaintext before the server ChangeCipherSpec
  // and is folded into the transcript the server Finished covers
  if FIssueNewTicket then
  begin
    LNst := BuildNewSessionTicketMessage;
    FTranscript.Update(LNst);
    TArrayUtilities.Append<THandshakeEffect>(Result,
      THandshakeEffects.SendHandshake(LNst));
  end;
  // session-id resumption stores the session under the id echoed in the ServerHello
  if (FParams.SessionStore <> nil) and (System.Length(FSessionId) > 0) then
    FParams.SessionStore.PutWithId(FSessionId, BuildStoredSession(FSessionId));

  // the server Finished is over the transcript INCLUDING the client Finished and any ticket
  LVerifyData := FSchedule.ComputeVerifyData(TTlsDirection.ServerWrite,
    FTranscript.CurrentHash);
  LServerFinished := THandshakeFraming.Frame(TTlsHandshakeType.Finished,
    THandshakeMessages.EncodeFinished(LVerifyData));
  FTranscript.Update(LServerFinished);

  FPhase := TPhase.Connected;
  MarkConnected;
  // change_cipher_spec, then the write side moves to the application keys, then the
  // encrypted server Finished is sent
  TArrayUtilities.Append<THandshakeEffect>(Result,
    THandshakeEffects.SendChangeCipherSpec);
  TArrayUtilities.Append<THandshakeEffect>(Result,
    THandshakeEffects.InstallKeys(FSchedule.TrafficKeys(TTlsEpoch.Application,
    TTlsDirection.ServerWrite), TRecordSide.WriteSide, FSelectedSuite.Common.Aead,
    TTlsVersion.Tls12, TTlsEpoch.Application));
  TArrayUtilities.Append<THandshakeEffect>(Result,
    THandshakeEffects.SendHandshake(LServerFinished));
  // a full TLS 1.2 handshake is always ECDHE (the only 1.2 key exchange): report FGroupCode
  TArrayUtilities.Append<THandshakeEffect>(Result,
    THandshakeEffects.ConnectionParams(FSelectedSuite.Common.Code, FGroupCode, False,
    FUseExtendedMasterSecret, FRequestedServerName));
  TArrayUtilities.Append<THandshakeEffect>(Result,
    THandshakeEffects.HandshakeEstablished);
  // the stored session captured the master secret and the write keys are installed; release the
  // handshake-stage material (the master secret stays for the RFC 5705 exporter)
  FSchedule.ForgetHandshakeSecrets;
end;

function TTls12ServerStateMachine.Route(
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
    TPhase.WaitClientKeyExchange:
      if LKnown and (LType = TTlsHandshakeType.ClientKeyExchange) then
        Result := ProcessClientKeyExchange(AMessage)
      else
        Result := Unexpected;
    TPhase.WaitClientFinished:
      if LKnown and (LType = TTlsHandshakeType.Finished) then
        Result := ProcessClientFinished(AMessage)
      else
        Result := Unexpected;
    TPhase.WaitAbbreviatedClientFinished:
      if LKnown and (LType = TTlsHandshakeType.Finished) then
        Result := ProcessAbbreviatedClientFinished(AMessage)
      else
        Result := Unexpected;
    TPhase.Connected:
      // this server does not renegotiate: a renegotiation ClientHello is answered with a warning
      // no_renegotiation and the connection continues (RFC 5246 7.2.2)
      if LKnown and (LType = TTlsHandshakeType.ClientHello) then
        Result := RefuseRenegotiation
      else
        Result := Unexpected;
  else
    Result := Unexpected;
  end;
end;

function TTls12ServerStateMachine.ExportKeyingMaterial(const ALabel: string;
  ALength: Int32): TBytes;
begin
  // TLS 1.2 stays gated on completion (no False Start), so query and operation agree: the master
  // exists from ClientKeyExchange, but the exporter is not offered before the handshake completes
  Result := nil;
  if not CanExportKeyingMaterial then
    Exit;
  Result := FSchedule.ExportKeyingMaterial(ALabel, ALength);
end;

function TTls12ServerStateMachine.ExportKeyingMaterial(const ALabel: string;
  const AContext: TBytes; ALength: Int32): TBytes;
begin
  Result := nil;
  if not CanExportKeyingMaterial then
    Exit;
  Result := FSchedule.ExportKeyingMaterial(ALabel, AContext, ALength);
end;

function TTls12ServerStateMachine.CanExportKeyingMaterial: Boolean;
begin
  // without Extended Master Secret the master secret can be synchronised across connections, so an
  // exporter would not be unique to this session (RFC 7627 5.4)
  Result := (Stage = THandshakeStage.Connected) and (FSchedule <> nil) and FSchedule.CanExport and
    FUseExtendedMasterSecret;
end;

end.
