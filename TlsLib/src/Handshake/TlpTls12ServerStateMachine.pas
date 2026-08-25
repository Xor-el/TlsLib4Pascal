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
  TlpINamedGroup,
  TlpIKeySchedule,
  TlpTls12KeySchedule,
  TlpITranscriptHash,
  TlpCryptoAlgorithms,
  TlpNegotiationTypes,
  TlpINegotiation,
  TlpNegotiationPolicy,
  TlpExtensionContext,
  TlpITlsExtension,
  TlpHandshakeMessage,
  TlpHandshakeMessages,
  TlpCertificateVerify,
  TlpICertificateTrust,
  TlpTlsCredential,
  TlpITlsCredentialResolver,
  TlpISession,
  TlpIClock,
  TlpSession,
  TlpSessionTicketStrategy,
  TlpHandshakeEffect,
  TlpHandshakeMachineBase;

type
  /// <summary>The inputs a TLS 1.2 server handshake needs to negotiate and drive its flight.</summary>
  TServer12HandshakeParams = record
    Provider: ICryptoProvider;
    CipherSuites: ICipherSuiteRegistry;
    ExtensionRegistry: IExtensionRegistry;
    /// <summary>The server's ECDHE groups in preference order; the first that the client
    /// listed in supported_groups (and resolves to an ECDHE group) is selected, tolerating
    /// unknown/non-ECDHE codes. Empty falls back to the single Group below.</summary>
    OfferedGroups: TArray<UInt16>;
    /// <summary>Resolves a selected group code (from OfferedGroups) to its INamedGroup;
    /// required whenever OfferedGroups is set.</summary>
    GroupRegistry: INamedGroupRegistry;
    /// <summary>A single fixed ECDHE group, used only when OfferedGroups is empty (the
    /// low-level sans-IO entry point); the engine factory always sets OfferedGroups.</summary>
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
    ClientCertificateVerifier: ICertificateVerifier;
    /// <summary>When set, after the built-in pipeline accepts the client chain the machine
    /// parks the handshake for an out-of-band verdict (the deferred-verdict seam) rather than
    /// continuing inline. Augment-only and fail-closed. OFF by default.</summary>
    AsyncVerdict: Boolean;
    /// <summary>The stateful store backing TLS 1.2 session-id resumption (RFC 5246 7.3):
    /// on a full handshake the server echoes a fresh session id and stores the session
    /// under it, then resumes on a later ClientHello that offers it. nil disables the
    /// session-id path.</summary>
    SessionStore: ISessionStore;
    /// <summary>The session-ticket keys backing stateless RFC 5077 ticket resumption: the
    /// server seals the session under the current key and re-presents it in a
    /// NewSessionTicket. nil disables ticket issuance.</summary>
    SessionTicketKeys: ISessionTicketKeyManager;
    /// <summary>The lifetime advertised for issued sessions and tickets, in seconds.</summary>
    TicketLifetimeSeconds: UInt32;
    /// <summary>The clock read for a cached session's issue time and freshness (RFC 5077). A
    /// required input, like Provider: the engine factory supplies one from the config, and a
    /// direct sans-IO caller must set it.</summary>
    Clock: ITlsClock;
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
    FEcdhePrivate: ISecretBuffer;
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
    /// <summary>Whether the server will staple: the client offered status_request and a
    /// staple is configured. Drives the ServerHello echo and the CertificateStatus message.</summary>
    FWillStaple: Boolean;
    /// <summary>Whether a NewSessionTicket is issued (echoed as an empty session_ticket).</summary>
    FIssueNewTicket: Boolean;
    /// <summary>The application protocol selected from the client's ALPN offer, or empty when
    /// none was offered/configured (RFC 7301); echoed in the ServerHello.</summary>
    FSelectedAlpn: string;
    /// <summary>Resumption state: the accepted session and whether it came via a ticket
    /// (rather than a session id).</summary>
    FResuming: Boolean;
    FResumedSession: IResumableSession;
    FResumedViaTicket: Boolean;
    /// <summary>The client's certificate chain (leaf first) and whether it sent one, for
    /// the client CertificateVerify and the required-auth policy.</summary>
    FClientCertChain: TArray<TBytes>;
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
    /// (RFC 8422 5.4 / RFC 4492 5.5). A non-ECDSA leaf is unconstrained here.</summary>
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
    /// Secret consistency; any mismatch returns False so the caller falls through to a
    /// full handshake. On success it fixes the suite, EMS use and the echoed session id.</summary>
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
    /// (RFC 5077 3.3), with a freshly stamped issue time.</summary>
    function BuildNewSessionTicketMessage: TBytes;
    /// <summary>The configured ticket lifetime, capped at the RFC 8446 4.6.1 ceiling.</summary>
    function EmittedTicketLifetime: UInt32;
    /// <summary>The resumable session for the current connection, under ASessionId.</summary>
    function BuildStoredSession(const ASessionId: TBytes): IResumableSession;
    function BuildServerHello: TBytes;
    /// <summary>Selects the application protocol from the client's ALPN offer: the first server
    /// preference the client also offered, empty when ALPN was not offered/configured, or an
    /// abort with no_application_protocol on reject-mode or no overlap (RFC 7301).</summary>
    function SelectAlpn(const AClientOffered: TArray<string>): string;
    function BuildCertificate: TBytes;
    /// <summary>The configured stapled OCSP response (the callback takes precedence over
    /// the static blob); empty when the server is not stapling.</summary>
    function ResolveOcspStaple: TBytes;
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
    function ExportKeyingMaterial(const ALabel: string; const AContext: TBytes;
      AUseContext: Boolean; ALength: Int32): TBytes; override;
  end;

implementation

resourcestring
  SNoCompatibleSuite =
    'no mutually supported TLS 1.2 ECDHE suite the credential can authenticate';
  SNoServerCertificate = 'the server has no certificate for a full TLS 1.2 handshake';
  SCredentialNoSigningKey = 'the selected server credential has no signing key';
  SNoCredentialForServerName = 'no server certificate is configured for the requested SNI host';
  SNoSignatureAlgorithms = 'the client offered no signature_algorithms';
  SGroupNotOffered = 'the client did not offer the server''s ECDHE group';
  SGroupNotEcdhe = 'the configured 1.2 group is not an ECDHE group';
  SNoExtendedMasterSecret =
    'the client did not offer extended_master_secret and it is required';
  SBadClientFinished = 'the client Finished did not verify';
  SClientCertificateRequired = 'client authentication is required but none was sent';
  SUntrustedClientCertificate = 'the client certificate chain was not trusted';
  SNoClientCertificateVerifier = 'no client certificate verifier configured (fail-closed)';
  SBadClientCertVerify = 'the client CertificateVerify did not verify';
  SAlpnRejected = 'the server rejects the offered application protocols (RFC 7301)';

const
  SessionIdLength = Int32(32);

{ TTls12ServerStateMachine }

constructor TTls12ServerStateMachine.Create(const AParams: TServer12HandshakeParams);
begin
  inherited Create(AParams.ExtensionRegistry);
  FParams := AParams;
  FPhase := TPhase.Initial;
  FSelectedGroup := AParams.Group;
  if AParams.Group <> nil then
    FGroupCode := AParams.Group.Code;
  // TLS 1.2 tickets are stateless STEK only; the session-id path uses SessionStore
  FTicketStrategy := TSessionTicketStrategies.ForServer(AParams.Provider,
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
      // an ECDHE_ECDSA suite accepts an ECDSA or an EdDSA (Ed25519) credential: RFC 8422
      // 5.1 requires the certificate to hold an "ECDSA- or EdDSA-capable public key"
      Result := AScheme in [TSignatureScheme.ECDSA_SECP256R1_SHA256,
        TSignatureScheme.ECDSA_SECP384R1_SHA384,
        TSignatureScheme.ECDSA_SECP521R1_SHA512, TSignatureScheme.ED25519];
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
begin
  Result := False;
  // server preference is the shared hardware-AES-aware order; a 1.2 suite is eligible only
  // if the client offered it and the credential can sign the suite's auth with a scheme the
  // client also offered
  for LCode in TNegotiationPolicy.SuitePreferenceOrder(FParams.Provider,
    FParams.CipherSuites, TSuiteProtocol.Tls12) do
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
var
  LGroupCode: UInt16;
  LGroup: INamedGroup;
begin
  // multi-group path: walk the server's preference order and choose the first group
  // the client also advertised that resolves to an ECDHE group (1.2 excludes KEM/
  // hybrid). Unknown or non-ECDHE offered codes are simply skipped.
  if System.Length(FParams.OfferedGroups) > 0 then
  begin
    for LGroupCode in FParams.OfferedGroups do
      if (TArrayUtilities.Contains<UInt16>(AClientGroups, LGroupCode)) and
        (FParams.GroupRegistry.TryGet(LGroupCode, LGroup)) and
        (LGroup.Kind = TNamedGroupKind.Ecdhe) then
      begin
        FSelectedGroup := LGroup;
        FGroupCode := LGroupCode;
        Exit;
      end;
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.HandshakeFailure, @SGroupNotOffered);
  end;

  // low-level sans-IO fallback: the single fixed group must be ECDHE and offered
  if FParams.Group.Kind <> TNamedGroupKind.Ecdhe then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.InternalError, @SGroupNotEcdhe);
  if not (TArrayUtilities.Contains<UInt16>(AClientGroups, FGroupCode)) then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.HandshakeFailure, @SGroupNotOffered);
end;

function TTls12ServerStateMachine.EcdsaCredentialCurveOffered(
  const AClientGroups: TArray<UInt16>): Boolean;
var
  LKind: TCertKeyKind;
  LCurve: UInt16;
begin
  // RFC 8422 5.4 / RFC 4492 5.5: an ECDSA server certificate is usable only when its
  // curve appears in the client's supported_groups. A non-ECDSA leaf (or a leaf whose
  // key we cannot classify) is not constrained here.
  Result := True;
  if System.Length(FResolvedCredential.CertificateChain) = 0 then
    Exit;
  if not FParams.Provider.Certificates.KeyKind(
    FResolvedCredential.CertificateChain[0], LKind, LCurve) then
    Exit;
  if LKind <> TCertKeyKind.Ecdsa then
    Exit;
  Result := TArrayUtilities.Contains<UInt16>(AClientGroups, LCurve);
end;

function TTls12ServerStateMachine.ProcessClientHello(
  const AMessage: TTlsHandshakeMessage): TArray<THandshakeEffect>;
var
  LHello: TTlsClientHello;
  LContext: TExtensionContext;
  LClientHelloInfo: TTlsClientHelloInfo;
  LServerHello, LCertificate, LCertificateStatus, LServerKeyExchange, LCertRequest,
    LServerHelloDone, LStaple: TBytes;
begin
  LHello := THandshakeMessages.DecodeClientHello(AMessage.Body);
  FClientRandom := LHello.Random;
  LContext := TExtensionContext.Create;
  try
    FCodec.ConsumeBlock(LContext, TTlsExtensionContextKind.ClientHello,
      LHello.Extensions);

    // select (or reject) the application protocol from the client's ALPN offer (RFC 7301)
    FSelectedAlpn := SelectAlpn(LContext.AlpnProtocols);

    // echo renegotiation_info if the client signalled secure renegotiation by either the
    // extension or the TLS_EMPTY_RENEGOTIATION_INFO_SCSV cipher suite (RFC 5746 3.4/3.6)
    FEchoRenegotiationInfo := LContext.RenegotiationInfo or
      (TArrayUtilities.Contains<UInt16>(LHello.CipherSuites, $00FF));
    FClientOfferedSessionTicket := LContext.SessionTicketOffered;
    FStatusRequestOffered := LContext.StatusRequestOffered;
    // a client host_name is acknowledged with an empty server_name in the ServerHello
    // (RFC 6066 3)
    FClientSentServerName := LContext.ServerName <> '';
    FRequestedServerName := LContext.ServerName;

    // resumption is attempted before any full-handshake negotiation; any mismatch
    // (bad/expired ticket or session id, suite/EMS conflict) falls through to a full
    // handshake rather than failing (RFC 5077 3.4 / RFC 5246 7.3)
    FResuming := TryAcceptResumption(LHello, LContext);
    if not FResuming then
    begin
      // select the server certificate for this handshake from the client's SNI (virtual hosting),
      // before suite/scheme negotiation which depends on the selected leaf's key
      if FParams.CredentialResolver = nil then
        raise EFatalAlertTlsLibException.CreateRes(
          TTlsAlertDescription.HandshakeFailure, @SNoServerCertificate);
      LClientHelloInfo.ServerName := FRequestedServerName;
      LClientHelloInfo.SignatureSchemes := LContext.SignatureSchemes;
      LClientHelloInfo.AlpnProtocols := LContext.AlpnProtocols;
      LClientHelloInfo.CipherSuites := LHello.CipherSuites;
      LClientHelloInfo.SupportedGroups := LContext.SupportedGroups;
      LClientHelloInfo.ProtocolVersion := TTlsVersion.Tls12;
      if not FParams.CredentialResolver.TryResolve(LClientHelloInfo, FResolvedCredential) then
      begin
        if FRequestedServerName <> '' then
          raise EFatalAlertTlsLibException.CreateRes(
            TTlsAlertDescription.UnrecognizedName, @SNoCredentialForServerName);
        raise EFatalAlertTlsLibException.CreateRes(
          TTlsAlertDescription.HandshakeFailure, @SNoServerCertificate);
      end;
      // a resolved credential with no signing key cannot complete certificate auth; reject it
      // as a handshake_failure rather than dereferencing a nil key during scheme selection
      if not Assigned(FResolvedCredential.PrivateKey) then
        raise EFatalAlertTlsLibException.CreateRes(
          TTlsAlertDescription.HandshakeFailure, @SCredentialNoSigningKey);
      // select the ECDHE group: the first server-preferred group the client also
      // advertised in supported_groups (RFC 8422 5.1). Unknown/non-ECDHE offered
      // codes are simply not chosen, so a client mixing bogus curves still succeeds.
      SelectEcdheGroup(LContext.SupportedGroups);
      if System.Length(LContext.SignatureSchemes) = 0 then
        raise EFatalAlertTlsLibException.CreateRes(
          TTlsAlertDescription.MissingExtension, @SNoSignatureAlgorithms);
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
  // the client supports tickets, a NewSessionTicket sealed under the STEK
  if FParams.SessionStore <> nil then
    FSessionId := FParams.Provider.Primitives.GetRandom.GenerateBytes(SessionIdLength)
  else
    FSessionId := nil;
  FIssueNewTicket := (FTicketStrategy <> nil) and FClientOfferedSessionTicket;

  FServerRandom := System.Copy(FParams.ServerRandom);
  if FParams.EmitDowngradeSentinel then
    Move(Tls12DowngradeSentinel[0], FServerRandom[24], 8);

  // the server's ECDHE ephemeral: its public value is signed into the ServerKeyExchange
  FSelectedGroup.GenerateKeyPair(FEcdhePrivate, FEcdhePublic);

  // the transcript hash is now known; the plaintext flight is folded into both the
  // transcript and the raw handshake log (the client CertificateVerify signs the log)
  FHandshakeLog.Clear;
  if System.Length(AMessage.Raw) > 0 then
    FHandshakeLog.Write(AMessage.Raw[0], System.Length(AMessage.Raw));
  FTranscript.Update(AMessage.Raw);
  FTranscript.Activate(FParams.Provider.Primitives.CreateHash(FSelectedSuite.Common.Hash));
  // staple when the client offered status_request and a staple is configured; the
  // ServerHello echoes an empty status_request and a CertificateStatus follows the
  // Certificate (RFC 6066 8)
  LStaple := ResolveOcspStaple;
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
    THandshakeEffects.SendHandshake(LServerHello),
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

function TTls12ServerStateMachine.SelectAlpn(
  const AClientOffered: TArray<string>): string;
var
  LPref, LOffered: string;
begin
  Result := '';
  // reject mode: any client ALPN offer is refused with no_application_protocol (RFC 7301 3.2)
  if FParams.AlpnRejectAll and (System.Length(AClientOffered) > 0) then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.NoApplicationProtocol, @SAlpnRejected);
  // no selection when the server is not configured for ALPN or the client did not offer it
  if (System.Length(FParams.AlpnProtocols) = 0) or (System.Length(AClientOffered) = 0) then
    Exit;
  for LPref in FParams.AlpnProtocols do
    for LOffered in AClientOffered do
      if LPref = LOffered then
        Exit(LPref);
  // configured, offered, but nothing overlaps (RFC 7301 3.2)
  raise EFatalAlertTlsLibException.CreateRes(
    TTlsAlertDescription.NoApplicationProtocol, @SAlpnRejected);
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
    // no acknowledgement in a resumed session (RFC 6066 3): the server SHALL NOT include
    // server_name in the ServerHello of an abbreviated handshake
    LContext.ServerNameAck := FClientSentServerName and
      FParams.ServerNameAck and not FResuming;
    // an empty session_ticket echo announces a forthcoming NewSessionTicket (RFC 5077 3.3)
    LContext.SessionTicketOffered := FIssueNewTicket;
    // an empty status_request echo announces a forthcoming CertificateStatus (RFC 6066 8)
    LContext.StatusRequestResponsePending := FWillStaple;
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

function TTls12ServerStateMachine.ResolveOcspStaple: TBytes;
begin
  if Assigned(FResolvedCredential.OcspStapleCallback) then
    Result := FResolvedCredential.OcspStapleCallback
  else
    Result := FResolvedCredential.OcspStaple;
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
  LSigner := FParams.Provider.Signing.CreateSignatureSigner(FSelectedScheme,
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
  FSchedule := TTls12KeySchedule.Create(FParams.Provider,
    FSelectedSuite.Common.Hash, FSelectedSuite.Common.KeyLength, FSelectedSuite.Common.Aead);
  FSchedule.SetRandoms(FClientRandom, FServerRandom);
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
    TTlsVersion.Tls12);
end;

function TTls12ServerStateMachine.ProcessClientCertificate(
  const AMessage: TTlsHandshakeMessage): TArray<THandshakeEffect>;
var
  LAlert: TTlsAlertDescription;
begin
  Result := nil;
  FClientCertChain := THandshakeMessages.DecodeCertificate12(AMessage.Body);
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
    TCertificateVerify.EnsureWellFormedLeaf(FParams.Provider, FClientCertChain[0]);
    // fail-closed: without a verifier there is no basis to trust the chain (LAlert would
    // otherwise be read unassigned when the nil check short-circuits the Verify call)
    if FParams.ClientCertificateVerifier = nil then
      raise EFatalAlertTlsLibException.CreateRes(
        TTlsAlertDescription.InternalError, @SNoClientCertificateVerifier);
    if not FParams.ClientCertificateVerifier.Verify(FClientCertChain, '', nil,
      LAlert) then
      raise EFatalAlertTlsLibException.CreateRes(LAlert, @SUntrustedClientCertificate);
    // surface the validated client chain for connection info (read-only)
    Result := TArray<THandshakeEffect>.Create(
      THandshakeEffects.PeerCertificateChain(FClientCertChain));
    // async verdict: the pipeline accepted the client chain; park for the host's out-of-band
    // decision (the buffered ClientKeyExchange/CertificateVerify/Finished resume on accept)
    if FParams.AsyncVerdict then
      TArrayUtilities.Append<THandshakeEffect>(Result,
        THandshakeEffects.AwaitCertificateVerdict(FClientCertChain, ''));
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
  LPublicKeyInfo: TBytes;
  LVerifier: ISignatureVerifier;
begin
  LCertVerify := THandshakeMessages.DecodeCertificateVerify(AMessage.Body);
  if not TSignatureScheme.TryFromCode(LCertVerify.Algorithm, LScheme) then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.IllegalParameter, @SBadClientCertVerify);
  // the client leaf must permit digitalSignature and, for an rsa_pss_rsae_* scheme, not
  // be an id-RSASSA-PSS key (symmetric with the client verifying the server leaf)
  TCertificateVerify.EnforceSigningLeafPolicy(FParams.Provider,
    FClientCertChain[0], LScheme, False);
  // the 1.2 CertificateVerify signs the raw handshake log through ClientKeyExchange;
  // the scheme applies its own hash, so the suite PRF hash does not matter here
  LPublicKeyInfo := FParams.Provider.Certificates.PublicKeyInfo(FClientCertChain[0]);
  LVerifier := FParams.Provider.Signing.CreateSignatureVerifier(LScheme, LPublicKeyInfo);
  LVerifier.Update(FHandshakeLog.Bytes, 0, FHandshakeLog.Size);
  if not LVerifier.Verify(LCertVerify.Signature) then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.DecryptError, @SBadClientCertVerify);
  Absorb(AMessage.Raw);

  FPhase := TPhase.WaitClientFinished;
  Result := TArray<THandshakeEffect>.Create(InstallReadKeys);
end;

function TTls12ServerStateMachine.TryAcceptResumption(
  const AHello: TTlsClientHello; const AContext: TExtensionContext): Boolean;
var
  LSession: IResumableSession;
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
    if FParams.SessionStore.Take(AHello.LegacySessionId, LSession) then
      LViaTicket := False;
  end;
  if LSession = nil then
    Exit;

  // a ticket/session issued under one SNI host must not resume as another (virtual-hosting
  // guard): a host mismatch falls through to a full handshake under the requested name
  if not SameText(LSession.ServerName, FRequestedServerName) then
    Exit;
  // the recovered session must be a live 1.2 session whose suite the client still offers
  if LSession.Version.WireValue <> TlsWireVersionTls12 then
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
  // Extended Master Secret must be consistent across the resumption (RFC 7627 5.3):
  // resume only when the ClientHello's EMS offer matches the original session
  if LSession.ExtendedMasterSecret <> AContext.ExtendedMasterSecret then
    Exit;

  FResumedSession := LSession;
  FResumedViaTicket := LViaTicket;
  FSelectedSuite := LSuite;
  FUseExtendedMasterSecret := LSession.ExtendedMasterSecret;
  FSessionId := System.Copy(AHello.LegacySessionId);
  // renew the ticket on an abbreviated handshake so single-use tickets stay resumable
  FIssueNewTicket := (FTicketStrategy <> nil) and AContext.SessionTicketOffered;
  Result := True;
end;

function TTls12ServerStateMachine.EmittedTicketLifetime: UInt32;
begin
  // a server MUST NOT advertise or honour a lifetime above the RFC 8446 4.6.1 ceiling
  Result := FParams.TicketLifetimeSeconds;
  if Result > MaxTicketLifetimeSeconds then
    Result := MaxTicketLifetimeSeconds;
end;

function TTls12ServerStateMachine.BuildStoredSession(
  const ASessionId: TBytes): IResumableSession;
begin
  Result := TResumableSession.CreateTls12(FSelectedSuite.Common.Code,
    FSelectedSuite.Common.Hash, FSchedule.MasterSecret, ASessionId, nil,
    FUseExtendedMasterSecret, '', FRequestedServerName, EmittedTicketLifetime, 0,
    FParams.Clock.NowUnixMillis);
end;

function TTls12ServerStateMachine.BuildNewSessionTicketMessage: TBytes;
var
  LMsg: TTls12NewSessionTicket;
begin
  LMsg.TicketLifetimeHint := EmittedTicketLifetime;
  // the ticket seals the session (no session id) under the current STEK
  LMsg.Ticket := FTicketStrategy.Seal(BuildStoredSession(nil));
  Result := THandshakeFraming.Frame(TTlsHandshakeType.NewSessionTicket,
    THandshakeMessages.EncodeTls12NewSessionTicket(LMsg));
end;

function TTls12ServerStateMachine.EmitAbbreviatedFlight(
  const AClientHelloRaw: TBytes): TArray<THandshakeEffect>;
var
  LServerHello, LNst, LServerFinished, LVerifyData: TBytes;
begin
  // resuming a 1.2 session is the client's explicit choice, so no downgrade sentinel
  FServerRandom := System.Copy(FParams.ServerRandom);

  // the abbreviated transcript is ClientHello, ServerHello, [NewSessionTicket]; the raw
  // handshake log is unused (no CertificateVerify on an abbreviated handshake)
  FTranscript.Update(AClientHelloRaw);
  FTranscript.Activate(FParams.Provider.Primitives.CreateHash(FSelectedSuite.Common.Hash));
  LServerHello := BuildServerHello;
  FTranscript.Update(LServerHello);

  // reuse the stored master secret; the key block re-expands under the new randoms
  FSchedule := TTls12KeySchedule.Create(FParams.Provider,
    FSelectedSuite.Common.Hash, FSelectedSuite.Common.KeyLength, FSelectedSuite.Common.Aead);
  FSchedule.SetRandoms(FClientRandom, FServerRandom);
  FSchedule.SetMasterSecret(FResumedSession.MasterSecret);
  FSchedule.DeriveKeyBlock;

  Result := TArray<THandshakeEffect>.Create(
    THandshakeEffects.SendHandshake(LServerHello));
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
    TTlsVersion.Tls12));
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
  // a session-id resumption consumed the stored session (single-use Take); re-store it so
  // the session stays resumable until it expires
  if (not FResumedViaTicket) and (FParams.SessionStore <> nil) and
    (System.Length(FSessionId) > 0) then
    FParams.SessionStore.PutWithId(FSessionId, FResumedSession);
  FPhase := TPhase.Connected;
  // an abbreviated resumption performs no fresh key exchange, so there is no negotiated group
  Result := TArray<THandshakeEffect>.Create(
    THandshakeEffects.ConnectionParams(FSelectedSuite.Common.Code, 0, True,
    FRequestedServerName),
    THandshakeEffects.HandshakeEstablished);
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
  // change_cipher_spec, then the write side moves to the application keys, then the
  // encrypted server Finished is sent
  TArrayUtilities.Append<THandshakeEffect>(Result,
    THandshakeEffects.SendChangeCipherSpec);
  TArrayUtilities.Append<THandshakeEffect>(Result,
    THandshakeEffects.InstallKeys(FSchedule.TrafficKeys(TTlsEpoch.Application,
    TTlsDirection.ServerWrite), TRecordSide.WriteSide, FSelectedSuite.Common.Aead,
    TTlsVersion.Tls12));
  TArrayUtilities.Append<THandshakeEffect>(Result,
    THandshakeEffects.SendHandshake(LServerFinished));
  // a full TLS 1.2 handshake is always ECDHE (the only 1.2 key exchange): report FGroupCode
  TArrayUtilities.Append<THandshakeEffect>(Result,
    THandshakeEffects.ConnectionParams(FSelectedSuite.Common.Code, FGroupCode, False,
    FRequestedServerName));
  TArrayUtilities.Append<THandshakeEffect>(Result,
    THandshakeEffects.HandshakeEstablished);
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
  else
    Result := Unexpected;
  end;
end;

function TTls12ServerStateMachine.ExportKeyingMaterial(const ALabel: string;
  const AContext: TBytes; AUseContext: Boolean; ALength: Int32): TBytes;
begin
  Result := nil;
  if FSchedule = nil then
    Exit;
  Result := FSchedule.ExportKeyingMaterial(ALabel, AContext, AUseContext, ALength);
end;

end.
