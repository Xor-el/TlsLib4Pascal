{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpTls12ClientStateMachine;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  Classes,
  TlpArrayUtilities,
  TlpDataEncoding,
  TlpTlsAlert,
  TlpTlsVersion,
  TlpTlsLibExceptions,
  TlpISecretBuffer,
  TlpICryptoProvider,
  TlpIPkixProvider,
  TlpINamedGroup,
  TlpIKeySchedule,
  TlpTls12KeySchedule,
  TlpITranscriptHash,
  TlpCryptoDomainTypes,
  TlpNegotiationTypes,
  TlpINegotiation,
  TlpNegotiationPolicy,
  TlpWireReader,
  TlpExtensionVector,
  TlpExtensionContext,
  TlpITlsExtension,
  TlpHandshakeMessage,
  TlpHandshakeMessages,
  TlpCertificateVerify,
  TlpPeerAuthentication,
  TlpICertificateTrust,
  TlpTrustTypes,
  TlpServerName,
  TlpISigningKey,
  TlpTlsCredential,
  TlpISession,
  TlpIClock,
  TlpSession,
  TlpITlsEngine,
  TlpHandshakeEffect,
  TlpHandshakeStage,
  TlpHandshakeMachineBase;

type
  /// <summary>The inputs a TLS 1.2 client handshake needs to build and drive its flight.</summary>
  TClient12HandshakeParams = record
    Crypto: ICryptoProvider;
    Inspector: ICertificateInspector;
    /// <summary>Resolves the ECDHE group the server names in its ServerKeyExchange to a
    /// usable group; the client key-exchanges on whichever offered curve the server
    /// picks (only classical ECDHE groups are eligible for 1.2).</summary>
    GroupRegistry: INamedGroupRegistry;
    CipherSuites: ICipherSuiteRegistry;
    ExtensionRegistry: IExtensionRegistry;
    OfferedSuites: TArray<UInt16>;
    /// <summary>The supported_groups the client advertises (preference order, non-empty).</summary>
    OfferedGroups: TArray<UInt16>;
    OfferedSchemes: TArray<UInt16>;
    /// <summary>The ALPN protocols the client advertised, in preference order; the
    /// server's ServerHello selection must be one of these (RFC 7301 3.2).</summary>
    AlpnProtocols: TArray<string>;
    /// <summary>The versions offered in supported_versions; listing 1.3 arms downgrade
    /// detection on a 1.2 ServerHello carrying the RFC 8446 sentinel.</summary>
    OfferedVersions: TArray<UInt16>;
    ClientRandom: TBytes;
    LegacySessionId: TBytes;
    ServerName: string;
    /// <summary>Whether to offer extended_master_secret (RFC 7627); default on.</summary>
    OfferExtendedMasterSecret: Boolean;
    /// <summary>When set, the handshake fails closed unless the negotiated (or resumed)
    /// session uses extended_master_secret (RFC 7627); guards against an MITM stripping it.</summary>
    RequireExtendedMasterSecret: Boolean;
    /// <summary>Whether to offer status_request (OCSP stapling, RFC 6066); default off, so an
    /// unsolicited server staple is rejected unless the client explicitly asked for one.</summary>
    RequestOcspStapling: Boolean;
    /// <summary>When set, Start seeds the transcript from these framed ClientHello bytes
    /// (already sent by a version-dispatching parent) instead of building and sending a
    /// fresh ClientHello.</summary>
    PresentClientHello: TBytes;
    /// <summary>On the PresentClientHello (dispatched) path, the cached TLS 1.2 session the
    /// parent's unified ClientHello offered, and the session id it carried. Set together so
    /// this machine resumes via the abbreviated handshake when the server echoes that id.</summary>
    PresentResumptionSession: IResumableSession;
    PresentOfferedSessionId: TBytes;
    /// <summary>The client's credential for mutual TLS: presented when the server sends
    /// a CertificateRequest and the credential can satisfy it. An empty chain sends an
    /// empty client Certificate (declining to authenticate).</summary>
    ClientCredential: TTlsCredential;
    /// <summary>Decides whether the server chain is trusted; none configured fails closed.</summary>
    CertificateVerifier: IServerCertificateVerifier;
    /// <summary>Verifies a resumed server's stored chain on reverify-on-resume (no Certificate,
    /// no staple gate); nil falls back to CertificateVerifier (never looser than it).</summary>
    ResumeCertificateVerifier: IServerCertificateVerifier;
    ExpectedServerName: TServerName;
    /// <summary>The client-side cache resumption draws from and stores into. When set, the
    /// client offers session_ticket support and, if a session is cached for this server,
    /// resumes it (RFC 5077 / RFC 5246 7.3). nil disables 1.2 resumption.</summary>
    SessionCache: ISessionCache;
    /// <summary>An opaque tag folded into the cache identity so a shared cache does not resume
    /// across configurations; empty (the direct sans-IO default) leaves the identity unscoped.</summary>
    SessionScope: TBytes;
    /// <summary>How the client verifies a resumed server: ReuseOriginal (default) reuses the
    /// original authentication; Reverify re-runs CertificateVerifier against the stored chain.</summary>
    ResumeVerification: TResumeVerification;
    /// <summary>The clock read to stamp a cached 1.2 session's issue time (RFC 5077). A required
    /// input, like Crypto: the engine factory supplies one from the config, and a direct sans-IO
    /// caller must set it.</summary>
    Clock: ITlsClock;
    /// <summary>The cache key for this server; ServerName is used when empty.</summary>
    ServerIdentity: string;
    /// <summary>How a peer-certificate verdict is deferred out-of-band (see TVerdictDeferral):
    /// augment-only and fail-closed, None by default.</summary>
    Deferral: TVerdictDeferral;
  end;

  /// <summary>
  /// The hardened TLS 1.2 client machine (RFC 5246 + RFC 4492/8422 ECDHE + RFC 7627
  /// Extended Master Secret). It sends the ClientHello, then on the server flight
  /// verifies the certificate chain and the ServerKeyExchange signature, sends its
  /// ClientKeyExchange, derives the (extended) master secret, sends its Finished, and
  /// verifies the server Finished. It returns effects and never touches the record
  /// layer; certificate trust runs inline and fail-closed.
  /// </summary>
  TTls12ClientStateMachine = class sealed(THandshakeMachineBase)
  strict private
  type
    TPhase = (Initial, WaitServerHello, WaitCertificate, WaitCertificateStatus,
      WaitServerKeyExchange, WaitServerHelloDone, WaitNewSessionTicket,
      WaitServerFinished, WaitAbbreviatedNewSessionTicket,
      WaitAbbreviatedServerFinished, WaitResumeVerdict, Connected);
  var
    FParams: TClient12HandshakeParams;
    FPhase: TPhase;
    FServerRandom: TBytes;
    FCurrentGroup: INamedGroup;
    FServerEcdhePublic: TBytes;
    FCertChain: TArray<TBytes>;
    // the server leaf parsed once for the well-formed gate, reused for the key-kind check,
    // the signing-policy check and its SubjectPublicKeyInfo; released once the SKE signature
    // is verified
    FParsedServerLeaf: IInspectedCertificate;
    FUseExtendedMasterSecret: Boolean;
    FClientSupportsTls13: Boolean;
    /// <summary>Whether the ServerHello echoed status_request, so a CertificateStatus
    /// message (RFC 6066 8) precedes the ServerKeyExchange.</summary>
    FServerWillStaple: Boolean;
    /// <summary>The stapled OCSP response the CertificateStatus carried; empty when none.
    /// Fed to the trust verdict.</summary>
    FReceivedOcspStaple: TBytes;
    FOfferedExtensions: TArray<UInt16>;
    FSchedule: ITls12KeySchedule;
    /// <summary>The cached session offered for resumption (nil when none), the session id
    /// the ClientHello carried (to detect the server's abbreviated echo), and the server's
    /// echoed id / issued ticket captured for caching on completion.</summary>
    FResumptionOffer: IResumableSession;
    // the validated path the reverify-on-resume check produced, surfaced to an async park so a
    // live resolver authenticates against the PKIX issuer rather than a re-guess
    FResumeValidatedPath: TArray<TBytes>;
    FOfferedSessionId: TBytes;
    FServerSessionId: TBytes;
    FReceivedTicket: TBytes;
    FReceivedTicketLifetime: UInt32;
    /// <summary>Whether the ServerHello echoed the session_ticket extension, so a plaintext
    /// NewSessionTicket precedes the server Finished (its read epoch is deferred past it).</summary>
    FExpectNewSessionTicket: Boolean;
    /// <summary>A CertificateRequest was received and the schemes the server accepts.</summary>
    FCertificateRequested: Boolean;
    FClientAuthSchemes: TArray<UInt16>;
    /// <summary>The DER DistinguishedName certificate_authorities the server named in its
    /// CertificateRequest (RFC 5246 7.4.4); surfaced for read-only connection info.</summary>
    FRequestedCertificateAuthorities: TArray<TBytes>;
    /// <summary>The client-certificate types the server will accept (RFC 5246 7.4.4
    /// ClientCertificateType: rsa_sign=1, ecdsa_sign=64); our leaf must match one.</summary>
    FClientAuthCertTypes: TBytes;
    /// <summary>The raw concatenation of every handshake message, signed over by the
    /// client CertificateVerify (RFC 5246 7.4.8).</summary>
    FHandshakeLog: TBytesStream;
    /// <summary>Folds a message into both the transcript hash and the raw handshake log.</summary>
    procedure Absorb(const ARaw: TBytes);
    procedure RememberOffered(const AFramedClientHello: TBytes);
    procedure ApplyOffered(const AContext: TExtensionContext);
    function BuildClientHello: TBytes;
    function ProcessServerHello(const AMessage: TTlsHandshakeMessage)
      : TArray<THandshakeEffect>;
    function ProcessCertificate(const AMessage: TTlsHandshakeMessage)
      : TArray<THandshakeEffect>;
    /// <summary>Consumes the CertificateStatus message (RFC 6066 8), capturing the stapled
    /// OCSP response, then runs the deferred trust verdict.</summary>
    function ProcessCertificateStatus(const AMessage: TTlsHandshakeMessage)
      : TArray<THandshakeEffect>;
    /// <summary>The fail-closed server-chain trust check, run once the stapled OCSP response
    /// (if any) is in hand. Raises on rejection. Returns the AwaitCertificateVerdict park
    /// effect when an async verdict is configured (the pipeline having accepted the chain),
    /// otherwise an empty result.</summary>
    function VerifyServerChain: TArray<THandshakeEffect>;
    function ProcessServerKeyExchange(const AMessage: TTlsHandshakeMessage)
      : TArray<THandshakeEffect>;
    /// <summary>Records a CertificateRequest (RFC 5246 7.4.4) and its signature algorithms.</summary>
    procedure ProcessCertificateRequest(const AMessage: TTlsHandshakeMessage);
    function ProcessServerHelloDone(const AMessage: TTlsHandshakeMessage)
      : TArray<THandshakeEffect>;
    function ProcessServerFinished(const AMessage: TTlsHandshakeMessage)
      : TArray<THandshakeEffect>;
    /// <summary>The cache key for this server (ServerIdentity, or ServerName when unset).</summary>
    function CacheServerIdentity: string;
    /// <summary>Enters the abbreviated (resumption) handshake once the ServerHello confirms
    /// it: validates the suite and EMS against the cached session, reuses its master secret,
    /// and either defers the read epoch for a forthcoming NewSessionTicket or installs it.</summary>
    function BeginAbbreviatedHandshake(const AContext: TExtensionContext)
      : TArray<THandshakeEffect>;
    /// <summary>Re-runs the certificate verifier against the resumed session's stored peer chain
    /// (the ReuseOriginal-vs-Reverify opt-in); a negative verdict aborts the handshake.</summary>
    procedure ReverifyResumedServer;
    /// <summary>Records a full-handshake NewSessionTicket (RFC 5077), folds it into the
    /// transcript and installs the deferred read epoch for the server Finished.</summary>
    function ProcessNewSessionTicket(const AMessage: TTlsHandshakeMessage)
      : TArray<THandshakeEffect>;
    /// <summary>Records an abbreviated-handshake NewSessionTicket and installs the read
    /// epoch for the following server Finished.</summary>
    function ProcessAbbreviatedNewSessionTicket(const AMessage: TTlsHandshakeMessage)
      : TArray<THandshakeEffect>;
    /// <summary>Verifies the abbreviated server Finished, then either parks for a reverify-on-
    /// resume verdict (withholding the closing flight) or completes the resumed connection.</summary>
    function ProcessAbbreviatedServerFinished(const AMessage: TTlsHandshakeMessage)
      : TArray<THandshakeEffect>;
    /// <summary>The client's closing flight for a resumed handshake: ChangeCipherSpec, the
    /// client write keys, the client Finished, the re-cache and connection events. Emitted
    /// inline, or from ResumeAfterVerdict when a reverify-on-resume park withheld it.</summary>
    function BuildAbbreviatedClientFlight: TArray<THandshakeEffect>;
    /// <summary>Caches the completed session (session id and/or ticket) for later
    /// resumption and returns the SessionTicketReceived event when a ticket was issued.</summary>
    function CacheCompletedSession: TArray<THandshakeEffect>;
    /// <summary>Frames the client Certificate (empty chain when no usable credential),
    /// appending it to AEffects and folding it in; returns whether a chain was sent.</summary>
    function AppendClientCertificate(var AEffects: TArray<THandshakeEffect>;
      out AScheme: TSignatureScheme): Boolean;
    procedure DeriveSecrets(const APreMaster: ISecretBuffer;
      const ASessionHash: TBytes);
  strict protected
    function Route(const AMessage: TTlsHandshakeMessage)
      : TArray<THandshakeEffect>; override;
    function ContinueAfterVerdict: TArray<THandshakeEffect>; override;
  public
    constructor Create(const AParams: TClient12HandshakeParams);
    destructor Destroy; override;
    function Initiates: Boolean; override;
    function Start: TArray<THandshakeEffect>; override;
    function ExportKeyingMaterial(const ALabel: string; const AContext: TBytes;
      AUseContext: Boolean; ALength: Int32): TBytes; override;
    function CanExportKeyingMaterial: Boolean; override;
  end;

implementation

resourcestring
  SUnofferedSuite = 'the server selected a cipher suite that was not offered';
  SUnknownSelectedSuite = 'the selected cipher suite is not in the registry';
  SCertificateRequestTwice = 'the server sent a second CertificateRequest';
  SCertKeyMismatchesSuite =
    'the certificate key algorithm does not match the negotiated suite authentication';
  SLeafCurveNotOffered =
    'the ECDSA certificate curve is not among the offered supported_groups';
  SNotTls12Suite = 'the server selected a suite that is not a TLS 1.2 suite';
  SDowngradeDetected = 'the ServerHello carries a version downgrade sentinel';
  SEchoedInvalidSessionId =
    'the server echoed a session id for a session we did not offer to resume';
  SEmptyCertificate = 'the server sent an empty certificate list';
  SNoCertificateVerifier = 'no certificate verifier configured (fail-closed)';
  SUntrustedCertificate = 'the server certificate chain was not trusted';
  SUnofferedAlpn = 'the server selected an ALPN protocol that was not offered';
  SBadServerKeyExchangeCurve = 'the ServerKeyExchange named a group that was not offered';
  SBadServerFinished = 'the server Finished did not verify';
  SResumedSuiteMismatch =
    'the resumed ServerHello selected a suite other than the cached session''s';
  SResumedEmsMismatch =
    'the resumed ServerHello''s extended_master_secret state does not match the session';
  SNoExtendedMasterSecret =
    'the server did not negotiate extended_master_secret and it is required';
  SServerHelloDoneNotEmpty = 'the ServerHelloDone message carries a non-empty body';

{ TTls12ClientStateMachine }

constructor TTls12ClientStateMachine.Create(const AParams: TClient12HandshakeParams);
begin
  inherited Create(AParams.ExtensionRegistry);
  FParams := AParams;
  FPhase := TPhase.Initial;
  FClientSupportsTls13 := TArrayUtilities.Contains<UInt16>(AParams.OfferedVersions,
    TlsWireVersionTls13);
  FHandshakeLog := TBytesStream.Create;
end;

destructor TTls12ClientStateMachine.Destroy;
begin
  FHandshakeLog.Free;
  inherited Destroy;
end;

procedure TTls12ClientStateMachine.Absorb(const ARaw: TBytes);
begin
  FTranscript.Update(ARaw);
  if System.Length(ARaw) > 0 then
    FHandshakeLog.Write(ARaw[0], System.Length(ARaw));
end;

procedure TTls12ClientStateMachine.RememberOffered(
  const AFramedClientHello: TBytes);
var
  LHello: TTlsClientHello;
  LVector: TExtensionVector;
begin
  // strip the 4-byte handshake header to reach the body
  LHello := THandshakeMessages.DecodeClientHello(System.Copy(AFramedClientHello, 4,
    System.Length(AFramedClientHello) - 4));
  LVector := TExtensionVector.Parse(LHello.Extensions);
  FOfferedExtensions := LVector.Types;
end;

procedure TTls12ClientStateMachine.ApplyOffered(const AContext: TExtensionContext);
var
  LType: UInt16;
begin
  for LType in FOfferedExtensions do
    AContext.MarkOffered(LType);
end;

function TTls12ClientStateMachine.BuildClientHello: TBytes;
var
  LContext: TExtensionContext;
  LHello: TTlsClientHello;
begin
  Result := nil;
  LContext := TExtensionContext.Create;
  try
    LContext.SupportedVersions := FParams.OfferedVersions;
    LContext.SupportedGroups := FParams.OfferedGroups;
    LContext.SignatureSchemes := FParams.OfferedSchemes;
    LContext.ServerName := FParams.ServerName;
    LContext.ExtendedMasterSecret := FParams.OfferExtendedMasterSecret;
    // secure-renegotiation signalling (RFC 5746), even though we never renegotiate
    LContext.RenegotiationInfo := True;
    // ec_point_formats (RFC 8422): a client offering ECC suites lists uncompressed support,
    // which strict servers require to accept ECDHE
    LContext.EcPointFormatsOffered := True;
    // offer to accept a stapled OCSP response (RFC 6066) only when asked; a stapling server
    // answers with an empty ServerHello echo and a CertificateStatus message
    LContext.StatusRequestOffered := FParams.RequestOcspStapling;

    LHello.Random := FParams.ClientRandom;
    LHello.LegacySessionId := FParams.LegacySessionId;
    // resumption offer: signal ticket support and present the cached ticket / session id
    if FParams.SessionCache <> nil then
    begin
      LContext.SessionTicketOffered := True;
      if FResumptionOffer <> nil then
      begin
        LContext.SessionTicket := FResumptionOffer.SessionTicket;
        // align the EMS offer to the cached session so the server may resume (RFC 7627 5.3)
        LContext.ExtendedMasterSecret := FResumptionOffer.ExtendedMasterSecret;
        if System.Length(FResumptionOffer.SessionId) > 0 then
          FOfferedSessionId := FResumptionOffer.SessionId
        else if System.Length(FResumptionOffer.SessionTicket) > 0 then
          // a ticket-only session still carries an id so the server's echo signals resumption
          FOfferedSessionId := FParams.Crypto.Primitives.GetRandom.GenerateBytes(32);
        LHello.LegacySessionId := FOfferedSessionId;
      end;
    end;
    LHello.CipherSuites := FParams.OfferedSuites;
    LHello.Extensions := FCodec.ProduceBlock(LContext,
      TTlsExtensionContextKind.ClientHello);
    Result := THandshakeFraming.Frame(TTlsHandshakeType.ClientHello,
      THandshakeMessages.EncodeClientHello(LHello));
  finally
    LContext.Free;
  end;
end;

function TTls12ClientStateMachine.CacheServerIdentity: string;
begin
  if FParams.ServerIdentity <> '' then
    Result := FParams.ServerIdentity
  else
    Result := FParams.ServerName;
  // fold the configuration scope into the key so a cache shared with another configuration does not
  // resume across the two (the separator is a control char that cannot occur in a server identity)
  if System.Length(FParams.SessionScope) > 0 then
    Result := Result + #31 + TDataEncoding.HexEncode(FParams.SessionScope);
end;

function TTls12ClientStateMachine.Initiates: Boolean;
begin
  Result := True;
end;

function TTls12ClientStateMachine.Start: TArray<THandshakeEffect>;
var
  LClientHello: TBytes;
  LCached: IResumableSession;
  LCappedLifetime: UInt32;
begin
  FPhase := TPhase.WaitServerHello;
  // a version-dispatching parent may have already sent a unified ClientHello: seed the
  // transcript from it and emit nothing, otherwise build and send our own
  if System.Length(FParams.PresentClientHello) > 0 then
  begin
    RememberOffered(FParams.PresentClientHello);
    Absorb(FParams.PresentClientHello);
    // adopt the legacy_session_id the parent's hello actually sent so ProcessServerHello can
    // detect the server echoing it - a genuine abbreviated resumption when the parent offered a
    // cached 1.2 session, or a false one (the TLS 1.3 compatibility-mode id) it must reject
    FOfferedSessionId := FParams.PresentOfferedSessionId;
    if FParams.PresentResumptionSession <> nil then
      FResumptionOffer := FParams.PresentResumptionSession;
    Exit(nil);
  end;
  // resumption: pop one cached TLS 1.2 session for this server to offer in the ClientHello.
  // A ticket past its hinted lifetime is dropped (RFC 5077 3.3); a hint of 0 is unspecified and
  // still offered. When a lifetime is hinted, a seven-day retention cap (local policy) bounds it.
  if (FParams.SessionCache <> nil) and
    FParams.SessionCache.Take(CacheServerIdentity, FParams.ServerName, LCached) and
    (LCached.Version.WireValue = TlsWireVersionTls12) then
  begin
    LCappedLifetime := LCached.TicketLifetime;
    if LCappedLifetime > MaxTicketLifetimeSeconds then
      LCappedLifetime := MaxTicketLifetimeSeconds;
    if (LCached.TicketLifetime = 0) or
      ((FParams.Clock.NowUnixMillis - LCached.IssuedAtMillis) <=
      (UInt64(LCappedLifetime) * 1000)) then
      FResumptionOffer := LCached;
  end;
  LClientHello := BuildClientHello;
  RememberOffered(LClientHello);
  Absorb(LClientHello);
  // a 1.2 client sends no change_cipher_spec until after its ClientKeyExchange
  Result := TArray<THandshakeEffect>.Create(
    THandshakeEffects.SendHandshake(LClientHello));
end;

function TTls12ClientStateMachine.ProcessServerHello(
  const AMessage: TTlsHandshakeMessage): TArray<THandshakeEffect>;
var
  LHello: TTlsServerHello;
  LContext: TExtensionContext;
begin
  Result := nil;
  LHello := THandshakeMessages.DecodeServerHello(AMessage.Body);

  if not (TArrayUtilities.Contains<UInt16>(FParams.OfferedSuites, LHello.CipherSuite)) then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.IllegalParameter, @SUnofferedSuite);
  if not FParams.CipherSuites.TryGet(LHello.CipherSuite, FSelectedSuite) then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.IllegalParameter, @SUnknownSelectedSuite);
  if FSelectedSuite.Protocol <> TSuiteProtocol.Tls12 then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.IllegalParameter, @SNotTls12Suite);

  FServerRandom := LHello.Random;
  FServerSessionId := LHello.LegacySessionIdEcho;
  FTranscript.Activate(FParams.Crypto.Primitives.CreateHash(FSelectedSuite.Common.Hash));
  Absorb(AMessage.Raw);

  // a 1.3-capable client aborts a stamped downgrade (RFC 8446 4.1.3) before acting on the rest
  // of the ServerHello, so an abbreviated (resumption) ServerHello is checked too; a genuine
  // 1.2-only server never stamps the sentinel
  if TDowngradeProtection.IsDowngradeAttack(LHello.Random, FClientSupportsTls13,
    TlsWireVersionTls12) then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.IllegalParameter, @SDowngradeDetected);

  LContext := TExtensionContext.Create;
  try
    ApplyOffered(LContext);
    FCodec.ConsumeBlock(LContext, TTlsExtensionContextKind.ServerHello,
      LHello.Extensions);
    // a server that echoed the (empty) session_ticket extension will send a NewSessionTicket
    FExpectNewSessionTicket := LContext.SessionTicketOffered;
    // a server that echoed status_request will send a CertificateStatus message
    FServerWillStaple := LContext.StatusRequestResponsePending;
    // the server's ALPN choice must be one this client offered (RFC 7301 3.2)
    if LContext.SelectedAlpn <> '' then
    begin
      if not (TArrayUtilities.Contains<string>(FParams.AlpnProtocols,
        LContext.SelectedAlpn)) then
        raise EFatalAlertTlsLibException.CreateRes(
          TTlsAlertDescription.IllegalParameter, @SUnofferedAlpn);
      TArrayUtilities.Append<THandshakeEffect>(Result,
        THandshakeEffects.SelectAlpn(LContext.SelectedAlpn));
    end;
    // the server resumed if it echoed the non-empty session id the ClientHello offered
    if (FResumptionOffer <> nil) and (System.Length(FOfferedSessionId) > 0) and
      TArrayUtilities.AreEqual(FServerSessionId, FOfferedSessionId) then
    begin
      // keep the effects already accumulated for this ServerHello (the ALPN selection, which a
      // 1.2 server re-negotiates on the abbreviated handshake per RFC 7301) ahead of the
      // resumption's key-install effects
      Result := TArrayUtilities.Concat<THandshakeEffect>(Result,
        BeginAbbreviatedHandshake(LContext));
      Exit;
    end;
    // the server echoed our session id while we offered nothing to resume (e.g. a random
    // TLS 1.3 compatibility-mode session id): it is falsely signalling resumption of a
    // session we cannot resume (RFC 5246 7.4.1.3)
    if (FResumptionOffer = nil) and (System.Length(FOfferedSessionId) > 0) and
      TArrayUtilities.AreEqual(FServerSessionId, FOfferedSessionId) then
      raise EFatalAlertTlsLibException.CreateRes(
        TTlsAlertDescription.IllegalParameter, @SEchoedInvalidSessionId);
    FUseExtendedMasterSecret := FParams.OfferExtendedMasterSecret and
      LContext.ExtendedMasterSecret;
    // an operator that requires EMS must not derive a plain 1.2 master secret; a stripping
    // MITM would otherwise re-expose the RFC 7627 / triple-handshake class as a silent no-op
    if FParams.RequireExtendedMasterSecret and not FUseExtendedMasterSecret then
      raise EFatalAlertTlsLibException.CreateRes(
        TTlsAlertDescription.HandshakeFailure, @SNoExtendedMasterSecret);
  finally
    LContext.Free;
  end;

  FPhase := TPhase.WaitCertificate;
end;

function TTls12ClientStateMachine.VerifyServerChain: TArray<THandshakeEffect>;
var
  LAlert: TTlsAlertDescription;
  LVerified: TVerifiedChain;
begin
  Result := nil;
  // fail-closed trust: no verifier or a negative verdict aborts with the reason's alert
  if FParams.CertificateVerifier = nil then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.InternalError, @SNoCertificateVerifier);
  if not FParams.CertificateVerifier.VerifyServerCertificate(FCertChain,
    FParams.ExpectedServerName, FReceivedOcspStaple, LVerified, LAlert) then
    raise EFatalAlertTlsLibException.CreateRes(LAlert, @SUntrustedCertificate);
  // surface the presented chain and the validated path for connection info (read-only)
  Result := TArray<THandshakeEffect>.Create(
    THandshakeEffects.PeerCertificateChain(FCertChain, LVerified.Path));
  // async verdict: the pipeline accepted the chain; park for the host's out-of-band decision.
  // Carry both the presented chain and the validated path (issuer at index 1), so a live resolver
  // authenticates against the PKIX issuer, never a guess. The rest of the flight stays buffered
  // until SetCertificateVerdict resumes it
  if TPeerAuthentication.ShouldPark(FParams.Deferral, LVerified.Outcome) then
    TArrayUtilities.Append<THandshakeEffect>(Result,
      ParkForVerdict(FCertChain, LVerified.Path,
      FParams.ExpectedServerName.ToString, FReceivedOcspStaple));
end;

function TTls12ClientStateMachine.ProcessCertificate(
  const AMessage: TTlsHandshakeMessage): TArray<THandshakeEffect>;
var
  LKind: TSignatureKeyKind;
  LEcGroup: UInt16;
begin
  Result := nil;
  FParsedServerLeaf := nil;
  FCertChain := THandshakeMessages.DecodeCertificate12(AMessage.Body);
  if System.Length(FCertChain) = 0 then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.DecodeError, @SEmptyCertificate);
  // a server leaf that is not a well-formed certificate is a decode error
  FParsedServerLeaf := TCertificateVerify.ParseWellFormedLeaf(FParams.Inspector,
    FCertChain[0]);

  if FParsedServerLeaf.KeyKind(LKind, LEcGroup) then
  begin
    // the leaf key algorithm must match the negotiated suite's authentication method (a
    // CertificateCipherMismatch, RFC 5246 7.4.2): an *_RSA suite needs an RSA leaf; an
    // *_ECDSA suite an EC-family leaf - ECDSA or, per RFC 8422, an EdDSA key
    if ((FSelectedSuite.Auth = TAuthMethod.Rsa) and (LKind <> TSignatureKeyKind.Rsa)) or
      ((FSelectedSuite.Auth = TAuthMethod.Ecdsa) and
      not (LKind in [TSignatureKeyKind.Ecdsa, TSignatureKeyKind.Ed25519, TSignatureKeyKind.Ed448])) then
      raise EFatalAlertTlsLibException.CreateRes(
        TTlsAlertDescription.IllegalParameter, @SCertKeyMismatchesSuite);
    // an ECDSA leaf's curve must be one we advertised: TLS 1.2 takes the ECDSA curve from
    // supported_groups, not the signature algorithm (RFC 8422 5.1 / CheckLeafCurve)
    if (LKind = TSignatureKeyKind.Ecdsa) and
      not (TArrayUtilities.Contains<UInt16>(FParams.OfferedGroups, LEcGroup)) then
      raise EFatalAlertTlsLibException.CreateRes(
        TTlsAlertDescription.IllegalParameter, @SLeafCurveNotOffered);
  end;

  Absorb(AMessage.Raw);
  // when the server will staple, defer the trust verdict until the CertificateStatus
  // message delivers the OCSP response (RFC 6066 8)
  if FServerWillStaple then
    FPhase := TPhase.WaitCertificateStatus
  else
  begin
    Result := VerifyServerChain;
    FPhase := TPhase.WaitServerKeyExchange;
  end;
end;

function TTls12ClientStateMachine.ProcessCertificateStatus(
  const AMessage: TTlsHandshakeMessage): TArray<THandshakeEffect>;
begin
  FReceivedOcspStaple := THandshakeMessages.DecodeCertificateStatus(AMessage.Body);
  Absorb(AMessage.Raw);
  // surface the staple so an integration can inspect it, then any async park effect
  Result := TArray<THandshakeEffect>.Create(
    THandshakeEffects.PeerOcspStaple(FReceivedOcspStaple));
  Result := TArrayUtilities.Concat<THandshakeEffect>(Result, VerifyServerChain);
  FPhase := TPhase.WaitServerKeyExchange;
end;

function TTls12ClientStateMachine.ProcessServerKeyExchange(
  const AMessage: TTlsHandshakeMessage): TArray<THandshakeEffect>;
var
  LSke: TTlsServerKeyExchangeEcdhe;
  LScheme: TSignatureScheme;
  LContent: TBytes;
begin
  Result := nil;
  LSke := THandshakeMessages.DecodeServerKeyExchangeEcdhe(AMessage.Body);
  // the leaf must sign with a scheme we offered (RFC 5246 7.4.3) whose key family it can produce;
  // TLS 1.2 does not bind the ECDSA curve to the scheme (that is the supported_groups list below)
  LScheme := TPeerAuthentication.RequirePeerScheme(FParams.OfferedSchemes,
    LSke.SignatureScheme, TTlsVersion.Tls12, FParsedServerLeaf);

  // the server's curve must be one we offered and a classical ECDHE group we hold;
  // the client key-exchanges on exactly this curve
  if not (TArrayUtilities.Contains<UInt16>(FParams.OfferedGroups, LSke.NamedCurve)) or
    not FParams.GroupRegistry.TryGet(LSke.NamedCurve, FCurrentGroup) or
    (FCurrentGroup.Kind <> TNamedGroupKind.Ecdhe) then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.IllegalParameter, @SBadServerKeyExchangeCurve);

  // the signature covers client_random + server_random + the ECDHE params
  LContent := TArrayUtilities.Concat(
    TArrayUtilities.Concat(FParams.ClientRandom, FServerRandom),
    THandshakeMessages.EcdheServerParams(LSke.NamedCurve, LSke.PublicKey));
  TPeerAuthentication.VerifyPeerSignature(FParams.Crypto, FParsedServerLeaf, LScheme,
    LContent, LSke.Signature);

  FServerEcdhePublic := LSke.PublicKey;
  Absorb(AMessage.Raw);
  FPhase := TPhase.WaitServerHelloDone;
end;

procedure TTls12ClientStateMachine.DeriveSecrets(const APreMaster: ISecretBuffer;
  const ASessionHash: TBytes);
begin
  FSchedule := TTls12KeySchedule.Create(FParams.Crypto,
    FSelectedSuite.Common.Hash, FSelectedSuite.Common.KeyLength, FSelectedSuite.Common.Aead);
  FSchedule.SetRandoms(FParams.ClientRandom, FServerRandom);
  FSchedule.SetPreMasterSecret(APreMaster);
  if FUseExtendedMasterSecret then
    FSchedule.DeriveExtendedMasterSecret(ASessionHash)
  else
    FSchedule.DeriveMasterSecret;
  FSchedule.DeriveKeyBlock;
end;

procedure TTls12ClientStateMachine.ProcessCertificateRequest(
  const AMessage: TTlsHandshakeMessage);
var
  LRequest: TTlsCertificateRequest12;
begin
  // at most one CertificateRequest, sent before ServerHelloDone (RFC 5246 7.4.4); a second one
  // has no legal slot
  if FCertificateRequested then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.UnexpectedMessage, @SCertificateRequestTwice);
  LRequest := THandshakeMessages.DecodeCertificateRequest12(AMessage.Body);
  FClientAuthSchemes := LRequest.SupportedSignatureAlgorithms;
  FClientAuthCertTypes := LRequest.CertificateTypes;
  FRequestedCertificateAuthorities := LRequest.CertificateAuthorities;
  FCertificateRequested := True;
  Absorb(AMessage.Raw);
end;

function TTls12ClientStateMachine.AppendClientCertificate(
  var AEffects: TArray<THandshakeEffect>; out AScheme: TSignatureScheme): Boolean;
const
  RsaSignCertType = Byte(1); // RFC 5246 7.4.4 ClientCertificateType.rsa_sign
  EcdsaSignCertType = Byte(64); // ecdsa_sign (RFC 8422 covers the EdDSA leaf too)
var
  LScheme: TSignatureScheme;
  LChain: TArray<TBytes>;
  LCertBytes: TBytes;
  LKind: TSignatureKeyKind;
  LEcGroup: UInt16;
  LCertType: Byte;
begin
  Result := False;
  AScheme := TSignatureScheme.ECDSA_SECP256R1_SHA256; // overwritten when a scheme is found
  LChain := FParams.ClientCredential.CertificateChain;
  // the leaf's certificate type must be one the server named in certificate_types, and a
  // usable signature scheme must exist; otherwise present an empty Certificate (RFC 5246 7.4.4)
  LCertType := 0;
  if (System.Length(LChain) > 0) and
    FParams.Inspector.KeyKind(LChain[0], LKind, LEcGroup) then
  begin
    if LKind = TSignatureKeyKind.Rsa then
      LCertType := RsaSignCertType
    else
      LCertType := EcdsaSignCertType;
  end;
  if (LCertType <> 0) and
    (TArrayUtilities.Contains<Byte>(FClientAuthCertTypes, LCertType)) then
    for LScheme in FParams.ClientCredential.PrivateKey.CapableSchemes do
      if TArrayUtilities.Contains<UInt16>(FClientAuthSchemes, LScheme.ToCode) then
      begin
        AScheme := LScheme;
        Result := True;
        Break;
      end;
  // send the chain when a usable scheme exists, otherwise an empty client Certificate
  if Result then
    LCertBytes := THandshakeFraming.Frame(TTlsHandshakeType.Certificate,
      THandshakeMessages.EncodeCertificate12(LChain))
  else
    LCertBytes := THandshakeFraming.Frame(TTlsHandshakeType.Certificate,
      THandshakeMessages.EncodeCertificate12(nil));
  Absorb(LCertBytes);
  TArrayUtilities.Append<THandshakeEffect>(AEffects,
    THandshakeEffects.SendHandshake(LCertBytes));
end;

function TTls12ClientStateMachine.ProcessServerHelloDone(
  const AMessage: TTlsHandshakeMessage): TArray<THandshakeEffect>;
var
  LClientPublic, LCke, LClientFinished, LVerifyData, LCertVerifyBytes: TBytes;
  LShared: ISecretBuffer;
  LCkeMsg: TTlsClientKeyExchangeEcdhe;
  LScheme: TSignatureScheme;
  LSigner: ISignatureSigner;
  LVerify: TTlsCertificateVerify;
  LSentCertificate: Boolean;
begin
  // ServerHelloDone is a zero-length message (RFC 5246 7.4.5); trailing data is a decode_error
  if System.Length(AMessage.Body) <> 0 then
    raise EDecodeErrorTlsLibException.CreateRes(@SServerHelloDoneNotEmpty);
  Absorb(AMessage.Raw);
  Result := nil;

  // mutual TLS: the client Certificate precedes the ClientKeyExchange (RFC 5246 7.3)
  LSentCertificate := False;
  if FCertificateRequested then
    LSentCertificate := AppendClientCertificate(Result, LScheme);

  // the client ephemeral is generated here; Encapsulate returns its public value (the
  // ClientKeyExchange point) and the ECDHE shared secret (the premaster)
  FCurrentGroup.Encapsulate(FServerEcdhePublic, LClientPublic, LShared);
  LCkeMsg.PublicKey := LClientPublic;
  LCke := THandshakeFraming.Frame(TTlsHandshakeType.ClientKeyExchange,
    THandshakeMessages.EncodeClientKeyExchangeEcdhe(LCkeMsg));
  Absorb(LCke);
  TArrayUtilities.Append<THandshakeEffect>(Result,
    THandshakeEffects.SendHandshake(LCke));

  // session_hash for extended_master_secret is over ClientHello..ClientKeyExchange
  DeriveSecrets(LShared, FTranscript.CurrentHash);

  // a CertificateVerify proves possession over the raw handshake log through the CKE
  if LSentCertificate then
  begin
    LSigner := FParams.Crypto.Signing.CreateSignatureSigner(LScheme,
      FParams.ClientCredential.PrivateKey);
    LSigner.Update(FHandshakeLog.Bytes, 0, FHandshakeLog.Size);
    LVerify.Algorithm := LScheme.ToCode;
    LVerify.Signature := LSigner.Sign;
    LCertVerifyBytes := THandshakeFraming.Frame(TTlsHandshakeType.CertificateVerify,
      THandshakeMessages.EncodeCertificateVerify(LVerify));
    Absorb(LCertVerifyBytes);
    TArrayUtilities.Append<THandshakeEffect>(Result,
      THandshakeEffects.SendHandshake(LCertVerifyBytes));
  end;

  // change_cipher_spec, then the write side moves to the application keys
  TArrayUtilities.Append<THandshakeEffect>(Result,
    THandshakeEffects.SendChangeCipherSpec);
  TArrayUtilities.Append<THandshakeEffect>(Result,
    THandshakeEffects.InstallKeys(FSchedule.TrafficKeys(TTlsEpoch.Application,
    TTlsDirection.ClientWrite), TRecordSide.WriteSide, FSelectedSuite.Common.Aead,
    TTlsVersion.Tls12));

  // the client Finished is over the transcript through CertificateVerify (or the CKE)
  LVerifyData := FSchedule.ComputeVerifyData(TTlsDirection.ClientWrite,
    FTranscript.CurrentHash);
  LClientFinished := THandshakeFraming.Frame(TTlsHandshakeType.Finished,
    THandshakeMessages.EncodeFinished(LVerifyData));
  FTranscript.Update(LClientFinished);
  TArrayUtilities.Append<THandshakeEffect>(Result,
    THandshakeEffects.SendHandshake(LClientFinished));
  if FExpectNewSessionTicket then
    // a plaintext NewSessionTicket precedes the server Finished; keep the read epoch
    // plaintext until it is consumed (RFC 5077 3.3)
    FPhase := TPhase.WaitNewSessionTicket
  else
  begin
    // the read side is installed for the server's encrypted Finished
    TArrayUtilities.Append<THandshakeEffect>(Result,
      THandshakeEffects.InstallKeys(FSchedule.TrafficKeys(TTlsEpoch.Application,
      TTlsDirection.ServerWrite), TRecordSide.ReadSide, FSelectedSuite.Common.Aead,
      TTlsVersion.Tls12));
    FPhase := TPhase.WaitServerFinished;
  end;
end;

function TTls12ClientStateMachine.ProcessNewSessionTicket(
  const AMessage: TTlsHandshakeMessage): TArray<THandshakeEffect>;
var
  LNst: TTls12NewSessionTicket;
begin
  // the NewSessionTicket (RFC 5077) arrives plaintext before the server ChangeCipherSpec;
  // it is folded into the transcript the server Finished covers, then the read epoch opens
  LNst := THandshakeMessages.DecodeTls12NewSessionTicket(AMessage.Body);
  FReceivedTicket := LNst.Ticket;
  FReceivedTicketLifetime := LNst.TicketLifetimeHint;
  Absorb(AMessage.Raw);
  FPhase := TPhase.WaitServerFinished;
  Result := TArray<THandshakeEffect>.Create(
    THandshakeEffects.InstallKeys(FSchedule.TrafficKeys(TTlsEpoch.Application,
    TTlsDirection.ServerWrite), TRecordSide.ReadSide, FSelectedSuite.Common.Aead,
    TTlsVersion.Tls12));
end;

function TTls12ClientStateMachine.CacheCompletedSession: TArray<THandshakeEffect>;
var
  LSession: IResumableSession;
  LPeerChain: TArray<TBytes>;
  LLifetime: UInt32;
begin
  Result := nil;
  if FParams.SessionCache = nil then
    Exit;
  // nothing to resume with unless the server issued a session id or a ticket
  if (System.Length(FServerSessionId) = 0) and (System.Length(FReceivedTicket) = 0) then
    Exit;
  // a seven-day retention cap (local policy) bounds a stored ticket; a lifetime_hint of 0 is
  // left unspecified per RFC 5077 3.3 rather than discarded
  LLifetime := FReceivedTicketLifetime;
  if LLifetime > MaxTicketLifetimeSeconds then
    LLifetime := MaxTicketLifetimeSeconds;
  // carry the verified server chain so an opt-in ReverifyOnResume can re-check it on resume. On an
  // abbreviated handshake no Certificate was sent, so the session inherits the resumed chain
  LPeerChain := FCertChain;
  if (System.Length(LPeerChain) = 0) and (FResumptionOffer <> nil) then
    LPeerChain := FResumptionOffer.PeerCertificates;
  LSession := TResumableSession.CreateTls12(FSelectedSuite.Common.Code,
    FSelectedSuite.Common.Hash, FSchedule.MasterSecret, FServerSessionId,
    FReceivedTicket, FUseExtendedMasterSecret, '', FParams.ServerName,
    LLifetime, 0,
    FParams.Clock.NowUnixMillis, LPeerChain);
  FParams.SessionCache.Store(CacheServerIdentity, FParams.ServerName, LSession);
  if System.Length(FReceivedTicket) > 0 then
    Result := TArray<THandshakeEffect>.Create(
      THandshakeEffects.RaiseEvent(TTlsEventKind.SessionTicketReceived));
end;

function TTls12ClientStateMachine.ProcessServerFinished(
  const AMessage: TTlsHandshakeMessage): TArray<THandshakeEffect>;
begin
  // the server Finished is over the transcript through the client Finished (and any ticket)
  if not FSchedule.VerifyFinished(TTlsDirection.ServerWrite,
    FTranscript.CurrentHash, AMessage.Body) then
    raise EFatalAlertTlsLibException.CreateRes(TTlsAlertDescription.DecryptError,
      @SBadServerFinished);

  FPhase := TPhase.Connected;
  MarkConnected;
  Result := CacheCompletedSession;
  // the session is cached (it captured the master secret); release the handshake-stage key
  // material - the connection keeps the master secret for the RFC 5705 exporter
  FSchedule.ForgetHandshakeSecrets;
  // a full TLS 1.2 handshake here is ECDHE (the only 1.2 key exchange), so FCurrentGroup is set
  TArrayUtilities.Append<THandshakeEffect>(Result,
    THandshakeEffects.ConnectionParams(FSelectedSuite.Common.Code,
    FCurrentGroup.Code, False, FParams.ServerName));
  if System.Length(FRequestedCertificateAuthorities) > 0 then
    TArrayUtilities.Append<THandshakeEffect>(Result,
      THandshakeEffects.RequestedCertificateAuthorities(
      FRequestedCertificateAuthorities));
  TArrayUtilities.Append<THandshakeEffect>(Result,
    THandshakeEffects.HandshakeEstablished);
end;

procedure TTls12ClientStateMachine.ReverifyResumedServer;
var
  LVerifier: IServerCertificateVerifier;
  LAlert: TTlsAlertDescription;
  LVerified: TVerifiedChain;
begin
  // prefer the resumption-occasion verifier (no must-staple on a chain with no Certificate);
  // fall back to the primary for a direct caller that wired only one
  LVerifier := FParams.ResumeCertificateVerifier;
  if LVerifier = nil then
    LVerifier := FParams.CertificateVerifier;
  if LVerifier = nil then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.InternalError, @SNoCertificateVerifier);
  // an empty stored chain cannot be re-verified, so it fails closed
  LAlert := TTlsAlertDescription.BadCertificate;
  if (FResumptionOffer = nil) or (System.Length(FResumptionOffer.PeerCertificates) = 0) or
    not LVerifier.VerifyServerCertificate(
    FResumptionOffer.PeerCertificates, FParams.ExpectedServerName, nil, LVerified, LAlert) then
    raise EFatalAlertTlsLibException.CreateRes(LAlert, @SUntrustedCertificate);
  FResumeValidatedPath := LVerified.Path;
end;

function TTls12ClientStateMachine.BeginAbbreviatedHandshake(
  const AContext: TExtensionContext): TArray<THandshakeEffect>;
begin
  // the server must resume with the cached suite and the same EMS choice (RFC 7627 5.3)
  if FSelectedSuite.Common.Code <> FResumptionOffer.CipherSuite then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.IllegalParameter, @SResumedSuiteMismatch);
  if AContext.ExtendedMasterSecret <> FResumptionOffer.ExtendedMasterSecret then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.IllegalParameter, @SResumedEmsMismatch);
  FUseExtendedMasterSecret := FResumptionOffer.ExtendedMasterSecret;
  // resuming a non-EMS session under a required-EMS policy would silently drop the guarantee
  if FParams.RequireExtendedMasterSecret and not FUseExtendedMasterSecret then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.HandshakeFailure, @SNoExtendedMasterSecret);
  // stricter opt-in: re-run the certificate verifier against the resumed server's stored chain
  if FParams.ResumeVerification = TResumeVerification.Reverify then
    ReverifyResumedServer;

  // reuse the stored master secret; the key block re-expands under the new randoms
  FSchedule := TTls12KeySchedule.Create(FParams.Crypto,
    FSelectedSuite.Common.Hash, FSelectedSuite.Common.KeyLength, FSelectedSuite.Common.Aead);
  FSchedule.SetRandoms(FParams.ClientRandom, FServerRandom);
  FSchedule.SetMasterSecret(FResumptionOffer.MasterSecret);
  FSchedule.DeriveKeyBlock;

  if FExpectNewSessionTicket then
  begin
    // a plaintext NewSessionTicket precedes the server Finished; keep the read epoch plaintext
    FPhase := TPhase.WaitAbbreviatedNewSessionTicket;
    Result := nil;
  end
  else
  begin
    FPhase := TPhase.WaitAbbreviatedServerFinished;
    Result := TArray<THandshakeEffect>.Create(
      THandshakeEffects.InstallKeys(FSchedule.TrafficKeys(TTlsEpoch.Application,
      TTlsDirection.ServerWrite), TRecordSide.ReadSide, FSelectedSuite.Common.Aead,
      TTlsVersion.Tls12));
  end;
end;

function TTls12ClientStateMachine.ProcessAbbreviatedNewSessionTicket(
  const AMessage: TTlsHandshakeMessage): TArray<THandshakeEffect>;
var
  LNst: TTls12NewSessionTicket;
begin
  LNst := THandshakeMessages.DecodeTls12NewSessionTicket(AMessage.Body);
  // a zero-length ticket on a renewal means "no new ticket": keep the resumed session's existing
  // ticket rather than replacing it with an empty one that could not resume (RFC 5077 3.3)
  if (System.Length(LNst.Ticket) = 0) and (FResumptionOffer <> nil) then
  begin
    FReceivedTicket := FResumptionOffer.SessionTicket;
    FReceivedTicketLifetime := FResumptionOffer.TicketLifetime;
  end
  else
  begin
    FReceivedTicket := LNst.Ticket;
    FReceivedTicketLifetime := LNst.TicketLifetimeHint;
  end;
  Absorb(AMessage.Raw);
  FPhase := TPhase.WaitAbbreviatedServerFinished;
  Result := TArray<THandshakeEffect>.Create(
    THandshakeEffects.InstallKeys(FSchedule.TrafficKeys(TTlsEpoch.Application,
    TTlsDirection.ServerWrite), TRecordSide.ReadSide, FSelectedSuite.Common.Aead,
    TTlsVersion.Tls12));
end;

function TTls12ClientStateMachine.ProcessAbbreviatedServerFinished(
  const AMessage: TTlsHandshakeMessage): TArray<THandshakeEffect>;
begin
  // the server Finished is over ClientHello, ServerHello, [NewSessionTicket]; verify it before
  // any park so we never withhold a flight on an unauthenticated Finished
  if not FSchedule.VerifyFinished(TTlsDirection.ServerWrite,
    FTranscript.CurrentHash, AMessage.Body) then
    raise EFatalAlertTlsLibException.CreateRes(TTlsAlertDescription.DecryptError,
      @SBadServerFinished);
  FTranscript.Update(AMessage.Raw);

  // an abbreviated handshake carries no Certificate: surface the server chain the session stored,
  // with the re-verified path when ResumeVerification re-ran the pipeline (empty otherwise). Before
  // any park, so connection info reads it while parked - the ordering a full handshake already has.
  Result := nil;
  if (FResumptionOffer <> nil) and (System.Length(FResumptionOffer.PeerCertificates) > 0) then
    TArrayUtilities.Append<THandshakeEffect>(Result,
      THandshakeEffects.PeerCertificateChain(FResumptionOffer.PeerCertificates,
      FResumeValidatedPath));

  // reverify-on-resume + async verdict: the inline reverify at the ServerHello accepted (under a
  // live posture it defers), so park now and withhold the client's closing flight until the
  // out-of-band verdict resolves - live revocation decides before we commit our Finished. The
  // transcript is untouched between here and the resume, so the verify_data is identical either way.
  // A resumption carries no staple, so the verifier never settles revocation inline; the park stands.
  if (FParams.ResumeVerification = TResumeVerification.Reverify) and
    (FParams.Deferral <> TVerdictDeferral.None) then
  begin
    FPhase := TPhase.WaitResumeVerdict;
    TArrayUtilities.Append<THandshakeEffect>(Result,
      ParkForVerdict(FResumptionOffer.PeerCertificates,
      FResumeValidatedPath, FParams.ExpectedServerName.ToString, nil));
    Exit;
  end;

  Result := TArrayUtilities.Concat<THandshakeEffect>(Result, BuildAbbreviatedClientFlight);
end;

function TTls12ClientStateMachine.BuildAbbreviatedClientFlight
  : TArray<THandshakeEffect>;
var
  LVerifyData, LClientFinished: TBytes;
begin
  // the client Finished is over the abbreviated transcript including the server Finished
  LVerifyData := FSchedule.ComputeVerifyData(TTlsDirection.ClientWrite,
    FTranscript.CurrentHash);
  LClientFinished := THandshakeFraming.Frame(TTlsHandshakeType.Finished,
    THandshakeMessages.EncodeFinished(LVerifyData));

  FPhase := TPhase.Connected;
  MarkConnected;
  Result := TArray<THandshakeEffect>.Create(
    THandshakeEffects.SendChangeCipherSpec,
    THandshakeEffects.InstallKeys(FSchedule.TrafficKeys(TTlsEpoch.Application,
    TTlsDirection.ClientWrite), TRecordSide.WriteSide, FSelectedSuite.Common.Aead,
    TTlsVersion.Tls12),
    THandshakeEffects.SendHandshake(LClientFinished));
  // re-cache the resumed session (carrying any freshly issued ticket) for the next resume
  Result := TArrayUtilities.Concat<THandshakeEffect>(Result, CacheCompletedSession);
  // the write keys are installed and the session is re-cached; release the handshake-stage material
  FSchedule.ForgetHandshakeSecrets;
  // an abbreviated resumption performs no fresh key exchange, so there is no negotiated group
  TArrayUtilities.Append<THandshakeEffect>(Result,
    THandshakeEffects.ConnectionParams(FSelectedSuite.Common.Code, 0, True,
    FParams.ServerName));
  TArrayUtilities.Append<THandshakeEffect>(Result,
    THandshakeEffects.HandshakeEstablished);
end;

function TTls12ClientStateMachine.ContinueAfterVerdict: TArray<THandshakeEffect>;
begin
  // only the reverify-on-resume park withholds a continuation; other paths resume by draining
  // the buffered server flight, so there is nothing to emit for them
  Result := nil;
  if FPhase = TPhase.WaitResumeVerdict then
    Result := BuildAbbreviatedClientFlight;
end;

function TTls12ClientStateMachine.Route(
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
    TPhase.WaitCertificate:
      if LKnown and (LType = TTlsHandshakeType.Certificate) then
        Result := ProcessCertificate(AMessage)
      else
        Result := Unexpected;
    TPhase.WaitCertificateStatus:
      if LKnown and (LType = TTlsHandshakeType.CertificateStatus) then
        Result := ProcessCertificateStatus(AMessage)
      else
      begin
        // the server may omit the CertificateStatus even after echoing status_request
        // (RFC 6066 8); verify the chain with no staple and re-dispatch this message as
        // the one that follows the (absent) CertificateStatus
        Result := VerifyServerChain;
        FPhase := TPhase.WaitServerKeyExchange;
        Result := TArrayUtilities.Concat<THandshakeEffect>(Result, Route(AMessage));
      end;
    TPhase.WaitServerKeyExchange:
      if LKnown and (LType = TTlsHandshakeType.ServerKeyExchange) then
        Result := ProcessServerKeyExchange(AMessage)
      else
        Result := Unexpected;
    TPhase.WaitServerHelloDone:
      // a CertificateRequest (mutual TLS) precedes ServerHelloDone; record it and keep
      // waiting for the ServerHelloDone (RFC 5246 7.4.4)
      if LKnown and (LType = TTlsHandshakeType.CertificateRequest) then
      begin
        ProcessCertificateRequest(AMessage);
        Result := nil;
      end
      else if LKnown and (LType = TTlsHandshakeType.ServerHelloDone) then
        Result := ProcessServerHelloDone(AMessage)
      else
        Result := Unexpected;
    TPhase.WaitNewSessionTicket:
      if LKnown and (LType = TTlsHandshakeType.NewSessionTicket) then
        Result := ProcessNewSessionTicket(AMessage)
      else
        Result := Unexpected;
    TPhase.WaitServerFinished:
      if LKnown and (LType = TTlsHandshakeType.Finished) then
        Result := ProcessServerFinished(AMessage)
      else
        Result := Unexpected;
    TPhase.WaitAbbreviatedNewSessionTicket:
      if LKnown and (LType = TTlsHandshakeType.NewSessionTicket) then
        Result := ProcessAbbreviatedNewSessionTicket(AMessage)
      else
        Result := Unexpected;
    TPhase.WaitAbbreviatedServerFinished:
      if LKnown and (LType = TTlsHandshakeType.Finished) then
        Result := ProcessAbbreviatedServerFinished(AMessage)
      else
        Result := Unexpected;
    TPhase.WaitResumeVerdict:
      // parked for the out-of-band verdict; the driver buffers peer messages and resumes via
      // ResumeAfterVerdict, so any message routed here is out of turn
      Result := Unexpected;
    TPhase.Connected:
      // this client does not renegotiate: a HelloRequest is answered with a warning
      // no_renegotiation and the connection continues (RFC 5246 7.2.2, RFC 5746 4.2). Its body
      // is empty (RFC 5246 7.4.1.1); anything else is a decode_error
      if LKnown and (LType = TTlsHandshakeType.HelloRequest) then
      begin
        if System.Length(AMessage.Body) <> 0 then
          Result := TArray<THandshakeEffect>.Create(
            THandshakeEffects.Fail(TTlsAlertDescription.DecodeError))
        else
          Result := RefuseRenegotiation;
      end
      else
        Result := Unexpected;
  else
    Result := Unexpected;
  end;
end;

function TTls12ClientStateMachine.ExportKeyingMaterial(const ALabel: string;
  const AContext: TBytes; AUseContext: Boolean; ALength: Int32): TBytes;
begin
  // TLS 1.2 stays gated on completion (no False Start), so query and operation agree
  Result := nil;
  if Stage <> THandshakeStage.Connected then
    Exit;
  Result := FSchedule.ExportKeyingMaterial(ALabel, AContext, AUseContext, ALength);
end;

function TTls12ClientStateMachine.CanExportKeyingMaterial: Boolean;
begin
  Result := Stage = THandshakeStage.Connected;
end;

end.
