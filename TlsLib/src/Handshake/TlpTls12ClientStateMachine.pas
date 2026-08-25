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
  TlpArrayUtilities,
  TlpTlsAlert,
  TlpTlsVersion,
  TlpTlsLibExceptions,
  TlpISecretBuffer,
  TlpICryptoProvider,
  TlpINamedGroup,
  TlpIKeySchedule,
  TlpTls12KeySchedule,
  TlpITranscriptHash,
  TlpCryptoAlgorithms,
  TlpNegotiationTypes,
  TlpINegotiation,
  TlpNegotiationPolicy,
  TlpWireReader,
  TlpExtensionContext,
  TlpITlsExtension,
  TlpHandshakeMessage,
  TlpHandshakeMessages,
  TlpCertificateVerify,
  TlpICertificateTrust,
  TlpISigningKey,
  TlpTlsCredential,
  TlpISession,
  TlpIClock,
  TlpSession,
  TlpITlsEngine,
  TlpHandshakeEffect,
  TlpHandshakeMachineBase;

type
  /// <summary>The inputs a TLS 1.2 client handshake needs to build and drive its flight.</summary>
  TClient12HandshakeParams = record
    Provider: ICryptoProvider;
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
    CertificateVerifier: ICertificateVerifier;
    ExpectedHostName: string;
    /// <summary>The client-side cache resumption draws from and stores into. When set, the
    /// client offers session_ticket support and, if a session is cached for this server,
    /// resumes it (RFC 5077 / RFC 5246 7.3). nil disables 1.2 resumption.</summary>
    SessionCache: ISessionCache;
    /// <summary>The clock read to stamp a cached 1.2 session's issue time (RFC 5077). A required
    /// input, like Provider: the engine factory supplies one from the config, and a direct sans-IO
    /// caller must set it.</summary>
    Clock: ITlsClock;
    /// <summary>The cache key for this server; ServerName is used when empty.</summary>
    ServerIdentity: string;
    /// <summary>When set, after the built-in trust pipeline accepts the server chain the
    /// machine parks the handshake for an out-of-band verdict (the deferred-verdict seam)
    /// rather than continuing inline. Augment-only and fail-closed. OFF by default.</summary>
    AsyncVerdict: Boolean;
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
      WaitAbbreviatedServerFinished, Connected);
  var
    FParams: TClient12HandshakeParams;
    FPhase: TPhase;
    FServerRandom: TBytes;
    FCurrentGroup: INamedGroup;
    FServerEcdhePublic: TBytes;
    FCertChain: TArray<TBytes>;
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
    FHandshakeLog: TBytes;
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
    /// <summary>Records a full-handshake NewSessionTicket (RFC 5077), folds it into the
    /// transcript and installs the deferred read epoch for the server Finished.</summary>
    function ProcessNewSessionTicket(const AMessage: TTlsHandshakeMessage)
      : TArray<THandshakeEffect>;
    /// <summary>Records an abbreviated-handshake NewSessionTicket and installs the read
    /// epoch for the following server Finished.</summary>
    function ProcessAbbreviatedNewSessionTicket(const AMessage: TTlsHandshakeMessage)
      : TArray<THandshakeEffect>;
    /// <summary>Verifies the abbreviated server Finished, sends the client
    /// ChangeCipherSpec and Finished, and completes the resumed connection.</summary>
    function ProcessAbbreviatedServerFinished(const AMessage: TTlsHandshakeMessage)
      : TArray<THandshakeEffect>;
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
  public
    constructor Create(const AParams: TClient12HandshakeParams);
    function Initiates: Boolean; override;
    function Start: TArray<THandshakeEffect>; override;
    function ExportKeyingMaterial(const ALabel: string; const AContext: TBytes;
      AUseContext: Boolean; ALength: Int32): TBytes; override;
  end;

implementation

resourcestring
  SUnofferedSuite = 'the server selected a cipher suite that was not offered';
  SUnknownSelectedSuite = 'the selected cipher suite is not in the registry';
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
  SUnofferedScheme = 'the ServerKeyExchange uses a signature scheme that was not offered';
  SUnofferedAlpn = 'the server selected an ALPN protocol that was not offered';
  SBadServerKeyExchangeCurve = 'the ServerKeyExchange named a group that was not offered';
  SBadServerKeyExchangeSig = 'the ServerKeyExchange signature did not verify';
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
end;

procedure TTls12ClientStateMachine.Absorb(const ARaw: TBytes);
begin
  FTranscript.Update(ARaw);
  FHandshakeLog := TArrayUtilities.Concat(FHandshakeLog, ARaw);
end;

procedure TTls12ClientStateMachine.RememberOffered(
  const AFramedClientHello: TBytes);
var
  LHello: TTlsClientHello;
  LReader, LOuter, LData: TWireReader;
begin
  FOfferedExtensions := nil;
  // strip the 4-byte handshake header to reach the body
  LHello := THandshakeMessages.DecodeClientHello(System.Copy(AFramedClientHello, 4,
    System.Length(AFramedClientHello) - 4));
  LReader := TWireReader.Create(LHello.Extensions);
  LOuter := LReader.OpenVector(2);
  while not LOuter.EndReached do
  begin
    TArrayUtilities.Append<UInt16>(FOfferedExtensions, LOuter.ReadUInt16);
    LData := LOuter.OpenVector(2);
    LData.ReadBytes(LData.Remaining);
  end;
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
          FOfferedSessionId := FParams.Provider.Primitives.GetRandom.GenerateBytes(32);
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
end;

function TTls12ClientStateMachine.Initiates: Boolean;
begin
  Result := True;
end;

function TTls12ClientStateMachine.Start: TArray<THandshakeEffect>;
var
  LClientHello: TBytes;
  LCached: IResumableSession;
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
  // resumption: pop one cached TLS 1.2 session for this server to offer in the ClientHello
  if (FParams.SessionCache <> nil) and
    FParams.SessionCache.Take(CacheServerIdentity, FParams.ServerName, LCached) and
    (LCached.Version.WireValue = TlsWireVersionTls12) then
    FResumptionOffer := LCached;
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
  FTranscript.Activate(FParams.Provider.Primitives.CreateHash(FSelectedSuite.Common.Hash));
  Absorb(AMessage.Raw);

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

  // a 1.3-capable client aborts a stamped downgrade (RFC 8446 4.1.3): a genuine
  // 1.2-only server never stamps the sentinel
  if TDowngradeProtection.IsDowngradeAttack(LHello.Random, FClientSupportsTls13,
    TlsWireVersionTls12) then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.IllegalParameter, @SDowngradeDetected);

  FPhase := TPhase.WaitCertificate;
end;

function TTls12ClientStateMachine.VerifyServerChain: TArray<THandshakeEffect>;
var
  LAlert: TTlsAlertDescription;
begin
  Result := nil;
  // fail-closed trust: no verifier or a negative verdict aborts with the reason's alert
  if FParams.CertificateVerifier = nil then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.InternalError, @SNoCertificateVerifier);
  if not FParams.CertificateVerifier.Verify(FCertChain, FParams.ExpectedHostName,
    FReceivedOcspStaple, LAlert) then
    raise EFatalAlertTlsLibException.CreateRes(LAlert, @SUntrustedCertificate);
  // surface the validated chain for connection info (read-only)
  Result := TArray<THandshakeEffect>.Create(
    THandshakeEffects.PeerCertificateChain(FCertChain));
  // async verdict: the pipeline accepted the chain; park for the host's out-of-band
  // decision (the rest of the flight stays buffered until SetCertificateVerdict resumes it)
  if FParams.AsyncVerdict then
    TArrayUtilities.Append<THandshakeEffect>(Result,
      THandshakeEffects.AwaitCertificateVerdict(FCertChain,
      FParams.ExpectedHostName));
end;

function TTls12ClientStateMachine.ProcessCertificate(
  const AMessage: TTlsHandshakeMessage): TArray<THandshakeEffect>;
var
  LKind: TCertKeyKind;
  LEcGroup: UInt16;
begin
  Result := nil;
  FCertChain := THandshakeMessages.DecodeCertificate12(AMessage.Body);
  if System.Length(FCertChain) = 0 then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.DecodeError, @SEmptyCertificate);
  // a server leaf that is not a well-formed certificate is a decode error
  TCertificateVerify.EnsureWellFormedLeaf(FParams.Provider, FCertChain[0]);

  if FParams.Provider.Certificates.KeyKind(FCertChain[0], LKind, LEcGroup) then
  begin
    // the leaf key algorithm must match the negotiated suite's authentication method (a
    // CertificateCipherMismatch, RFC 5246 7.4.2): an *_RSA suite needs an RSA leaf; an
    // *_ECDSA suite an EC-family leaf - ECDSA or, per RFC 8422, an EdDSA key
    if ((FSelectedSuite.Auth = TAuthMethod.Rsa) and (LKind <> TCertKeyKind.Rsa)) or
      ((FSelectedSuite.Auth = TAuthMethod.Ecdsa) and
      not (LKind in [TCertKeyKind.Ecdsa, TCertKeyKind.Ed25519, TCertKeyKind.Ed448])) then
      raise EFatalAlertTlsLibException.CreateRes(
        TTlsAlertDescription.IllegalParameter, @SCertKeyMismatchesSuite);
    // an ECDSA leaf's curve must be one we advertised: TLS 1.2 takes the ECDSA curve from
    // supported_groups, not the signature algorithm (RFC 8422 5.1 / CheckLeafCurve)
    if (LKind = TCertKeyKind.Ecdsa) and
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
  LContent, LPublicKeyInfo: TBytes;
  LVerifier: ISignatureVerifier;
begin
  Result := nil;
  LSke := THandshakeMessages.DecodeServerKeyExchangeEcdhe(AMessage.Body);
  if not (TArrayUtilities.Contains<UInt16>(FParams.OfferedSchemes,
    LSke.SignatureScheme)) then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.IllegalParameter, @SUnofferedScheme);
  if not TSignatureScheme.TryFromCode(LSke.SignatureScheme, LScheme) then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.IllegalParameter, @SUnofferedScheme);

  // the leaf that signs the ServerKeyExchange must permit digitalSignature and, for an
  // rsa_pss_rsae_* scheme, not be an id-RSASSA-PSS key
  TCertificateVerify.EnforceSigningLeafPolicy(FParams.Provider,
    FCertChain[0], LScheme, False);

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
  LPublicKeyInfo := FParams.Provider.Certificates.PublicKeyInfo(FCertChain[0]);
  LVerifier := FParams.Provider.Signing.CreateSignatureVerifier(LScheme, LPublicKeyInfo);
  LVerifier.Update(LContent, 0, System.Length(LContent));
  if not LVerifier.Verify(LSke.Signature) then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.DecryptError, @SBadServerKeyExchangeSig);

  FServerEcdhePublic := LSke.PublicKey;
  Absorb(AMessage.Raw);
  FPhase := TPhase.WaitServerHelloDone;
end;

procedure TTls12ClientStateMachine.DeriveSecrets(const APreMaster: ISecretBuffer;
  const ASessionHash: TBytes);
begin
  FSchedule := TTls12KeySchedule.Create(FParams.Provider,
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
  LKind: TCertKeyKind;
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
    FParams.Provider.Certificates.KeyKind(LChain[0], LKind, LEcGroup) then
  begin
    if LKind = TCertKeyKind.Rsa then
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
    LSigner := FParams.Provider.Signing.CreateSignatureSigner(LScheme,
      FParams.ClientCredential.PrivateKey);
    LSigner.Update(FHandshakeLog, 0, System.Length(FHandshakeLog));
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
begin
  Result := nil;
  if FParams.SessionCache = nil then
    Exit;
  // nothing to resume with unless the server issued a session id or a ticket
  if (System.Length(FServerSessionId) = 0) and (System.Length(FReceivedTicket) = 0) then
    Exit;
  LSession := TResumableSession.CreateTls12(FSelectedSuite.Common.Code,
    FSelectedSuite.Common.Hash, FSchedule.MasterSecret, FServerSessionId,
    FReceivedTicket, FUseExtendedMasterSecret, '', FParams.ServerName,
    FReceivedTicketLifetime, 0,
    FParams.Clock.NowUnixMillis);
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
  Result := CacheCompletedSession;
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

  // reuse the stored master secret; the key block re-expands under the new randoms
  FSchedule := TTls12KeySchedule.Create(FParams.Provider,
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
  FReceivedTicket := LNst.Ticket;
  FReceivedTicketLifetime := LNst.TicketLifetimeHint;
  Absorb(AMessage.Raw);
  FPhase := TPhase.WaitAbbreviatedServerFinished;
  Result := TArray<THandshakeEffect>.Create(
    THandshakeEffects.InstallKeys(FSchedule.TrafficKeys(TTlsEpoch.Application,
    TTlsDirection.ServerWrite), TRecordSide.ReadSide, FSelectedSuite.Common.Aead,
    TTlsVersion.Tls12));
end;

function TTls12ClientStateMachine.ProcessAbbreviatedServerFinished(
  const AMessage: TTlsHandshakeMessage): TArray<THandshakeEffect>;
var
  LVerifyData, LClientFinished: TBytes;
begin
  // the server Finished is over ClientHello, ServerHello, [NewSessionTicket]
  if not FSchedule.VerifyFinished(TTlsDirection.ServerWrite,
    FTranscript.CurrentHash, AMessage.Body) then
    raise EFatalAlertTlsLibException.CreateRes(TTlsAlertDescription.DecryptError,
      @SBadServerFinished);
  FTranscript.Update(AMessage.Raw);

  // the client Finished is over the abbreviated transcript including the server Finished
  LVerifyData := FSchedule.ComputeVerifyData(TTlsDirection.ClientWrite,
    FTranscript.CurrentHash);
  LClientFinished := THandshakeFraming.Frame(TTlsHandshakeType.Finished,
    THandshakeMessages.EncodeFinished(LVerifyData));

  FPhase := TPhase.Connected;
  Result := TArray<THandshakeEffect>.Create(
    THandshakeEffects.SendChangeCipherSpec,
    THandshakeEffects.InstallKeys(FSchedule.TrafficKeys(TTlsEpoch.Application,
    TTlsDirection.ClientWrite), TRecordSide.WriteSide, FSelectedSuite.Common.Aead,
    TTlsVersion.Tls12),
    THandshakeEffects.SendHandshake(LClientFinished));
  // re-cache the resumed session (carrying any freshly issued ticket) for the next resume
  Result := TArrayUtilities.Concat<THandshakeEffect>(Result, CacheCompletedSession);
  // an abbreviated resumption performs no fresh key exchange, so there is no negotiated group
  TArrayUtilities.Append<THandshakeEffect>(Result,
    THandshakeEffects.ConnectionParams(FSelectedSuite.Common.Code, 0, True,
    FParams.ServerName));
  TArrayUtilities.Append<THandshakeEffect>(Result,
    THandshakeEffects.HandshakeEstablished);
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
  else
    Result := Unexpected;
  end;
end;

function TTls12ClientStateMachine.ExportKeyingMaterial(const ALabel: string;
  const AContext: TBytes; AUseContext: Boolean; ALength: Int32): TBytes;
begin
  Result := nil;
  if FSchedule = nil then
    Exit;
  Result := FSchedule.ExportKeyingMaterial(ALabel, AContext, AUseContext, ALength);
end;

end.
