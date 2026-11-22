{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpTlsEngineFactory;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpArrayUtilities,
  TlpTlsLibExceptions,
  TlpTlsVersion,
  TlpCryptoDomainTypes,
  TlpSecretBuffer,
  TlpINamedGroup,
  TlpNamedGroups,
  TlpClientPskPath,
  TlpINegotiation,
  TlpICertificateTrust,
  TlpTrustTypes,
  TlpICertificateCompression,
  TlpHandshakeMessage,
  TlpNegotiationTypes,
  TlpNegotiationPolicy,
  TlpSignatureSchemeRegistry,
  TlpCertificateVerifier,
  TlpICertificateVerifierSource,
  TlpIssuerLookupVerifierSource,
  TlpServerName,
  TlpTrustPolicy,
  TlpTlsCredential,
  TlpTicketBinding,
  TlpSession,
  TlpISession,
  TlpCoreExtensions,
  TlpITlsExtension,
  TlpITlsHostExtension,
  TlpHostExtensions,
  TlpISessionApplicationData,
  TlpSessionApplicationData,
  TlpIHandshakeMachine,
  TlpTls13ClientStateMachine,
  TlpTls13ServerStateMachine,
  TlpTls12ClientStateMachine,
  TlpTls12ServerStateMachine,
  TlpVersionDispatchMachine,
  TlpITlsConfig,
  TlpITlsEngine,
  TlpITls13HandshakeEngine,
  TlpTlsEngine,
  TlpTls13HandshakeEngine;

type
  /// <summary>
  /// Assembles a wired <see cref="ITlsEngine" /> from a frozen config: it builds the
  /// role's state machine, its extension registry and (client) certificate verifier,
  /// generates the connection randoms, and hands the machine to a fresh engine. The
  /// config builder only accumulates and freezes settings; this factory owns the
  /// composition.
  /// </summary>
  TTlsEngineFactory = class sealed(TObject)
  strict private
    /// <summary>The cipher-suite codes a hello advertises: the registry's suites, in its order,
    /// for the protocol versions the config offers.</summary>
    class function SuiteCodes(const AConfig: ITlsClientConfig): TArray<UInt16>; static;
    class function PreferredGroup(const AConfig: ITlsCommonConfig;
      out ACode: UInt16): INamedGroup; static;
    /// <summary>The first preferred classical ECDHE group (TLS 1.2 excludes KEM/hybrid).</summary>
    class function PreferredEcdheGroup(const AConfig: ITlsCommonConfig): INamedGroup; static;
    /// <summary>The preferred groups the config's registry holds, as codes in order - the
    /// registry is the source of capability truth, so a preferred codepoint that was pruned (or
    /// never registered) is silently dropped rather than advertised and then failing to resolve
    /// when selected. AEcdheOnly keeps only classical ECDHE groups: TLS 1.2 key exchange is
    /// ECDHE-only, so a client that does not offer 1.3 must not advertise KEM/hybrid
    /// (post-quantum) groups in supported_groups.</summary>
    class function OfferedGroupCodes(const AConfig: ITlsCommonConfig;
      AEcdheOnly: Boolean): TArray<UInt16>; static;
    class function Offers(const AConfig: ITlsCommonConfig;
      AVersion: UInt16): Boolean; static;
    /// <summary>The host_name a client sends in server_name: the DNS host, else empty (an IP
    /// literal, RFC 6066 sec. 3, no host, or an Omit config).</summary>
    class function SniHostName(const AConfig: ITlsClientConfig;
      const AName: TServerName): string; static;
    /// <summary>The server-certificate verifier the source builds from ATrust, composed with SPKI
    /// pinning and then the augment-only verify callback, so the callback runs last and sees what
    /// pinning already accepted. The context handed to the source carries no callback (it is
    /// applied here, once).</summary>
    class function ComposeServerVerifier(const AConfig: ITlsClientConfig;
      const ATrust: TServerTrustContext): IServerCertificateVerifier; static;
    /// <summary>The client-certificate counterpart of ComposeServerVerifier.</summary>
    class function ComposeClientVerifier(const AConfig: ITlsServerConfig;
      const ATrust: TClientTrustContext): IClientCertificateVerifier; static;
    /// <summary>Builds the server-certificate verifier a client checks the server against, the
    /// resumption verifier (nil unless a resume can reverify) and the ECH reject verifier (nil
    /// unless an ECH reject must prove public_name); AOffersResumption tells whether the client
    /// resumes at all.</summary>
    class procedure BuildServerCertificateVerifiers(const AConfig: ITlsClientConfig;
      ADeferral: TVerdictDeferral; out AOffersResumption: Boolean;
      out AVerifier, AResumeVerifier, AEchRejectVerifier: IServerCertificateVerifier); static;
    /// <summary>The verifier a server checks client certificates with; nil unless the server
    /// requests client authentication.</summary>
    class function BuildClientCertificateVerifier(const AConfig: ITlsServerConfig;
      ADeferral: TVerdictDeferral): IClientCertificateVerifier; static;
    /// <summary>The Certificate-message cap a server's reassembler takes: the chain budget when it
    /// requests client authentication, else the default.</summary>
    class function ClientCertificateMessageCap(
      const AConfig: ITlsServerConfig): Int32; static;
    /// <summary>The server name a client connects to; fails closed when name checking is on and
    /// AHost holds no usable name.</summary>
    class function ParseServerName(const AConfig: ITlsClientConfig;
      const AHost: string): TServerName; static;
    /// <summary>Refuses a config that does not offer TLS 1.3 alone: a TLS 1.3
    /// handshake-only engine speaks no other version.</summary>
    class procedure RequireTls13Only(const AConfig: ITlsCommonConfig); static;
    /// <summary>The TLS 1.3 client machine's parameters.</summary>
    class function BuildClient13Params(const AConfig: ITlsClientConfig;
      const AServerName: TServerName; const AClientRandom, ASessionId: TBytes;
      const AVerifier, AResumeVerifier, AEchRejectVerifier: IServerCertificateVerifier;
      ADeferral: TVerdictDeferral; AOffers13, AOffersResumption: Boolean;
      const AHostAdapters: TArray<ITlsExtension>;
      const ASessionData: ISessionApplicationDataChannel): TClientHandshakeParams; static;
    /// <summary>The TLS 1.3 server machine's parameters.</summary>
    class function BuildServer13Params(const AConfig: ITlsServerConfig;
      const AServerRandom: TBytes; const AClientVerifier: IClientCertificateVerifier;
      ADeferral: TVerdictDeferral; AOffers13: Boolean;
      const AHostAdapters: TArray<ITlsExtension>): TServerHandshakeParams; static;
    /// <summary>The registry entries carrying AHostExtensions; they ride TLS 1.3 handshakes only,
    /// so a config that does not offer 1.3 cannot take them.</summary>
    class function HostAdapters(const AHostExtensions: TArray<ITlsHostExtension>;
      ARole: TTlsHostExtensionRole; AOffers13: Boolean;
      out AResults: ITlsHostExtensionResults): TArray<ITlsExtension>; static;
  public
    /// <summary>A client engine wired from the config, ready for StartHandshake.</summary>
    class function CreateClientEngine(const AConfig: ITlsClientConfig;
      const AHost: string): ITlsEngine; overload; static;
    /// <summary>As above, carrying AHostExtensions in its TLS 1.3 handshakes; read the peer's back
    /// with Supports(engine, ITlsHostExtensionResults). A TLS 1.2 handshake neither answers nor
    /// requires them, and a TLS 1.2 server that echoes one fails the handshake. Raises when the config offers no TLS 1.3, or a host extension is refused
    /// (see TTlsHostExtensions).</summary>
    class function CreateClientEngine(const AConfig: ITlsClientConfig; const AHost: string;
      const AHostExtensions: TArray<ITlsHostExtension>): ITlsEngine; overload; static;
    /// <summary>A server engine wired from the config; it starts on the first ClientHello.</summary>
    class function CreateServerEngine(const AConfig: ITlsServerConfig): ITlsEngine; overload; static;
    /// <summary>As above, carrying AHostExtensions as the client engine overload does.</summary>
    class function CreateServerEngine(const AConfig: ITlsServerConfig;
      const AHostExtensions: TArray<ITlsHostExtension>): ITlsEngine; overload; static;
    /// <summary>A TLS 1.3 handshake-only client engine for a host that owns record protection,
    /// ready for StartHandshake. The config must offer TLS 1.3 alone. AHostExtensions ride its
    /// handshake as for CreateClientEngine. ATicketEarlyDataLimit is the early-data budget every ticket it
    /// receives while it keeps a session cache must carry: any other value, an explicit 0
    /// included, fails the connection without an alert. A client with no session cache ignores
    /// tickets. 0 leaves the value unchecked; a host that offers 0-RTT passes the value its
    /// tickets must carry. Tickets it caches resume only on a TLS 1.3 handshake-only engine.</summary>
    class function CreateTls13HandshakeClientEngine(const AConfig: ITlsClientConfig;
      const AHost: string; const AHostExtensions: TArray<ITlsHostExtension>;
      ATicketEarlyDataLimit: UInt32): ITls13HandshakeEngine; static;
    /// <summary>A TLS 1.3 handshake-only server engine for a host that owns record protection; it
    /// starts on the first ClientHello. The config must offer TLS 1.3 alone. When the config
    /// enables early data, ATicketEarlyDataLimit is the budget its tickets advertise and accept
    /// (the config's own limit is not used), and 0 turns 0-RTT off. AEarlyDataContext is the only
    /// source of the early-data context its tickets carry and 0-RTT must match, sealed while 0-RTT
    /// is on; a config with its own early-data context (a record-engine setting) is refused.
    /// Tickets it mints resume only on a TLS 1.3 handshake-only engine.</summary>
    class function CreateTls13HandshakeServerEngine(const AConfig: ITlsServerConfig;
      const AHostExtensions: TArray<ITlsHostExtension>; ATicketEarlyDataLimit: UInt32;
      const AEarlyDataContext: TBytes): ITls13HandshakeEngine; static;
  end;

implementation

const
  AnyGroupKind = False;
  EcdheGroupsOnly = True;

resourcestring
  SNoPreferredGroup = 'the config lists no preferred key-exchange groups';
  SUnconfiguredGroup =
    'preferred group 0x%.4x is not present in the named-group registry';
  SNoEcdheGroup =
    'TLS 1.2 is offered but no preferred group is a classical ECDHE group';
  SNoServerNameForCheck =
    'server-name checking is on but no usable host was given to verify the certificate ' +
    'against; pass the connection host, or disable it with WithDangerousDisableServerNameCheck';
  SHostExtensionsNeedTls13 =
    'host extensions ride TLS 1.3 handshakes only, but the config does not offer TLS 1.3';
  SHandshakeEngineNeedsTls13Only =
    'a TLS 1.3 handshake-only engine needs a config that offers TLS 1.3 and no other version';
  SEarlyDataContextTooLongForTicket = 'the early-data context exceeds the ticket limit';
  SConfigEarlyDataContextOnHandshakeEngine =
    'a TLS 1.3 handshake-only engine takes its early-data context from the host, not the config';

{ TTlsEngineFactory }

class function TTlsEngineFactory.SniHostName(const AConfig: ITlsClientConfig;
  const AName: TServerName): string;
begin
  if AConfig.ServerNameIndication = TServerNameIndication.Omit then
    Result := ''
  else
    Result := AName.AsDns;
end;

class function TTlsEngineFactory.ComposeServerVerifier(const AConfig: ITlsClientConfig;
  const ATrust: TServerTrustContext): IServerCertificateVerifier;
var
  LSourceTrust: TServerTrustContext;
  LSource: IServerCertificateVerifierSource;
begin
  LSourceTrust := ATrust;
  LSourceTrust.Dangerous.VerifyCallback := nil;
  LSource := AConfig.ServerVerifierSource;
  // wrapped here and not in the config, whose source is classified by its type
  if AConfig.IssuerLookup <> nil then
    LSource := TIssuerLookupServerVerifierSource.Create(LSource, AConfig.IssuerLookup,
      AConfig.IssuerAnchorRule) as IServerCertificateVerifierSource;
  Result := LSource.CreateServerVerifier(LSourceTrust);
  // SPKI pinning composes over the source output, so it augments any source (built-in or OS delegate)
  if System.Length(AConfig.CertificatePins) > 0 then
    Result := TPinningVerifier.Create(Result, AConfig.CertificatePins, AConfig.Crypto,
      AConfig.Pkix) as IServerCertificateVerifier;
  if Assigned(ATrust.Dangerous.VerifyCallback) then
    Result := TVerifyCallbackVerifier.Create(Result, ATrust.Dangerous.VerifyCallback)
      as IServerCertificateVerifier;
end;

class function TTlsEngineFactory.ComposeClientVerifier(const AConfig: ITlsServerConfig;
  const ATrust: TClientTrustContext): IClientCertificateVerifier;
var
  LSourceTrust: TClientTrustContext;
  LSource: IClientCertificateVerifierSource;
begin
  LSourceTrust := ATrust;
  LSourceTrust.Dangerous.VerifyCallback := nil;
  LSource := AConfig.ClientVerifierSource;
  if AConfig.IssuerLookup <> nil then
    LSource := TIssuerLookupClientVerifierSource.Create(LSource, AConfig.IssuerLookup,
      AConfig.IssuerAnchorRule) as IClientCertificateVerifierSource;
  Result := LSource.CreateClientVerifier(LSourceTrust);
  // SPKI pinning composes over the source output, so it pins the presented client chain
  // uniformly over the built-in pipeline and an OS client delegate (RFC 7469)
  if System.Length(AConfig.CertificatePins) > 0 then
    Result := TClientPinningVerifier.Create(Result, AConfig.CertificatePins, AConfig.Crypto,
      AConfig.Pkix) as IClientCertificateVerifier;
  if Assigned(ATrust.Dangerous.VerifyCallback) then
    Result := TClientVerifyCallbackVerifier.Create(Result, ATrust.Dangerous.VerifyCallback)
      as IClientCertificateVerifier;
end;

class procedure TTlsEngineFactory.BuildServerCertificateVerifiers(
  const AConfig: ITlsClientConfig; ADeferral: TVerdictDeferral;
  out AOffersResumption: Boolean; out AVerifier, AResumeVerifier,
  AEchRejectVerifier: IServerCertificateVerifier);
var
  LTrustContext, LResumeContext, LRejectContext: TServerTrustContext;
begin
  // the source builds the verifier from this context, so the clock and posture reach the
  // built-in and an OS delegate the same way
  LTrustContext := Default(TServerTrustContext);
  LTrustContext.Pkix := AConfig.Pkix;
  LTrustContext.Clock := AConfig.Clock;
  LTrustContext.TrustStore := AConfig.TrustStore;
  LTrustContext.CheckHostName := AConfig.CheckServerName;
  LTrustContext.ChainLimits := AConfig.CertificateChainLimits;
  LTrustContext.RevocationPosture := AConfig.RevocationPosture;
  LTrustContext.Dangerous := AConfig.DangerousTrust;
  LTrustContext.Deferral := ADeferral;
  LTrustContext.Intermediates := AConfig.IntermediateCertificates;
  LTrustContext.StrengthPolicy := AConfig.CertificateStrengthPolicy;
  LTrustContext.AdvertisedSignatureSchemes := TSignatureSchemeCodes.FromRegistry(AConfig.SignatureSchemes);
  // the initial-handshake verifier: must-staple binds here only when the client offers status_request
  LTrustContext.StatusRequestOffered := AConfig.RequestOcspStapling;
  LTrustContext.Occasion := TVerificationOccasion.InitialHandshake;
  AVerifier := ComposeServerVerifier(AConfig, LTrustContext);
  // reverify-on-resume re-checks the stored chain, which carries no Certificate and no fresh
  // staple: a second verifier built for the Resumption occasion so must-staple never fires on a
  // resume. Built only when a resume can actually reverify (composed with the same pins).
  AOffersResumption := AConfig.Resumption and (AConfig.SessionCache <> nil);
  AResumeVerifier := nil;
  if AOffersResumption and
    (AConfig.ResumeVerification = TResumeVerification.Reverify) then
  begin
    LResumeContext := LTrustContext;
    LResumeContext.Occasion := TVerificationOccasion.Resumption;
    AResumeVerifier := ComposeServerVerifier(AConfig, LResumeContext);
  end;
  // an ECH reject proves public_name even with the origin check off, at one more source build
  AEchRejectVerifier := nil;
  if (AConfig.EncryptedClientHello <> nil) and AConfig.EncryptedClientHello.Usable and
    not AConfig.CheckServerName then
  begin
    LRejectContext := LTrustContext;
    LRejectContext.CheckHostName := True;
    AEchRejectVerifier := ComposeServerVerifier(AConfig, LRejectContext);
  end;
end;

class function TTlsEngineFactory.BuildClientCertificateVerifier(
  const AConfig: ITlsServerConfig; ADeferral: TVerdictDeferral): IClientCertificateVerifier;
var
  LClientContext: TClientTrustContext;
begin
  // one client-certificate verifier from the source (built-in, injected, or the OS client
  // delegate over the client-CA anchors), shared by the version machines; built only for mTLS
  Result := nil;
  if AConfig.ClientAuth = TClientAuthMode.None then
    Exit;
  LClientContext := Default(TClientTrustContext);
  LClientContext.Pkix := AConfig.Pkix;
  LClientContext.Clock := AConfig.Clock;
  LClientContext.TrustStore := AConfig.TrustStore;
  LClientContext.ChainLimits := AConfig.CertificateChainLimits;
  LClientContext.RevocationPosture := AConfig.RevocationPosture;
  LClientContext.Dangerous := AConfig.DangerousTrust;
  LClientContext.Deferral := ADeferral;
  LClientContext.Intermediates := AConfig.IntermediateCertificates;
  LClientContext.StrengthPolicy := AConfig.CertificateStrengthPolicy;
  LClientContext.AdvertisedSignatureSchemes := TSignatureSchemeCodes.FromRegistry(AConfig.SignatureSchemes);
  Result := ComposeClientVerifier(AConfig, LClientContext);
end;

class function TTlsEngineFactory.BuildClient13Params(const AConfig: ITlsClientConfig;
  const AServerName: TServerName; const AClientRandom, ASessionId: TBytes;
  const AVerifier, AResumeVerifier, AEchRejectVerifier: IServerCertificateVerifier;
  ADeferral: TVerdictDeferral; AOffers13, AOffersResumption: Boolean;
  const AHostAdapters: TArray<ITlsExtension>;
  const ASessionData: ISessionApplicationDataChannel): TClientHandshakeParams;
begin
  Result := Default(TClientHandshakeParams);
  Result.Crypto := AConfig.Crypto;
  Result.Inspector := AConfig.Pkix.Certificates;
  Result.Group := PreferredGroup(AConfig, Result.GroupCode);
  // advertise every preferred group the registry holds (a pruned/absent group is dropped, not
  // advertised-then-unresolvable) and carry the registry, so the server may retry the client
  // onto any offered group it prefers (HelloRetryRequest)
  Result.OfferedGroups := OfferedGroupCodes(AConfig, AnyGroupKind);
  Result.GroupRegistry := AConfig.NamedGroups;
  Result.CipherSuites := AConfig.CipherSuites;
  // the extension registry is built only for a version whose machine is created
  if AOffers13 then
    Result.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry(AHostAdapters);
  Result.TicketBinding := TTicketBinding.RecordEngine;
  Result.SessionApplicationData := ASessionData;
  Result.OfferedSuites := SuiteCodes(AConfig);
  Result.OfferedSchemes := TSignatureSchemeCodes.FromRegistry(AConfig.SignatureSchemes);
  Result.AlpnProtocols := AConfig.AlpnProtocols;
  Result.RecordSizeLimit := AConfig.RecordSizeLimit;
  // the client advertises what it can decompress, and compresses its own Certificate with what it
  // holds when the server asks for one and advertises a match (RFC 8879)
  Result.CertificateDecompressors := AConfig.CertificateDecompressors;
  Result.CertificateCompressors := AConfig.CertificateCompressors;
  Result.CertificateCompressionCache := AConfig.CertificateCompressionCache;
  // GREASE is on by default for a client (RFC 8701 keeps peers tolerant); optional per the RFC
  Result.Grease := AConfig.Grease;
  Result.RequestOcspStapling := AConfig.RequestOcspStapling;
  // the config guarantees a non-nil clock (system clock by default); it backs a resumption
  // PSK's obfuscated_ticket_age and ticket-lifetime expiry
  Result.Clock := AConfig.Clock;
  Result.KeyLog := AConfig.KeyLog;
  Result.ClientRandom := AClientRandom;
  Result.LegacySessionId := ASessionId;
  // SNI carries the DNS name only (none for an IP literal, RFC 6066 sec. 3, no host, or Omit);
  // the name check still uses the host
  Result.ServerName := SniHostName(AConfig, AServerName);
  // the session-cache identity is the full host (IP literals included), keeping each
  // destination on its own cache key even when no SNI is sent
  Result.ServerIdentity := AServerName.ToString;
  Result.CertificateVerifier := AVerifier;
  Result.CertificateChainLimits := AConfig.CertificateChainLimits;
  Result.ResumeCertificateVerifier := AResumeVerifier;
  Result.EchRejectCertificateVerifier := AEchRejectVerifier;
  Result.Deferral := ADeferral;
  Result.RevocationPosture := AConfig.RevocationPosture;
  // Encrypted Client Hello policy (RFC 9849), nil when not offered
  Result.EchPolicy := AConfig.EncryptedClientHello;
  Result.ExpectedServerName := AServerName;
  // a mutual-TLS client presents this credential when the server requests one; empty
  // sends an empty client Certificate
  Result.ClientCredential := AConfig.Credential;
  if AOffersResumption and AOffers13 then
  begin
    Result.SessionCache := AConfig.SessionCache;
    Result.SessionScope := AConfig.SessionScope;
    Result.EarlyDataEnabled := AConfig.EarlyData;
    Result.ResumeVerification := AConfig.ResumeVerification;
  end;
  // out-of-band external PSKs (RFC 9258) are a TLS 1.3-only offer. A PSK-only client (external
  // PSKs configured with no certificate trust to fall back on) requires the server to select a
  // PSK - a non-PSK ServerHello is then fatal.
  if AOffers13 then
  begin
    Result.ExternalPsks := AConfig.ExternalPsks;
    Result.RequirePsk := TClientPskPath.RequiresPsk(System.Length(AConfig.ExternalPsks),
      AConfig.ExternalPskRequired);
  end;
end;

class function TTlsEngineFactory.BuildServer13Params(const AConfig: ITlsServerConfig;
  const AServerRandom: TBytes; const AClientVerifier: IClientCertificateVerifier;
  ADeferral: TVerdictDeferral; AOffers13: Boolean;
  const AHostAdapters: TArray<ITlsExtension>): TServerHandshakeParams;
var
  LGroupCode: UInt16;
begin
  Result := Default(TServerHandshakeParams);
  Result.Crypto := AConfig.Crypto;
  Result.Inspector := AConfig.Pkix.Certificates;
  Result.Clock := AConfig.Clock;
  Result.KeyLog := AConfig.KeyLog;
  Result.Policy := TNegotiationPolicy.Create(AConfig.CipherSuites,
    AConfig.NamedGroups, AConfig.PreferredGroups, AConfig.SupportedVersions,
    AConfig.CipherSuitePreference);
  Result.CipherSuites := AConfig.CipherSuites;
  // build the extension registry only for a version whose machine is created
  if AOffers13 then
    Result.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry(AHostAdapters);
  Result.TicketBinding := TTicketBinding.RecordEngine;
  // the negotiation policy (built above from the same PreferredGroups/NamedGroups) selects the
  // group by server preference among the client's supported_groups (RFC 9846 4.3.7); the state
  // machine resolves the selected code via GroupRegistry
  Result.GroupRegistry := AConfig.NamedGroups;
  // validate at creation that at least one preferred group is registered when 1.3 is offered (an
  // empty registry-vs-preference intersection would leave the policy unable to select any group);
  // the result is discarded - this is a creation-time guard, not a stored fallback
  if AOffers13 then
    PreferredGroup(AConfig, LGroupCode);
  Result.ServerRandom := AServerRandom;
  Result.AlpnProtocols := AConfig.AlpnProtocols;
  Result.RecordSizeLimit := AConfig.RecordSizeLimit;
  // the server compresses its Certificate with what it holds and the client advertised, and
  // advertises what it can decompress when it asks for a client certificate (RFC 8879)
  Result.CertificateCompressors := AConfig.CertificateCompressors;
  Result.CertificateDecompressors := AConfig.CertificateDecompressors;
  Result.CertificateChainLimits := AConfig.CertificateChainLimits;
  // memoize that compression across connections (a stable certificate deflates once)
  Result.CertificateCompressionCache := AConfig.CertificateCompressionCache;
  // a per-server-instance secret so the server can answer with a stateless HelloRetryRequest
  Result.CookieSecret := TSecretBuffer.From(AConfig.Crypto.Primitives.GetRandom.GenerateBytes(32));
  // the resolver selects the credential per handshake from the client's SNI (virtual hosting);
  // each credential carries the chain, key, and (when set) the OCSP staple the server sends for
  // its leaf once the client offers status_request
  Result.CredentialResolver := AConfig.CredentialResolver;
  Result.ServerNameAck := AConfig.ServerNameAcknowledgement;
  Result.AlpnRejectAll := AConfig.AlpnRejectAll;
  // mutual TLS: request a client certificate and verify it against the trust store
  Result.ClientAuth := AConfig.ClientAuth;
  Result.ClientAuthSignatureSchemes := TSignatureSchemeCodes.FromRegistry(AConfig.SignatureSchemes);
  Result.ClientCertificateAuthorities := AConfig.ClientCertificateAuthorities;
  Result.ClientCertificateVerifier := AClientVerifier;
  Result.Deferral := ADeferral;
  Result.RevocationPosture := AConfig.RevocationPosture;
  // resumption (RFC 9846 4.7.1): the session store/STEK are shared with the 1.2 machine; 0-RTT is
  // 1.3-only, so the early-data budget and anti-replay reach only this machine
  if AConfig.Resumption then
  begin
    Result.SessionStore := AConfig.SessionStore;
    Result.SessionTicketKeys := AConfig.SessionTicketKeys;
    Result.ResumptionScope := AConfig.ResumptionScope;
    Result.IssueTicketCount := AConfig.TicketCount;
    Result.TicketLifetimeSeconds := AConfig.TicketLifetimeSeconds;
    Result.MaxEarlyData := AConfig.MaxEarlyData;
    Result.EarlyDataContext := AConfig.EarlyDataContext;
    Result.AntiReplay := AConfig.AntiReplay;
  end;
  // out-of-band external PSKs (RFC 9258) and Encrypted Client Hello are matched only on the TLS
  // 1.3 path; a keyed server decrypts ECH offers with its store and advertises its is_retry
  // configs as retry_configs on reject (RFC 9849)
  if AOffers13 then
  begin
    Result.ExternalPsks := AConfig.ExternalPsks;
    Result.EchPolicy := AConfig.EncryptedClientHello;
  end;
end;

class function TTlsEngineFactory.SuiteCodes(
  const AConfig: ITlsClientConfig): TArray<UInt16>;
var
  LSuite: TTlsCipherSuite;
  LOffers13, LOffers12, LHasPsk, LPskOnly12, LOffered: Boolean;
begin
  Result := nil;
  LOffers13 := Offers(AConfig, TlsWireVersionTls13);
  LOffers12 := Offers(AConfig, TlsWireVersionTls12);
  LHasPsk := System.Length(AConfig.Tls12Psks) > 0;
  LPskOnly12 := TClientPskPath.RequiresPsk(System.Length(AConfig.Tls12Psks),
    AConfig.Tls12PreSharedKeyRequired);
  // registry order is kept; a suite of a version the config does not offer is not advertised, so a
  // single-version hello carries no suite it could never complete. The PSK suites are offered only
  // with a PSK to present, and a client that requires its PSK offers no certificate suite for 1.2
  for LSuite in AConfig.CipherSuites.Items do
    if (LSuite.Protocol = TSuiteProtocol.Tls13) and LOffers13 then
      TArrayUtilities.Append<UInt16>(Result, LSuite.Common.Code)
    else if (LSuite.Protocol = TSuiteProtocol.Tls12) and LOffers12 then
    begin
      if LSuite.Auth = TAuthMethod.Psk then
        LOffered := LHasPsk
      else
        LOffered := not LPskOnly12;
      if LOffered then
        TArrayUtilities.Append<UInt16>(Result, LSuite.Common.Code);
    end;
end;

class function TTlsEngineFactory.PreferredGroup(const AConfig: ITlsCommonConfig;
  out ACode: UInt16): INamedGroup;
var
  LGroups: TArray<INamedGroup>;
begin
  if System.Length(AConfig.PreferredGroups) = 0 then
    raise EArgumentTlsLibException.CreateRes(@SNoPreferredGroup);
  // the registry is authoritative: pick the first preferred group it actually holds, so a
  // preferred order that still names a pruned group (a preset lists the hybrid first) resolves
  // to the top registered group instead of failing
  LGroups := TNamedGroups.ResolvedGroups(AConfig.NamedGroups, AConfig.PreferredGroups);
  if System.Length(LGroups) = 0 then
    raise EArgumentTlsLibException.CreateResFmt(@SUnconfiguredGroup,
      [AConfig.PreferredGroups[0]]);
  Result := LGroups[0];
  ACode := Result.Code;
end;

class function TTlsEngineFactory.PreferredEcdheGroup(
  const AConfig: ITlsCommonConfig): INamedGroup;
var
  LGroup: INamedGroup;
begin
  for LGroup in TNamedGroups.ResolvedGroups(AConfig.NamedGroups, AConfig.PreferredGroups) do
    if LGroup.Kind = TNamedGroupKind.Ecdhe then
      Exit(LGroup);
  raise EArgumentTlsLibException.CreateRes(@SNoEcdheGroup);
end;

class function TTlsEngineFactory.OfferedGroupCodes(const AConfig: ITlsCommonConfig;
  AEcdheOnly: Boolean): TArray<UInt16>;
var
  LGroup: INamedGroup;
begin
  Result := nil;
  for LGroup in TNamedGroups.ResolvedGroups(AConfig.NamedGroups, AConfig.PreferredGroups) do
    if (not AEcdheOnly) or (LGroup.Kind = TNamedGroupKind.Ecdhe) then
      TArrayUtilities.Append<UInt16>(Result, LGroup.Code);
end;

class function TTlsEngineFactory.Offers(const AConfig: ITlsCommonConfig;
  AVersion: UInt16): Boolean;
begin
  Result := TArrayUtilities.Contains<UInt16>(AConfig.SupportedVersions, AVersion);
end;

class function TTlsEngineFactory.HostAdapters(
  const AHostExtensions: TArray<ITlsHostExtension>; ARole: TTlsHostExtensionRole;
  AOffers13: Boolean; out AResults: ITlsHostExtensionResults): TArray<ITlsExtension>;
begin
  Result := TTlsHostExtensions.Adapt(AHostExtensions, ARole, AResults);
  if (System.Length(Result) > 0) and not AOffers13 then
    raise EArgumentTlsLibException.CreateRes(@SHostExtensionsNeedTls13);
end;

class function TTlsEngineFactory.CreateClientEngine(
  const AConfig: ITlsClientConfig; const AHost: string): ITlsEngine;
begin
  Result := CreateClientEngine(AConfig, AHost, nil);
end;

class function TTlsEngineFactory.CreateClientEngine(
  const AConfig: ITlsClientConfig; const AHost: string;
  const AHostExtensions: TArray<ITlsHostExtension>): ITlsEngine;
var
  L13: TClientHandshakeParams;
  L12: TClient12HandshakeParams;
  LClientRandom, LSessionId: TBytes;
  LVerifier, LResumeVerifier, LEchRejectVerifier: IServerCertificateVerifier;
  LServerName: TServerName;
  LDeferral: TVerdictDeferral;
  LOffers13, LOffers12, LOffersResumption: Boolean;
  LMachine: IHandshakeMachine;
  LHostResults: ITlsHostExtensionResults;
  LSessionData: ITlsSessionApplicationData;
  LAdapters: TArray<ITlsExtension>;
begin
  LOffers13 := Offers(AConfig, TlsWireVersionTls13);
  LOffers12 := Offers(AConfig, TlsWireVersionTls12);
  LAdapters := HostAdapters(AHostExtensions, TTlsHostExtensionRole.Client, LOffers13, LHostResults);
  LSessionData := TSessionApplicationData.Create as ITlsSessionApplicationData;
  // a verdict-deferral mode parks the handshake after the pipeline accepts the server chain; any
  // time budget belongs to the resolver built from the config, not the engine
  LDeferral := AConfig.AsyncCertificateVerdict.Deferral;
  // the two client machines must share one client random and session id so a 1.2
  // hand-off keeps the ServerKeyExchange/master-secret binding of the sent ClientHello
  LClientRandom := AConfig.Crypto.Primitives.GetRandom.GenerateBytes(32);
  LSessionId := AConfig.Crypto.Primitives.GetRandom.GenerateBytes(32);
  LServerName := ParseServerName(AConfig, AHost);
  BuildServerCertificateVerifiers(AConfig, LDeferral, LOffersResumption, LVerifier,
    LResumeVerifier, LEchRejectVerifier);

  L13 := BuildClient13Params(AConfig, LServerName, LClientRandom, LSessionId, LVerifier,
    LResumeVerifier, LEchRejectVerifier, LDeferral, LOffers13, LOffersResumption, LAdapters,
    LSessionData as ISessionApplicationDataChannel);

  L12 := Default(TClient12HandshakeParams);
  L12.Crypto := AConfig.Crypto;
  L12.Inspector := AConfig.Pkix.Certificates;
  L12.GroupRegistry := AConfig.NamedGroups;
  L12.CipherSuites := AConfig.CipherSuites;
  if LOffers12 then
    L12.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  L12.Clock := AConfig.Clock;
  L12.KeyLog := AConfig.KeyLog;
  L12.OfferedSuites := SuiteCodes(AConfig);
  if System.Length(AConfig.Tls12Psks) > 0 then
    L12.ClientPsk := AConfig.Tls12Psks[0];
  // TLS 1.2 key exchange is ECDHE-only: a 1.2 supported_groups carries no KEM/hybrid group,
  // so a client that reaches the 1.2 path (never offering 1.3) does not advertise one
  L12.OfferedGroups := OfferedGroupCodes(AConfig, EcdheGroupsOnly);
  L12.OfferedSchemes := TSignatureSchemeCodes.FromRegistry(AConfig.SignatureSchemes);
  L12.AlpnProtocols := AConfig.AlpnProtocols;
  L12.RecordSizeLimit := AConfig.RecordSizeLimit;
  L12.Grease := AConfig.Grease;
  L12.OfferedVersions := AConfig.SupportedVersions;
  L12.ClientRandom := LClientRandom;
  // the non-empty legacy_session_id is the TLS 1.3 middlebox-compatibility session id
  // (RFC 9846 E.4); a client that does not offer 1.3 sends an empty session id
  if LOffers13 then
    L12.LegacySessionId := LSessionId
  else
    L12.LegacySessionId := nil;
  L12.ServerName := SniHostName(AConfig, LServerName);
  L12.ServerIdentity := LServerName.ToString;
  L12.OfferExtendedMasterSecret := True;
  L12.RequireExtendedMasterSecret := AConfig.RequireExtendedMasterSecret;
  L12.RequestOcspStapling := AConfig.RequestOcspStapling;
  L12.CertificateVerifier := LVerifier;
  L12.ResumeCertificateVerifier := LResumeVerifier;
  L12.Deferral := LDeferral;
  L12.RevocationPosture := AConfig.RevocationPosture;
  L12.ExpectedServerName := LServerName;
  L12.ClientCredential := AConfig.Credential;

  // resumption (RFC 9846 4.7.1 / RFC 5077): the version-appropriate client machine draws a
  // cached session and offers it. In a dual-version client the 1.3 machine draws (preferring
  // a 1.3 ticket, else offering a cached 1.2 session it hands to the 1.2 machine); either
  // way the 1.2 machine still needs the cache to store completed 1.2 sessions, so wire both
  // (the 1.3 side is wired with its params above).
  if LOffersResumption and LOffers12 then
  begin
    L12.SessionCache := AConfig.SessionCache;
    L12.SessionScope := AConfig.SessionScope;
    L12.ResumeVerification := AConfig.ResumeVerification;
  end;

  // the inner hello never offers TLS 1.2 (RFC 9849 sec. 6.1), and this client also offers only
  // TLS 1.3 in the outer, so a server selecting 1.2 is refused - a legacy or downgrading peer
  // is not silently completed to the public_name. A usable config
  // forces the 1.3-only machine; GREASE alone (no usable config) is decorative and does not
  // constrain the version.
  if (AConfig.EncryptedClientHello <> nil) and
    AConfig.EncryptedClientHello.Usable then
    LMachine := TTls13ClientStateMachine.Create(L13)
  else if LOffers13 and LOffers12 then
    LMachine := TClientVersionDispatchMachine.Create(L13, L12)
  else if LOffers13 then
    LMachine := TTls13ClientStateMachine.Create(L13)
  else
    LMachine := TTls12ClientStateMachine.Create(L12);

  // a client always receives the server's Certificate, so bound its reassembler by the chain budget
  Result := TTlsEngine.Create(LMachine, AConfig.Crypto,
    AConfig.CertificateChainLimits.MaxTotalChainLength, LHostResults, LSessionData) as ITlsEngine;
end;

class function TTlsEngineFactory.CreateServerEngine(
  const AConfig: ITlsServerConfig): ITlsEngine;
begin
  Result := CreateServerEngine(AConfig, nil);
end;

class function TTlsEngineFactory.CreateServerEngine(const AConfig: ITlsServerConfig;
  const AHostExtensions: TArray<ITlsHostExtension>): ITlsEngine;
var
  L13: TServerHandshakeParams;
  L12: TServer12HandshakeParams;
  LServerRandom: TBytes;
  LClientVerifier: IClientCertificateVerifier;
  LDeferral: TVerdictDeferral;
  LOffers13, LOffers12: Boolean;
  LMachine: IHandshakeMachine;
  LHostResults: ITlsHostExtensionResults;
  LAdapters: TArray<ITlsExtension>;
begin
  LOffers13 := Offers(AConfig, TlsWireVersionTls13);
  LOffers12 := Offers(AConfig, TlsWireVersionTls12);
  LAdapters := HostAdapters(AHostExtensions, TTlsHostExtensionRole.Server, LOffers13, LHostResults);
  LServerRandom := AConfig.Crypto.Primitives.GetRandom.GenerateBytes(32);
  // a verdict-deferral mode parks the handshake after the pipeline accepts the client chain
  // (only meaningful when the server requests client authentication)
  LDeferral := AConfig.AsyncCertificateVerdict.Deferral;
  if AConfig.ClientAuth = TClientAuthMode.None then
    LDeferral := TVerdictDeferral.None;

  LClientVerifier := BuildClientCertificateVerifier(AConfig, LDeferral);

  L13 := BuildServer13Params(AConfig, LServerRandom, LClientVerifier, LDeferral,
    LOffers13, LAdapters);

  L12 := Default(TServer12HandshakeParams);
  L12.Crypto := AConfig.Crypto;
  L12.Inspector := AConfig.Pkix.Certificates;
  L12.Clock := AConfig.Clock;
  L12.KeyLog := AConfig.KeyLog;
  L12.CipherSuites := AConfig.CipherSuites;
  // the same negotiation policy as the 1.3 server, so WithCipherSuitePreference applies to a
  // 1.2 handshake identically (version-agnostic server/client order)
  L12.Policy := L13.Policy;
  if LOffers12 then
    L12.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  // TLS 1.2 needs a classical ECDHE group (KEM/hybrid are 1.3-only); the same policy selects it by
  // server preference among the client's supported_groups, resolved via GroupRegistry
  L12.GroupRegistry := AConfig.NamedGroups;
  // validate at creation that at least one preferred group is a registered classical ECDHE group
  // when 1.2 is offered; the result is discarded (creation-time guard, not a stored fallback)
  if LOffers12 then
    PreferredEcdheGroup(AConfig);
  L12.ServerRandom := LServerRandom;
  L12.CredentialResolver := AConfig.CredentialResolver;
  L12.RequireExtendedMasterSecret := AConfig.RequireExtendedMasterSecret;
  L12.NonEmsResumption := AConfig.NonEmsResumption;
  L12.ServerNameAck := AConfig.ServerNameAcknowledgement;
  L12.AlpnRejectAll := AConfig.AlpnRejectAll;
  L12.ClientCertificateAuthorities := AConfig.ClientCertificateAuthorities;
  L12.AlpnProtocols := AConfig.AlpnProtocols;
  L12.RecordSizeLimit := AConfig.RecordSizeLimit;
  L12.ClientAuth := AConfig.ClientAuth;
  L12.ClientAuthSignatureSchemes := TSignatureSchemeCodes.FromRegistry(AConfig.SignatureSchemes);
  L12.ClientCertificateVerifier := LClientVerifier;
  L12.Deferral := LDeferral;
  L12.RevocationPosture := AConfig.RevocationPosture;

  // resumption (RFC 9846 4.7.1 / RFC 5077): both version machines share the session
  // store/STEK; each stores and accepts only its own version's sessions (the 1.3 side is wired
  // with its params above)
  if AConfig.Resumption then
  begin
    L12.SessionStore := AConfig.SessionStore;
    L12.SessionTicketKeys := AConfig.SessionTicketKeys;
    L12.ResumptionScope := AConfig.ResumptionScope;
    L12.TicketLifetimeSeconds := AConfig.TicketLifetimeSeconds;
  end;

  // TLS 1.2 PSKs (RFC 4279 / RFC 5489) are matched only on the TLS 1.2 path; an unknown identity
  // proceeds on a stand-in derived from a key minted per engine
  if LOffers12 and (System.Length(AConfig.Tls12Psks) > 0) then
  begin
    L12.Psks := AConfig.Tls12Psks;
    L12.PskIdentityHint := AConfig.Tls12PskIdentityHint;
    L12.PskDummyKey := TSecretBuffer.From(
      AConfig.Crypto.Primitives.GetRandom.GenerateBytes(32));
  end;

  if LOffers13 and LOffers12 then
    LMachine := TServerVersionDispatchMachine.Create(L13, L12,
      AConfig.SupportedVersions)
  else if LOffers13 then
    LMachine := TTls13ServerStateMachine.Create(L13)
  else
    LMachine := TTls12ServerStateMachine.Create(L12);

  // a server has no ticket to attach session application data to
  Result := TTlsEngine.Create(LMachine, AConfig.Crypto, ClientCertificateMessageCap(AConfig),
    LHostResults, nil) as ITlsEngine;
end;

class function TTlsEngineFactory.ClientCertificateMessageCap(
  const AConfig: ITlsServerConfig): Int32;
begin
  // a server receives a peer Certificate only when it requests client authentication; otherwise it
  // never reassembles one, so the reassembler keeps the tighter default cap
  Result := DefaultMaxHandshakeMessageLength;
  if AConfig.ClientAuth <> TClientAuthMode.None then
    Result := AConfig.CertificateChainLimits.MaxTotalChainLength;
end;

class function TTlsEngineFactory.ParseServerName(const AConfig: ITlsClientConfig;
  const AHost: string): TServerName;
begin
  // fail closed: when name checking is on, a client must have a usable server name to verify
  // the leaf against. A missing/unparsable host here would otherwise silently skip RFC 9525.
  if not TServerName.TryParse(AHost, Result) then
    if AConfig.CheckServerName then
      raise EArgumentTlsLibException.CreateRes(@SNoServerNameForCheck);
end;

class procedure TTlsEngineFactory.RequireTls13Only(const AConfig: ITlsCommonConfig);
begin
  if (not Offers(AConfig, TlsWireVersionTls13)) or Offers(AConfig, TlsWireVersionTls12) then
    raise EArgumentTlsLibException.CreateRes(@SHandshakeEngineNeedsTls13Only);
end;

class function TTlsEngineFactory.CreateTls13HandshakeClientEngine(
  const AConfig: ITlsClientConfig; const AHost: string;
  const AHostExtensions: TArray<ITlsHostExtension>;
  ATicketEarlyDataLimit: UInt32): ITls13HandshakeEngine;
var
  L13: TClientHandshakeParams;
  LVerifier, LResumeVerifier, LEchRejectVerifier: IServerCertificateVerifier;
  LServerName: TServerName;
  LDeferral: TVerdictDeferral;
  LOffersResumption: Boolean;
  LMachine: IHandshakeMachine;
  LHostResults: ITlsHostExtensionResults;
  LSessionData: ITlsSessionApplicationData;
  LAdapters: TArray<ITlsExtension>;
begin
  RequireTls13Only(AConfig);
  LAdapters := HostAdapters(AHostExtensions, TTlsHostExtensionRole.Client, True, LHostResults);
  LSessionData := TSessionApplicationData.Create as ITlsSessionApplicationData;
  LDeferral := AConfig.AsyncCertificateVerdict.Deferral;
  LServerName := ParseServerName(AConfig, AHost);
  BuildServerCertificateVerifiers(AConfig, LDeferral, LOffersResumption, LVerifier,
    LResumeVerifier, LEchRejectVerifier);
  // no compatibility session id: there are no records for it to disguise
  L13 := BuildClient13Params(AConfig, LServerName,
    AConfig.Crypto.Primitives.GetRandom.GenerateBytes(32), nil, LVerifier, LResumeVerifier,
    LEchRejectVerifier, LDeferral, True, LOffersResumption, LAdapters,
    LSessionData as ISessionApplicationDataChannel);
  L13.HostOwnsRecordProtection := True;
  L13.TicketBinding := TTicketBinding.HandshakeEngine;
  L13.TicketEarlyDataLimit := ATicketEarlyDataLimit;
  // record sizing is the host's
  L13.RecordSizeLimit := 0;
  LMachine := TTls13ClientStateMachine.Create(L13);
  Result := TTls13HandshakeEngine.Create(LMachine,
    AConfig.CertificateChainLimits.MaxTotalChainLength, LHostResults, LSessionData)
    as ITls13HandshakeEngine;
end;

class function TTlsEngineFactory.CreateTls13HandshakeServerEngine(
  const AConfig: ITlsServerConfig; const AHostExtensions: TArray<ITlsHostExtension>;
  ATicketEarlyDataLimit: UInt32; const AEarlyDataContext: TBytes): ITls13HandshakeEngine;
var
  L13: TServerHandshakeParams;
  LHostResults: ITlsHostExtensionResults;
  LAdapters: TArray<ITlsExtension>;
  LDeferral: TVerdictDeferral;
  LMachine: IHandshakeMachine;
begin
  RequireTls13Only(AConfig);
  if System.Length(AEarlyDataContext) > TSessionTicketLimits.MaxEarlyDataContextLength then
    raise EArgumentTlsLibException.CreateRes(@SEarlyDataContextTooLongForTicket);
  if System.Length(AConfig.EarlyDataContext) > 0 then
    raise EArgumentTlsLibException.CreateRes(@SConfigEarlyDataContextOnHandshakeEngine);
  LAdapters := HostAdapters(AHostExtensions, TTlsHostExtensionRole.Server, True, LHostResults);
  LDeferral := AConfig.AsyncCertificateVerdict.Deferral;
  if AConfig.ClientAuth = TClientAuthMode.None then
    LDeferral := TVerdictDeferral.None;
  L13 := BuildServer13Params(AConfig, AConfig.Crypto.Primitives.GetRandom.GenerateBytes(32),
    BuildClientCertificateVerifier(AConfig, LDeferral), LDeferral, True, LAdapters);
  L13.HostOwnsRecordProtection := True;
  L13.TicketBinding := TTicketBinding.HandshakeEngine;
  // record sizing is the host's
  L13.RecordSizeLimit := 0;
  // the host fixes the early-data budget its tickets carry; the config only says whether 0-RTT is on
  if L13.MaxEarlyData > 0 then
    L13.MaxEarlyData := ATicketEarlyDataLimit;
  // the context binds 0-RTT, so it is sealed only while 0-RTT is on
  if L13.MaxEarlyData > 0 then
    L13.EarlyDataContext := System.Copy(AEarlyDataContext);
  LMachine := TTls13ServerStateMachine.Create(L13);
  Result := TTls13HandshakeEngine.Create(LMachine, ClientCertificateMessageCap(AConfig),
    LHostResults, nil) as ITls13HandshakeEngine;
end;

end.
