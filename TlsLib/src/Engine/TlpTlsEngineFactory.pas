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
  TlpCryptoAlgorithms,
  TlpISecretBuffer,
  TlpSecretBuffer,
  TlpINamedGroup,
  TlpINegotiation,
  TlpICertificateTrust,
  TlpICertificateCompression,
  TlpNegotiationTypes,
  TlpNegotiationPolicy,
  TlpCertificateVerifier,
  TlpTrustPolicy,
  TlpTlsCredential,
  TlpITlsCredentialResolver,
  TlpISession,
  TlpAntiReplay,
  TlpCoreExtensions,
  TlpIHandshakeMachine,
  TlpTls13ClientStateMachine,
  TlpTls13ServerStateMachine,
  TlpTls12ClientStateMachine,
  TlpTls12ServerStateMachine,
  TlpVersionDispatchMachine,
  TlpITlsConfig,
  TlpITlsEngine,
  TlpTlsEngine;

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
    class function SuiteCodes(const ARegistry: ICipherSuiteRegistry): TArray<UInt16>; static;
    class function SchemeCodes(const ARegistry: ISignatureSchemeRegistry): TArray<UInt16>; static;
    class function PreferredGroup(const AConfig: ITlsCommonConfig;
      out ACode: UInt16): INamedGroup; static;
    /// <summary>The first preferred classical ECDHE group (TLS 1.2 excludes KEM/hybrid).</summary>
    class function PreferredEcdheGroup(const AConfig: ITlsCommonConfig): INamedGroup; static;
    /// <summary>The subset of ACodes that name classical ECDHE groups, in order. TLS 1.2
    /// key exchange is ECDHE-only, so a client that does not offer 1.3 must not advertise
    /// KEM/hybrid (post-quantum) groups in supported_groups.</summary>
    class function EcdheGroupCodes(const AConfig: ITlsCommonConfig;
      const ACodes: TArray<UInt16>): TArray<UInt16>; static;
    class function Offers(const AConfig: ITlsCommonConfig;
      AVersion: UInt16): Boolean; static;
  public
    /// <summary>A client engine wired from the config, ready for StartHandshake.</summary>
    class function CreateClientEngine(const AConfig: ITlsClientConfig;
      const AHost: string): ITlsEngine; static;
    /// <summary>A server engine wired from the config; it starts on the first ClientHello.</summary>
    class function CreateServerEngine(const AConfig: ITlsServerConfig): ITlsEngine; static;
  end;

implementation

resourcestring
  SNoPreferredGroup = 'the config lists no preferred key-exchange groups';
  SUnconfiguredGroup =
    'preferred group 0x%.4x is not present in the named-group registry';
  SNoEcdheGroup =
    'TLS 1.2 is offered but no preferred group is a classical ECDHE group';

{ TTlsEngineFactory }

class function TTlsEngineFactory.SuiteCodes(
  const ARegistry: ICipherSuiteRegistry): TArray<UInt16>;
var
  LSuites: TArray<TTlsCipherSuite>;
  LI: Int32;
begin
  Result := nil;
  LSuites := ARegistry.Items;
  SetLength(Result, System.Length(LSuites));
  for LI := 0 to System.High(LSuites) do
    Result[LI] := LSuites[LI].Common.Code;
end;

class function TTlsEngineFactory.SchemeCodes(
  const ARegistry: ISignatureSchemeRegistry): TArray<UInt16>;
var
  LSchemes: TArray<TSignatureScheme>;
  LI: Int32;
begin
  Result := nil;
  LSchemes := ARegistry.Items;
  SetLength(Result, System.Length(LSchemes));
  for LI := 0 to System.High(LSchemes) do
    Result[LI] := LSchemes[LI].ToCode;
end;

class function TTlsEngineFactory.PreferredGroup(const AConfig: ITlsCommonConfig;
  out ACode: UInt16): INamedGroup;
var
  LGroups: TArray<UInt16>;
begin
  LGroups := AConfig.PreferredGroups;
  if System.Length(LGroups) = 0 then
    raise EArgumentTlsLibException.CreateRes(@SNoPreferredGroup);
  ACode := LGroups[0];
  if not AConfig.NamedGroups.TryGet(ACode, Result) then
    raise EArgumentTlsLibException.CreateResFmt(@SUnconfiguredGroup, [ACode]);
end;

class function TTlsEngineFactory.PreferredEcdheGroup(
  const AConfig: ITlsCommonConfig): INamedGroup;
var
  LCode: UInt16;
  LGroup: INamedGroup;
begin
  for LCode in AConfig.PreferredGroups do
    if AConfig.NamedGroups.TryGet(LCode, LGroup) and
      (LGroup.Kind = TNamedGroupKind.Ecdhe) then
      Exit(LGroup);
  raise EArgumentTlsLibException.CreateRes(@SNoEcdheGroup);
end;

class function TTlsEngineFactory.EcdheGroupCodes(const AConfig: ITlsCommonConfig;
  const ACodes: TArray<UInt16>): TArray<UInt16>;
var
  LCode: UInt16;
  LGroup: INamedGroup;
  LN: Int32;
begin
  Result := nil;
  for LCode in ACodes do
    if AConfig.NamedGroups.TryGet(LCode, LGroup) and
      (LGroup.Kind = TNamedGroupKind.Ecdhe) then
    begin
      LN := System.Length(Result);
      SetLength(Result, LN + 1);
      Result[LN] := LCode;
    end;
end;

class function TTlsEngineFactory.Offers(const AConfig: ITlsCommonConfig;
  AVersion: UInt16): Boolean;
begin
  Result := TArrayUtilities.Contains<UInt16>(AConfig.SupportedVersions, AVersion);
end;

class function TTlsEngineFactory.CreateClientEngine(
  const AConfig: ITlsClientConfig; const AHost: string): ITlsEngine;
var
  L13: TClientHandshakeParams;
  L12: TClient12HandshakeParams;
  LClientRandom, LSessionId: TBytes;
  LVerifier: ICertificateVerifier;
  LOffers13, LOffers12, LAsyncVerdict: Boolean;
  LVerdictDeadlineMs: Cardinal;
  LMachine: IHandshakeMachine;
begin
  LOffers13 := Offers(AConfig, TlsWireVersionTls13);
  LOffers12 := Offers(AConfig, TlsWireVersionTls12);
  // the async peer-certificate verdict parks the handshake after the pipeline accepts the
  // server chain; the deadline is surfaced to the driver (the engine owns no timer)
  LAsyncVerdict := AConfig.AsyncCertificateVerdict.Enabled;
  if LAsyncVerdict then
    LVerdictDeadlineMs := AConfig.AsyncCertificateVerdict.DeadlineMs
  else
    LVerdictDeadlineMs := 0;
  // the two client machines must share one client random and session id so a 1.2
  // hand-off keeps the ServerKeyExchange/master-secret binding of the sent ClientHello
  LClientRandom := AConfig.Provider.GetRandom.GenerateBytes(32);
  LSessionId := AConfig.Provider.GetRandom.GenerateBytes(32);
  // an injected whole-verifier replaces the built-in pipeline (it consults no anchors)
  if AConfig.CertificateVerifier <> nil then
    LVerifier := AConfig.CertificateVerifier
  else
    LVerifier := TCertificateVerifier.Create(AConfig.Provider, AConfig.Clock,
      AConfig.TrustStore, AConfig.CheckServerName, AConfig.CertificateChainLimits,
      AConfig.RevocationPosture, AConfig.CertificatePins, AConfig.DangerousTrust,
      LAsyncVerdict);

  L13 := Default(TClientHandshakeParams);
  L13.Provider := AConfig.Provider;
  L13.Group := PreferredGroup(AConfig, L13.GroupCode);
  // advertise every preferred group and carry the registry, so the server may retry
  // the client onto any offered group it prefers (HelloRetryRequest)
  L13.OfferedGroups := AConfig.PreferredGroups;
  L13.GroupRegistry := AConfig.NamedGroups;
  L13.CipherSuites := AConfig.CipherSuites;
  L13.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  L13.OfferedSuites := SuiteCodes(AConfig.CipherSuites);
  L13.OfferedSchemes := SchemeCodes(AConfig.SignatureSchemes);
  L13.AlpnProtocols := AConfig.AlpnProtocols;
  // the client advertises what it can decompress (RFC 8879)
  L13.CertificateDecompressors := AConfig.CertificateDecompressors;
  // GREASE is on by default for a client (RFC 8701 keeps peers tolerant); optional per the RFC
  L13.Grease := AConfig.Grease;
  L13.RequestOcspStapling := AConfig.RequestOcspStapling;
  // the config guarantees a non-nil clock (system clock by default); it backs a resumption
  // PSK's obfuscated_ticket_age and ticket-lifetime expiry
  L13.Clock := AConfig.Clock;
  L13.ClientRandom := LClientRandom;
  L13.LegacySessionId := LSessionId;
  L13.ServerName := AHost;
  L13.CertificateVerifier := LVerifier;
  L13.AsyncVerdict := LAsyncVerdict;
  L13.ExpectedHostName := AHost;
  // a mutual-TLS client presents this credential when the server requests one; empty
  // sends an empty client Certificate
  L13.ClientCredential := AConfig.Credential;

  L12 := Default(TClient12HandshakeParams);
  L12.Provider := AConfig.Provider;
  L12.GroupRegistry := AConfig.NamedGroups;
  L12.CipherSuites := AConfig.CipherSuites;
  L12.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  L12.Clock := AConfig.Clock;
  L12.OfferedSuites := SuiteCodes(AConfig.CipherSuites);
  // TLS 1.2 key exchange is ECDHE-only: a 1.2 supported_groups carries no KEM/hybrid group,
  // so a client that reaches the 1.2 path (never offering 1.3) does not advertise one
  L12.OfferedGroups := EcdheGroupCodes(AConfig, AConfig.PreferredGroups);
  L12.OfferedSchemes := SchemeCodes(AConfig.SignatureSchemes);
  L12.AlpnProtocols := AConfig.AlpnProtocols;
  L12.OfferedVersions := AConfig.SupportedVersions;
  L12.ClientRandom := LClientRandom;
  // the non-empty legacy_session_id is the TLS 1.3 middlebox-compatibility session id
  // (RFC 8446 D.4); a client that does not offer 1.3 sends an empty session id
  if LOffers13 then
    L12.LegacySessionId := LSessionId
  else
    L12.LegacySessionId := nil;
  L12.ServerName := AHost;
  L12.OfferExtendedMasterSecret := True;
  L12.RequireExtendedMasterSecret := AConfig.RequireExtendedMasterSecret;
  L12.RequestOcspStapling := AConfig.RequestOcspStapling;
  L12.CertificateVerifier := LVerifier;
  L12.AsyncVerdict := LAsyncVerdict;
  L12.ExpectedHostName := AHost;
  L12.ClientCredential := AConfig.Credential;

  // resumption (RFC 8446 4.6.1 / RFC 5077): the version-appropriate client machine draws a
  // cached session and offers it. In a dual-version client the 1.3 machine draws (preferring
  // a 1.3 ticket, else offering a cached 1.2 session it hands to the 1.2 machine); either
  // way the 1.2 machine still needs the cache to store completed 1.2 sessions, so wire both.
  if AConfig.Resumption and (AConfig.SessionCache <> nil) then
  begin
    if LOffers13 then
    begin
      L13.SessionCache := AConfig.SessionCache;
      L13.EarlyDataEnabled := AConfig.EarlyData;
    end;
    if LOffers12 then
      L12.SessionCache := AConfig.SessionCache;
  end;

  // out-of-band external PSKs (RFC 9258) are a TLS 1.3-only offer; the 1.2 machine ignores
  // them. A PSK-only client (external PSKs configured with no certificate trust to fall back
  // on) requires the server to select a PSK - a non-PSK ServerHello is then fatal.
  if LOffers13 then
  begin
    L13.ExternalPsks := AConfig.ExternalPsks;
    L13.RequirePsk := (System.Length(AConfig.ExternalPsks) > 0) and
      AConfig.ExternalPskRequired;
  end;

  if LOffers13 and LOffers12 then
    LMachine := TClientVersionDispatchMachine.Create(L13, L12)
  else if LOffers13 then
    LMachine := TTls13ClientStateMachine.Create(L13)
  else
    LMachine := TTls12ClientStateMachine.Create(L12);

  Result := TTlsEngine.CreateConfigured(LMachine, AConfig.Provider,
    LVerdictDeadlineMs);
end;

class function TTlsEngineFactory.CreateServerEngine(
  const AConfig: ITlsServerConfig): ITlsEngine;
var
  L13: TServerHandshakeParams;
  L12: TServer12HandshakeParams;
  LServerRandom: TBytes;
  LOffers13, LOffers12, LAsyncVerdict: Boolean;
  LVerdictDeadlineMs: Cardinal;
  LMachine: IHandshakeMachine;
begin
  LOffers13 := Offers(AConfig, TlsWireVersionTls13);
  LOffers12 := Offers(AConfig, TlsWireVersionTls12);
  LServerRandom := AConfig.Provider.GetRandom.GenerateBytes(32);
  // the async client-certificate verdict parks the handshake after the pipeline accepts the
  // client chain (only meaningful when the server requests client authentication)
  LAsyncVerdict := AConfig.AsyncCertificateVerdict.Enabled and
    (AConfig.ClientAuth <> TClientAuthMode.None);
  if LAsyncVerdict then
    LVerdictDeadlineMs := AConfig.AsyncCertificateVerdict.DeadlineMs
  else
    LVerdictDeadlineMs := 0;

  L13 := Default(TServerHandshakeParams);
  L13.Provider := AConfig.Provider;
  L13.Clock := AConfig.Clock;
  L13.Policy := TNegotiationPolicy.Create(AConfig.Provider, AConfig.CipherSuites,
    AConfig.NamedGroups, AConfig.SignatureSchemes, AConfig.PreferredGroups,
    AConfig.SupportedVersions, AConfig.CipherSuitePreference);
  L13.CipherSuites := AConfig.CipherSuites;
  L13.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  // the server offers all its preferred groups and selects one the client offered (RFC 8446
  // 4.2.8); secp256r1 is mandatory to implement (9.1), so it is never a single group
  L13.OfferedGroups := AConfig.PreferredGroups;
  L13.GroupRegistry := AConfig.NamedGroups;
  L13.ServerRandom := LServerRandom;
  L13.AlpnProtocols := AConfig.AlpnProtocols;
  // the server compresses its Certificate with what it holds and the client advertised
  L13.CertificateCompressors := AConfig.CertificateCompressors;
  // memoize that compression across connections (a stable certificate deflates once)
  L13.CertificateCompressionCache := AConfig.CertificateCompressionCache;
  // a per-server-instance secret so the server can answer with a stateless HelloRetryRequest
  L13.CookieSecret := TSecretBuffer.From(AConfig.Provider.GetRandom.GenerateBytes(32));
  // the resolver selects the credential per handshake from the client's SNI (virtual hosting);
  // each credential carries the chain, key, and (when set) the OCSP staple the server sends for
  // its leaf once the client offers status_request
  L13.CredentialResolver := AConfig.CredentialResolver;
  L13.ServerNameAck := AConfig.ServerNameAcknowledgement;
  L13.AlpnRejectAll := AConfig.AlpnRejectAll;
  // mutual TLS: request a client certificate and verify it against the trust store
  L13.ClientAuth := AConfig.ClientAuth;
  L13.ClientAuthSignatureSchemes := SchemeCodes(AConfig.SignatureSchemes);
  L13.ClientCertificateAuthorities := AConfig.ClientCertificateAuthorities;
  if AConfig.ClientAuth <> TClientAuthMode.None then
  begin
    if AConfig.CertificateVerifier <> nil then
      L13.ClientCertificateVerifier := AConfig.CertificateVerifier
    else
      L13.ClientCertificateVerifier := TCertificateVerifier.Create(AConfig.Provider,
        AConfig.Clock, AConfig.TrustStore, False, AConfig.CertificateChainLimits,
        AConfig.RevocationPosture, AConfig.CertificatePins, AConfig.DangerousTrust,
        LAsyncVerdict);
  end;
  L13.AsyncVerdict := LAsyncVerdict;

  L12 := Default(TServer12HandshakeParams);
  L12.Provider := AConfig.Provider;
  L12.Clock := AConfig.Clock;
  L12.CipherSuites := AConfig.CipherSuites;
  L12.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  // TLS 1.2 needs a classical ECDHE group (KEM/hybrid are 1.3-only); the server picks
  // the first of these the client also advertised, so OfferedGroups drives selection
  // and Group is only the low-level single-group fallback
  L12.GroupRegistry := AConfig.NamedGroups;
  L12.OfferedGroups := EcdheGroupCodes(AConfig, AConfig.PreferredGroups);
  if LOffers12 then
    L12.Group := PreferredEcdheGroup(AConfig);
  L12.ServerRandom := LServerRandom;
  L12.CredentialResolver := AConfig.CredentialResolver;
  L12.RequireExtendedMasterSecret := AConfig.RequireExtendedMasterSecret;
  L12.ServerNameAck := AConfig.ServerNameAcknowledgement;
  L12.AlpnRejectAll := AConfig.AlpnRejectAll;
  L12.ClientCertificateAuthorities := AConfig.ClientCertificateAuthorities;
  L12.AlpnProtocols := AConfig.AlpnProtocols;
  L12.ClientAuth := AConfig.ClientAuth;
  L12.ClientAuthSignatureSchemes := SchemeCodes(AConfig.SignatureSchemes);
  if AConfig.ClientAuth <> TClientAuthMode.None then
  begin
    if AConfig.CertificateVerifier <> nil then
      L12.ClientCertificateVerifier := AConfig.CertificateVerifier
    else
      L12.ClientCertificateVerifier := TCertificateVerifier.Create(AConfig.Provider,
        AConfig.Clock, AConfig.TrustStore, False, AConfig.CertificateChainLimits,
        AConfig.RevocationPosture, AConfig.CertificatePins, AConfig.DangerousTrust,
        LAsyncVerdict);
  end;
  L12.AsyncVerdict := LAsyncVerdict;

  // resumption (RFC 8446 4.6.1 / RFC 5077): both version machines share the session
  // store/STEK; each stores and accepts only its own version's sessions. 0-RTT is 1.3-only,
  // so the early-data budget and anti-replay reach only the 1.3 machine
  if AConfig.Resumption then
  begin
    L13.SessionStore := AConfig.SessionStore;
    L13.SessionTicketKeys := AConfig.SessionTicketKeys;
    L13.IssueTicketCount := AConfig.TicketCount;
    L13.TicketLifetimeSeconds := AConfig.TicketLifetimeSeconds;
    L13.MaxEarlyData := AConfig.MaxEarlyData;
    L13.AntiReplay := AConfig.AntiReplay;
    // a server authorizing early data needs an anti-replay register; default one when the
    // budget is positive but none was supplied (RFC 8446 8)
    if (L13.MaxEarlyData > 0) and (L13.AntiReplay = nil) then
      L13.AntiReplay := TStrikeRegisterAntiReplay.Create as IAntiReplayStrategy;
    L12.SessionStore := AConfig.SessionStore;
    L12.SessionTicketKeys := AConfig.SessionTicketKeys;
    L12.TicketLifetimeSeconds := AConfig.TicketLifetimeSeconds;
  end;

  // out-of-band external PSKs (RFC 9258) are matched only on the TLS 1.3 path
  if LOffers13 then
    L13.ExternalPsks := AConfig.ExternalPsks;

  if LOffers13 and LOffers12 then
    LMachine := TServerVersionDispatchMachine.Create(L13, L12,
      AConfig.SupportedVersions)
  else if LOffers13 then
    LMachine := TTls13ServerStateMachine.Create(L13)
  else
    LMachine := TTls12ServerStateMachine.Create(L12);

  Result := TTlsEngine.CreateConfigured(LMachine, AConfig.Provider,
    LVerdictDeadlineMs);
end;

end.
