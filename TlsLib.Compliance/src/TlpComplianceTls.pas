{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpComplianceTls;

{$I ..\..\TlsLib\src\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpArrayUtilities,
  TlpCryptoDomainTypes,
  TlpNegotiationTypes,
  TlpTlsVersion,
  TlpCipherSuiteRegistry,
  TlpIClock,
  TlpClock,
  TlpSignatureSchemeRegistry,
  TlpINegotiation,
  TlpCertificateLimits,
  TlpCertificateVerifierSource,
  TlpICertificateVerifierSource,
  TlpTlsCredential,
  TlpITlsCredentialResolver,
  TlpTrustPolicy,
  TlpITlsConfig,
  TlpITrustAnchorStore,
  TlpITlsConfigBuilder,
  TlpTlsConfigBuilder,
  TlpSessionTicketStrategy,
  TlpSystemTrustBase,
  TlpOSSystemTrust,
  TlpSystemTrustFacade,
  TlpTlsLibExceptions,
  TlpComplianceTypes,
  TlpICompliancePolicy;

type
  /// <summary>
  /// Config builders seeded from a compliance policy: the policy's providers and allowlists, the
  /// OS verifier for the server chain and, through WithPeerAuth, for a client chain, and the
  /// extended-master-secret requirement. Build through BuildClient or
  /// BuildServer so the frozen config is admitted by the policy. Only Admit holds a config to the
  /// groups and the verifier source it carries: a key agreement runs inside its group object, and
  /// a chain is verified by the source, neither through the policy providers.
  /// </summary>
  TComplianceTls = class sealed(TObject)
  strict private
    class function RequiresExtendedMasterSecret(
      const ARules: TComplianceRules): Boolean; static;
    class function Profile(const APolicy: ICompliancePolicy): TTlsConfigProfile; static;
    class function ServerBase(const APolicy: ICompliancePolicy)
      : ITlsServerConfigBuilder; static;
    class procedure CheckPeerAuth(const APolicy: ICompliancePolicy;
      const ABuilder: ITlsServerConfigBuilder; AMode: TClientAuthMode); static;
    class function ApplyPeerAuth(const APolicy: ICompliancePolicy;
      const ABuilder: ITlsServerConfigBuilder; AMode: TClientAuthMode;
      const AVerification: IClientVerificationBuilder): ITlsServerConfigBuilder; static;
  public
    /// <summary>A client builder verifying the server through the OS verifier, trusting ARoots
    /// (the OS roots, the OS roots and host roots, or host roots alone). Raises
    /// ESystemTrustUnsupportedTlsLibException where the platform has none.</summary>
    class function Client(const APolicy: ICompliancePolicy;
      const ARoots: TSystemTrustRoots): ITlsClientConfigBuilder; overload; static;
    /// <summary>A client builder verifying the server by AVerification, held to the strength floors
    /// of the rules. AVerification itself is changed, not copied, and any minimum strength set on
    /// it is replaced by the floors of the rules, as the builder cannot be read back.</summary>
    class function Client(const APolicy: ICompliancePolicy;
      const AVerification: IServerVerificationBuilder): ITlsClientConfigBuilder;
      overload; static;
    /// <summary>As the ARoots overload, with live revocation under APosture; pair it with the OS
    /// live-revocation resolver on the stream.</summary>
    class function Client(const APolicy: ICompliancePolicy; const ARoots: TSystemTrustRoots;
      APosture: TRevocationPosture; ADeadlineMs: Cardinal): ITlsClientConfigBuilder;
      overload; static;
    /// <summary>A server builder presenting ACredential, its key narrowed to the schemes of the
    /// rules. Load the credential through the policy's crypto provider. Session resumption is
    /// off unless the rules allow AES-256-GCM, which seals the tickets.</summary>
    class function Server(const APolicy: ICompliancePolicy;
      const ACredential: TTlsCredential): ITlsServerConfigBuilder; overload; static;
    /// <summary>As the credential overload, selecting the credential per handshake through
    /// AResolver wrapped by the policy's CheckedCredentialResolver. Raises
    /// EArgumentTlsLibException for a nil AResolver.</summary>
    class function Server(const APolicy: ICompliancePolicy;
      const AResolver: ITlsServerCredentialResolver): ITlsServerConfigBuilder;
      overload; static;
    /// <summary>ABuilder, a facade server builder, with resumption off: it clears the ticket keys
    /// and the resumption scope the facade set, which the builder otherwise refuses while
    /// resumption is off. Raises EArgumentTlsLibException for a nil ABuilder.</summary>
    class function WithoutResumption(
      const ABuilder: ITlsServerConfigBuilder): ITlsServerConfigBuilder; static;
    /// <summary>ABuilder requesting a client certificate per AMode, verified by the OS verifier
    /// with AClientCa as its only root (the OS roots are never consulted), cache-only
    /// revocation, and the strength floors of the rules. Raises EArgumentTlsLibException for a
    /// nil argument, AMode None, or an AClientCa with no root certificates, and
    /// ESystemTrustUnsupportedTlsLibException where the platform has no OS client verifier.</summary>
    class function WithPeerAuth(const APolicy: ICompliancePolicy;
      const ABuilder: ITlsServerConfigBuilder; AMode: TClientAuthMode;
      const AClientCa: ITrustAnchorStore): ITlsServerConfigBuilder; overload; static;
    /// <summary>ABuilder requesting a client certificate per AMode, verified by AVerification, held
    /// to the strength floors of the rules. AVerification itself is changed, not copied, and any
    /// minimum strength set on it is replaced by the floors of the rules. Raises
    /// EArgumentTlsLibException for a nil argument or AMode None.</summary>
    class function WithPeerAuth(const APolicy: ICompliancePolicy;
      const ABuilder: ITlsServerConfigBuilder; AMode: TClientAuthMode;
      const AVerification: IClientVerificationBuilder): ITlsServerConfigBuilder;
      overload; static;
    /// <summary>As the AClientCa overload, with live revocation under APosture; the result defers
    /// to the live-revocation verdict, so pair it with the OS live-revocation resolver on the
    /// server config.</summary>
    class function WithPeerAuth(const APolicy: ICompliancePolicy;
      const ABuilder: ITlsServerConfigBuilder; AMode: TClientAuthMode;
      const AClientCa: ITrustAnchorStore; APosture: TRevocationPosture;
      ADeadlineMs: Cardinal): ITlsServerConfigBuilder; overload; static;
    /// <summary>Builds the client config and admits it, raising
    /// EComplianceUnmetTlsLibException when the policy refuses it.</summary>
    class function BuildClient(const APolicy: ICompliancePolicy;
      const ABuilder: ITlsClientConfigBuilder): ITlsClientConfig; static;
    /// <summary>Builds the server config and admits it, raising
    /// EComplianceUnmetTlsLibException when the policy refuses it.</summary>
    class function BuildServer(const APolicy: ICompliancePolicy;
      const ABuilder: ITlsServerConfigBuilder): ITlsServerConfig; static;
  end;

implementation

resourcestring
  SNilPolicy = 'the compliance policy must not be nil';
  SNilVerification = 'the server verification must not be nil';
  SNilResolver = 'the credential resolver must not be nil';
  SNilBuilder = 'the config builder must not be nil';
  SNilClientVerification = 'the client verification must not be nil';
  SClientAuthNone = 'the client authentication mode must request a client certificate';
  SClientCaNeedsRoots = 'the client CA store must hold at least one root certificate';

{ TComplianceTls }

class function TComplianceTls.RequiresExtendedMasterSecret(
  const ARules: TComplianceRules): Boolean;
var
  LOffers12: Boolean;
begin
  LOffers12 := TArrayUtilities.Contains<UInt16>(ARules.Versions, TlsWireVersionTls12);
  Result := LOffers12 and (TComplianceRequirement.ExtendedMasterSecret in ARules.Requirements);
end;

class function TComplianceTls.Profile(const APolicy: ICompliancePolicy): TTlsConfigProfile;
var
  LRules: TComplianceRules;
begin
  LRules := APolicy.Rules;
  Result := TTlsConfigProfile.Default;
  Result.CipherSuites := TCipherSuiteRegistry.CreateFromCodes(LRules.CipherSuites);
  Result.SignatureSchemes := TSignatureSchemeRegistry.CreateDefaultRestricted(
    TComplianceCatalog.Schemes(LRules.SignatureSchemes));
  Result.NamedGroups := APolicy.NamedGroups;
  Result.SupportedVersions := LRules.Versions;
  Result.PreferredGroups := LRules.NamedGroups;
  Result.CertificateChainLimits := TCertificateChainLimits.Defaults;
  Result.RequestOcspStapling := False;
end;

class function TComplianceTls.ServerBase(const APolicy: ICompliancePolicy)
  : ITlsServerConfigBuilder;
var
  LRules: TComplianceRules;
begin
  if APolicy = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilPolicy);
  LRules := APolicy.Rules;
  Result := TTlsConfigBuilder.CreateFromProfile(APolicy.Crypto, APolicy.Pkix,
    Profile(APolicy)).Server;
  if RequiresExtendedMasterSecret(LRules) then
    Result.Tls12.WithExtendedMasterSecret(True);
  // only a server seals tickets, and always with the ticket AEAD
  if TSessionTicketStrategies.TicketAead in LRules.Aeads then
    Result.WithResumptionScope(APolicy.SessionScope).WithSessionTicketKeys(
      APolicy.TicketKeys(TSystemClock.Create as ITlsClock,
      TTlsConfigBuilder.DefaultTicketLifetimeSeconds))
  else
    Result.WithResumption(False);
end;

class function TComplianceTls.Client(const APolicy: ICompliancePolicy;
  const ARoots: TSystemTrustRoots): ITlsClientConfigBuilder;
begin
  if APolicy = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilPolicy);
  // the mode is Delegate, never Default, so the OS verifier decides on every platform
  Result := Client(APolicy, TSystemTrust.ServerVerification(APolicy.Pkix,
    TSystemTrustMode.Delegate, ARoots));
end;

class function TComplianceTls.Client(const APolicy: ICompliancePolicy;
  const AVerification: IServerVerificationBuilder): ITlsClientConfigBuilder;
var
  LRules: TComplianceRules;
begin
  if APolicy = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilPolicy);
  if AVerification = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilVerification);
  LRules := APolicy.Rules;
  Result := TTlsConfigBuilder.CreateFromProfile(APolicy.Crypto, APolicy.Pkix,
    Profile(APolicy)).Client.WithServerVerification(
    AVerification.WithMinimumStrength(LRules.Strength).Build);
  if RequiresExtendedMasterSecret(LRules) then
    Result.Tls12.WithExtendedMasterSecret(True);
end;

class function TComplianceTls.Client(const APolicy: ICompliancePolicy;
  const ARoots: TSystemTrustRoots; APosture: TRevocationPosture;
  ADeadlineMs: Cardinal): ITlsClientConfigBuilder;
var
  LVerification: IServerVerificationBuilder;
begin
  if APolicy = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilPolicy);
  // a later WithLiveSystemTrust would replace this verification and drop the strength floors
  LVerification := TServerVerification.VerifierSource(TOSSystemTrust.ServerVerifierSource(
    TSystemTrustFetch.Live, ARoots, APolicy.Pkix)).WithRevocation(APosture);
  Result := Client(APolicy, LVerification).WithLiveRevocationVerdict(ADeadlineMs);
end;

class function TComplianceTls.Server(const APolicy: ICompliancePolicy;
  const ACredential: TTlsCredential): ITlsServerConfigBuilder;
begin
  Result := ServerBase(APolicy);
  // a server signs with its credential key, so the key itself must be narrowed
  Result.WithCredential(TComplianceCatalog.NarrowedCredential(ACredential,
    TComplianceCatalog.Schemes(APolicy.Rules.SignatureSchemes)));
end;

class function TComplianceTls.Server(const APolicy: ICompliancePolicy;
  const AResolver: ITlsServerCredentialResolver): ITlsServerConfigBuilder;
begin
  if APolicy = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilPolicy);
  if AResolver = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilResolver);
  Result := ServerBase(APolicy);
  Result.WithCredentialResolver(APolicy.CheckedCredentialResolver(AResolver));
end;

class function TComplianceTls.WithoutResumption(
  const ABuilder: ITlsServerConfigBuilder): ITlsServerConfigBuilder;
begin
  if ABuilder = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilBuilder);
  Result := ABuilder.WithSessionTicketKeys(nil).WithResumptionScope(nil).WithResumption(False);
end;

class function TComplianceTls.WithPeerAuth(const APolicy: ICompliancePolicy;
  const ABuilder: ITlsServerConfigBuilder; AMode: TClientAuthMode;
  const AClientCa: ITrustAnchorStore): ITlsServerConfigBuilder;
begin
  CheckPeerAuth(APolicy, ABuilder, AMode);
  if (AClientCa = nil) or (AClientCa.AnchorCount = 0) then
    raise EArgumentTlsLibException.CreateRes(@SClientCaNeedsRoots);
  Result := ApplyPeerAuth(APolicy, ABuilder, AMode, TClientVerification.VerifierSource(
    TOSSystemTrust.ClientVerifierSource(TSystemTrustFetch.CacheOnly), AClientCa));
end;

class function TComplianceTls.WithPeerAuth(const APolicy: ICompliancePolicy;
  const ABuilder: ITlsServerConfigBuilder; AMode: TClientAuthMode;
  const AVerification: IClientVerificationBuilder): ITlsServerConfigBuilder;
begin
  CheckPeerAuth(APolicy, ABuilder, AMode);
  if AVerification = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilClientVerification);
  Result := ApplyPeerAuth(APolicy, ABuilder, AMode, AVerification);
end;

class procedure TComplianceTls.CheckPeerAuth(const APolicy: ICompliancePolicy;
  const ABuilder: ITlsServerConfigBuilder; AMode: TClientAuthMode);
begin
  if APolicy = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilPolicy);
  if ABuilder = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilBuilder);
  if AMode = TClientAuthMode.None then
    raise EArgumentTlsLibException.CreateRes(@SClientAuthNone);
end;

class function TComplianceTls.ApplyPeerAuth(const APolicy: ICompliancePolicy;
  const ABuilder: ITlsServerConfigBuilder; AMode: TClientAuthMode;
  const AVerification: IClientVerificationBuilder): ITlsServerConfigBuilder;
begin
  // a later WithClientVerification would replace this verification and drop the strength floors
  Result := ABuilder.WithPeerAuth(AMode).WithClientVerification(
    AVerification.WithMinimumStrength(APolicy.Rules.Strength).Build);
end;

class function TComplianceTls.WithPeerAuth(const APolicy: ICompliancePolicy;
  const ABuilder: ITlsServerConfigBuilder; AMode: TClientAuthMode;
  const AClientCa: ITrustAnchorStore; APosture: TRevocationPosture;
  ADeadlineMs: Cardinal): ITlsServerConfigBuilder;
var
  LVerification: IClientVerificationBuilder;
begin
  CheckPeerAuth(APolicy, ABuilder, AMode);
  if (AClientCa = nil) or (AClientCa.AnchorCount = 0) then
    raise EArgumentTlsLibException.CreateRes(@SClientCaNeedsRoots);
  LVerification := TClientVerification.VerifierSource(
    TOSSystemTrust.ClientVerifierSource(TSystemTrustFetch.Live), AClientCa)
    .WithRevocation(APosture);
  Result := ApplyPeerAuth(APolicy, ABuilder, AMode, LVerification)
    .WithLiveRevocationVerdict(ADeadlineMs);
end;

class function TComplianceTls.BuildClient(const APolicy: ICompliancePolicy;
  const ABuilder: ITlsClientConfigBuilder): ITlsClientConfig;
var
  LConfig: ITlsClientConfig;
begin
  if APolicy = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilPolicy);
  if ABuilder = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilBuilder);
  // a refused config must not reach the caller's variable
  LConfig := ABuilder.Build;
  APolicy.Admit(LConfig);
  Result := LConfig;
end;

class function TComplianceTls.BuildServer(const APolicy: ICompliancePolicy;
  const ABuilder: ITlsServerConfigBuilder): ITlsServerConfig;
var
  LConfig: ITlsServerConfig;
begin
  if APolicy = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilPolicy);
  if ABuilder = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilBuilder);
  LConfig := ABuilder.Build;
  APolicy.Admit(LConfig);
  Result := LConfig;
end;

end.
