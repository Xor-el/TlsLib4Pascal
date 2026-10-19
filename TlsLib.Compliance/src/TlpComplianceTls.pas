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
  TlpCipherSuiteCatalog,
  TlpCipherSuiteRegistry,
  TlpSignatureSchemeRegistry,
  TlpINamedGroup,
  TlpINegotiation,
  TlpNamedGroups,
  TlpCertificateLimits,
  TlpCertificateVerifierSource,
  TlpICertificateVerifierSource,
  TlpTlsCredential,
  TlpTrustPolicy,
  TlpITlsConfig,
  TlpITlsConfigBuilder,
  TlpTlsConfigBuilder,
  TlpSystemTrustBase,
  TlpOSSystemTrust,
  TlpSystemTrustFacade,
  TlpTlsLibExceptions,
  TlpComplianceTypes,
  TlpICompliancePolicy;

type
  /// <summary>
  /// Config builders seeded from a compliance policy: the policy's providers and allowlists, the
  /// OS verifier, and the extended-master-secret requirement. Build through BuildClient or
  /// BuildServer so the frozen config is admitted by the policy; a config built any other way
  /// skips the checks that are not crypto.
  /// </summary>
  TComplianceTls = class sealed(TObject)
  strict private
    class function Profile(const APolicy: ICompliancePolicy): TTlsConfigProfile; static;
    class function GroupRegistry(const APolicy: ICompliancePolicy): INamedGroupRegistry; static;
  public
    /// <summary>A client builder verifying the server through the OS verifier, trusting ARoots
    /// (the OS roots, the OS roots and host roots, or host roots alone). Raises
    /// ESystemTrustUnsupported where the platform has none.</summary>
    class function Client(const APolicy: ICompliancePolicy;
      const ARoots: TSystemTrustRoots): ITlsClientConfigBuilder; overload; static;
    /// <summary>A client builder verifying the server by AVerification, held to the strength floors
    /// of the rules.</summary>
    class function Client(const APolicy: ICompliancePolicy;
      const AVerification: IServerVerificationBuilder): ITlsClientConfigBuilder;
      overload; static;
    /// <summary>As the ARoots overload, with live revocation under APosture; pair it with the OS
    /// live-revocation resolver on the stream.</summary>
    class function Client(const APolicy: ICompliancePolicy; const ARoots: TSystemTrustRoots;
      APosture: TRevocationPosture; ADeadlineMs: Cardinal): ITlsClientConfigBuilder;
      overload; static;
    /// <summary>A server builder presenting ACredential, its key narrowed to the schemes of the
    /// rules. Load the credential through the policy's crypto provider.</summary>
    class function Server(const APolicy: ICompliancePolicy;
      const ACredential: TTlsCredential): ITlsServerConfigBuilder; static;
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
  SNilBuilder = 'the config builder must not be nil';

{ TComplianceTls }

class function TComplianceTls.GroupRegistry(const APolicy: ICompliancePolicy)
  : INamedGroupRegistry;
var
  LRules: TComplianceRules;
  LGroups: TArray<INamedGroup>;
  LI: Int32;
begin
  LRules := APolicy.Rules;
  SetLength(LGroups, System.Length(LRules.NamedGroups));
  for LI := 0 to System.Length(LRules.NamedGroups) - 1 do
    // built over the policy crypto, so each group's agreement is the refusing one
    LGroups[LI] := TNamedGroups.CreateNistEcdh(APolicy.Crypto,
      TNamedGroupCatalog.Name(LRules.NamedGroups[LI]));
  Result := TNamedGroups.CreateRegistry(LGroups);
end;

class function TComplianceTls.Profile(const APolicy: ICompliancePolicy): TTlsConfigProfile;
var
  LRules: TComplianceRules;
  LSuites: ICipherSuiteRegistryBuilder;
  LSchemes: ISignatureSchemeRegistryBuilder;
  LSuite: TTlsCipherSuite;
  LDefaults: TArray<TSignatureScheme>;
  LI: Int32;
  LKnown: Boolean;
begin
  LRules := APolicy.Rules;
  Result := TTlsConfigProfile.Default;
  LSuites := TCipherSuiteRegistryBuilder.Create as ICipherSuiteRegistryBuilder;
  for LI := 0 to System.Length(LRules.CipherSuites) - 1 do
  begin
    LKnown := TCipherSuiteCatalog.TryGet(LRules.CipherSuites[LI], LSuite);
    if LKnown then
      LSuites.Add(LSuite);
  end;
  Result.CipherSuites := LSuites.Build;
  LSchemes := TSignatureSchemeRegistryBuilder.Create as ISignatureSchemeRegistryBuilder;
  LDefaults := TSignatureSchemeRegistry.CreateDefault.Items;
  for LI := 0 to System.Length(LDefaults) - 1 do
    if LDefaults[LI] in LRules.SignatureSchemes then
      LSchemes.Add(LDefaults[LI]);
  Result.SignatureSchemes := LSchemes.Build;
  Result.NamedGroups := GroupRegistry(APolicy);
  Result.SupportedVersions := LRules.Versions;
  Result.PreferredGroups := LRules.NamedGroups;
  Result.CertificateChainLimits := TCertificateChainLimits.Defaults;
  Result.RequestOcspStapling := False;
  // session tickets are always sealed with AES-256-GCM
  Result.Resumption := TAeadAlgorithm.AES_256_GCM in LRules.Aeads;
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
  LOffers12: Boolean;
begin
  if APolicy = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilPolicy);
  if AVerification = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilVerification);
  LRules := APolicy.Rules;
  Result := TTlsConfigBuilder.CreateFromProfile(APolicy.Crypto, APolicy.Pkix,
    Profile(APolicy)).Client.WithServerVerification(
    AVerification.WithMinimumStrength(LRules.Strength).Build);
  LOffers12 := TArrayUtilities.Contains<UInt16>(LRules.Versions, TlsWireVersionTls12);
  if LOffers12 and (TComplianceRequirement.ExtendedMasterSecret in LRules.Requirements) then
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
var
  LRules: TComplianceRules;
  LCredential: TTlsCredential;
  LOffers12: Boolean;
begin
  if APolicy = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilPolicy);
  LRules := APolicy.Rules;
  LCredential := ACredential;
  // a server signs with its credential key, so the key itself must be narrowed
  if LCredential.PrivateKey <> nil then
    LCredential.PrivateKey := LCredential.PrivateKey.WithPreferredSchemes(
      TComplianceCatalog.Schemes(LRules.SignatureSchemes));
  Result := TTlsConfigBuilder.CreateFromProfile(APolicy.Crypto, APolicy.Pkix,
    Profile(APolicy)).Server.WithCredential(LCredential);
  LOffers12 := TArrayUtilities.Contains<UInt16>(LRules.Versions, TlsWireVersionTls12);
  if LOffers12 and (TComplianceRequirement.ExtendedMasterSecret in LRules.Requirements) then
    Result.Tls12.WithExtendedMasterSecret(True);
end;

class function TComplianceTls.BuildClient(const APolicy: ICompliancePolicy;
  const ABuilder: ITlsClientConfigBuilder): ITlsClientConfig;
begin
  if APolicy = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilPolicy);
  if ABuilder = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilBuilder);
  Result := ABuilder.Build;
  APolicy.Admit(Result);
end;

class function TComplianceTls.BuildServer(const APolicy: ICompliancePolicy;
  const ABuilder: ITlsServerConfigBuilder): ITlsServerConfig;
begin
  if APolicy = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilPolicy);
  if ABuilder = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilBuilder);
  Result := ABuilder.Build;
  APolicy.Admit(Result);
end;

end.
