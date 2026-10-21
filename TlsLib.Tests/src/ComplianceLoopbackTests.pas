{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

/// <summary>Handshakes between configs the compliance facade built, over the selected crypto
/// provider under a relaxed policy with a fake validated module.</summary>
unit ComplianceLoopbackTests;

{$I ..\..\TlsLib\src\Include\TlsLib.inc}

interface

uses
  SysUtils,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  TlpArrayUtilities,
  TlpCryptoDomainTypes,
  TlpNegotiationTypes,
  TlpTlsVersion,
  TlpTlsAlert,
  TlpITlsEngine,
  TlpTlsEngine,
  TlpTlsEngineFactory,
  TlpIHandshakeMachine,
  TlpIClock,
  TlpClock,
  TlpServerName,
  TlpCertificateVerifier,
  TlpCertificateVerifierSource,
  TlpICertificateTrust,
  TlpTrustPolicy,
  TlpNamedGroups,
  TlpCipherSuiteRegistry,
  TlpCoreExtensions,
  TlpITlsConfig,
  TlpITlsConfigBuilder,
  TlpTlsPresets,
  TlpTls12ClientStateMachine,
  TlpComplianceTypes,
  TlpIComplianceReport,
  TlpIModuleAttestation,
  TlpICompliancePolicy,
  TlpCompliancePolicy,
  TlpCompliancePresets,
  TlpComplianceTls,
  TlpOSSystemTrust,
  TlpOSDelegateVerifier,
  TlpTlsCredential,
  TlpITrustAnchorStore,
  TlpTrustAnchorStore,
  TlpISession,
  TlpSecretBuffer,
  TlpSessionTicketKeys,
  TlpInMemorySessionCache,
  TlpInMemorySessionStore,
  MockCompliance,
  TlsLibTestCertificates,
  TlsLibHandshakeTestBase;

type
  TTestComplianceLoopback = class(TTlsLibHandshakeTestCase)
  strict private
    function NewPolicy: ICompliancePolicy;
    function ClientConfig(const APolicy: ICompliancePolicy): ITlsClientConfig;
    function ServerConfig(const APolicy: ICompliancePolicy): ITlsServerConfig;
    function Tls12ClientConfig(const APolicy: ICompliancePolicy): ITlsClientConfig;
    function OutsideClient(const APreferredGroups: TArray<UInt16>;
      const ASuites: TArray<UInt16>): ITlsEngine;
    function NonEmsClient: ITlsEngine;
    function NoConfigurationFinding(const AReport: IComplianceReport): Boolean;
    function ReportHasChainFinding(const AReport: IComplianceReport): Boolean;
    // a fleet holding one installed key, as a shared STEK would
    function SharedFleet: IFleetTicketKeyManager;
    // a scope a host chose for a fleet, with no policy prefix
    function FleetScope: TBytes;
    // a client the policy admits that keeps its sessions in ACache under the policy scope
    function ResumingClient(const APolicy: ICompliancePolicy;
      const ACache: ISessionCache): ITlsClientConfig;
    // as ResumingClient, offering TLS 1.2 only
    function Tls12ResumingClient(const APolicy: ICompliancePolicy;
      const ACache: ISessionCache): ITlsClientConfig;
    // a facade server sharing AStore and AFleet when set; AScope is its scope and the fleet's
    function CompliantServer(const APolicy: ICompliancePolicy; const AStore: ISessionStore;
      const AFleet: IFleetTicketKeyManager; const AScope: TBytes): ITlsServerConfig;
    // a server on the default provider with no policy that shares the same state under AScope
    function PlainServer(const AStore: ISessionStore; const AFleet: IFleetTicketKeyManager;
      const AScope: TBytes): ITlsServerConfig;
    // drains the events of AEngine, returning how many were a received session ticket
    function CountTicketEvents(const AEngine: ITlsEngine): Int32;
    // a handshake whose post-handshake tickets have reached the client
    procedure Connect(const AClientConfig: ITlsClientConfig;
      const AServerConfig: ITlsServerConfig; out AClient, AServer: ITlsEngine);
{$IFDEF TLSLIB_MSWINDOWS}
    // a handshake of a client presenting the ClientAuthChain leaf to a facade mTLS server whose
    // client CA is AClientCa
    procedure MtlsHandshake(const AClientCa: ITrustAnchorStore;
      out AClient, AServer: ITlsEngine);
{$ENDIF TLSLIB_MSWINDOWS}
  published
    procedure TestTls13HandshakeRelaxed;
    procedure TestTls13ConnectionUsesRuleSuiteAndGroup;
    procedure TestTls13AppDataFlowsRelaxed;
    procedure TestAdmitReportOfTls13ClientHasOnlyPlatformFindings;
    procedure TestTls12EmsHandshakeRelaxed;
    procedure TestTls12ConnectionUsesEmsAndAesGcm;
    procedure TestNonEmsPeerRefused;
    procedure TestNonEmsPeerRefusedWithHandshakeFailure;
    procedure TestX25519OnlyPeerRefused;
    procedure TestChaChaOnlyPeerRefused;
    procedure TestEachRuleGroupHandshakes;
    procedure TestEachRuleGroupHandshakesInTls12;
    procedure TestCompliantServerResumesItsOwnTicket;
    procedure TestCompliantFleetOnlyServerResumesItsOwnTicket;
    procedure TestPlainServerResumesItsOwnTicket;
    procedure TestPlainServerTicketDoesNotResumeOnCompliantServer;
    procedure TestCompliantServerTicketDoesNotResumeOnPlainServer;
    procedure TestPlainTicketDoesNotResumeOnCompliantFleetOnly;
    // controls for the two tests above: one scope copied onto both servers resumes across them
    procedure TestCopiedScopeResumesAcrossPlainAndCompliantServers;
    procedure TestCopiedScopeResumesAcrossPlainAndCompliantFleetOnly;
    procedure TestFleetServersWithTheSameFleetScopeResumeAcrossEachOther;
    procedure TestFleetServerWithAnotherFleetScopeDoesNotResume;
    procedure TestTls12CompliantServerResumesItsOwnSessionThroughTheStore;
    procedure TestTls12PlainSessionDoesNotResumeOnCompliantServer;
    procedure TestTls12CopiedScopeResumesAcrossPlainAndCompliantServers;
    procedure TestTls12ServerWithStoreAndKeysIssuesATicket;
    procedure TestTls12ServerWithStoreAloneIssuesNoTicket;
{$IFDEF TLSLIB_MSWINDOWS}
    procedure TestHostRootsClientHandshakesWithPrivateChain;
    procedure TestOsRootsClientRefusesPrivateChainWithUnknownCa;
    procedure TestMtlsServerAdmitsACompliantClientChain;
    procedure TestMtlsServerAdmitsTheClientChainOfItsClientCa;
    procedure TestMtlsServerRefusesAClientChainOutsideItsClientCa;
    procedure TestMtlsServerRefusalOutsideItsClientCaCarriesUnknownCa;
{$ENDIF TLSLIB_MSWINDOWS}
  end;

implementation

const
  Host = 'localhost';

{ TTestComplianceLoopback }

function TTestComplianceLoopback.NewPolicy: ICompliancePolicy;
var
  LIdentity: TModuleIdentity;
begin
  LIdentity := Default(TModuleIdentity);
  LIdentity.OsName := 'Windows';
  LIdentity.OsVersion := '10.0.20348.1';
  Result := TCompliancePolicy.Create(TCompliancePresets.Fips140_3, Crypto, Pkix,
    TFakeModuleAttestation.Create(TModuleStatus.Validated, LIdentity) as IModuleAttestation,
    TComplianceEnforcement.Relaxed) as ICompliancePolicy;
end;

function TTestComplianceLoopback.ClientConfig(const APolicy: ICompliancePolicy)
  : ITlsClientConfig;
begin
  Result := TComplianceTls.BuildClient(APolicy, TComplianceTls.Client(APolicy,
    TServerVerification.WebPki(TTlsLibTestCertificates.EcP256RootStore)));
end;

function TTestComplianceLoopback.Tls12ClientConfig(const APolicy: ICompliancePolicy)
  : ITlsClientConfig;
var
  LBuilder: ITlsClientConfigBuilder;
begin
  LBuilder := TComplianceTls.Client(APolicy, TServerVerification.WebPki(
    TTlsLibTestCertificates.EcP256RootStore));
  LBuilder.WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls12));
  Result := TComplianceTls.BuildClient(APolicy, LBuilder);
end;

function TTestComplianceLoopback.ServerConfig(const APolicy: ICompliancePolicy)
  : ITlsServerConfig;
begin
  Result := TComplianceTls.BuildServer(APolicy, TComplianceTls.Server(APolicy,
    ServerCredential(APolicy.Crypto)));
end;

function TTestComplianceLoopback.OutsideClient(const APreferredGroups: TArray<UInt16>;
  const ASuites: TArray<UInt16>): ITlsEngine;
var
  LBuilder: ITlsClientConfigBuilder;
begin
  // a client built with no policy, offering only what the rules refuse
  LBuilder := TTlsPresets.Compatible(Crypto, Pkix).Client;
  LBuilder.WithServerVerification(TServerVerification.WebPki(
    TTlsLibTestCertificates.EcP256RootStore).Build);
  LBuilder.WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls13));
  LBuilder.WithPreferredGroups(APreferredGroups);
  LBuilder.WithCipherSuiteList(ASuites);
  Result := TTlsEngineFactory.CreateClientEngine(LBuilder.Build, Host);
end;

function TTestComplianceLoopback.NonEmsClient: ITlsEngine;
var
  LParams: TClient12HandshakeParams;
begin
  LParams := Default(TClient12HandshakeParams);
  LParams.Clock := TSystemClock.Create;
  LParams.Crypto := Crypto;
  LParams.Inspector := Pkix.Certificates;
  LParams.GroupRegistry := TNamedGroups.CreateDefaultRegistry(Crypto);
  LParams.CipherSuites := TCipherSuiteRegistry.CreateDualVersion(Crypto);
  LParams.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  LParams.OfferedSuites := TArray<UInt16>.Create(TCipherSuites12.EcdheEcdsaAes128GcmSha256);
  LParams.OfferedGroups := TArray<UInt16>.Create(TNamedGroupCatalog.Secp256r1);
  LParams.OfferedSchemes := TArray<UInt16>.Create(TSignatureSchemes.EcdsaSecp256r1Sha256);
  LParams.OfferedVersions := TArray<UInt16>.Create(TlsWireVersionTls12);
  LParams.ClientRandom := Filled($11, 32);
  LParams.LegacySessionId := nil;
  LParams.OfferExtendedMasterSecret := False;
  LParams.CertificateVerifier := TCertificateVerifier.Create(Pkix,
    TSystemClock.Create as ITlsClock, TTlsLibTestCertificates.EcP256RootStore, True)
    as IServerCertificateVerifier;
  LParams.ExpectedServerName := TServerName.DnsName(Host);
  Result := TTlsEngine.CreateConfigured(TTls12ClientStateMachine.Create(LParams)
    as IHandshakeMachine, Crypto);
end;

function TTestComplianceLoopback.ReportHasChainFinding(const AReport: IComplianceReport)
  : Boolean;
var
  LFindings: TArray<TComplianceFinding>;
  LI: Int32;
begin
  LFindings := AReport.Findings;
  Result := False;
  for LI := 0 to System.Length(LFindings) - 1 do
    if LFindings[LI].Kind = TComplianceFindingKind.ChainVerifiedOutsideModule then
      Result := True;
end;

function TTestComplianceLoopback.NoConfigurationFinding(const AReport: IComplianceReport)
  : Boolean;
var
  LFindings: TArray<TComplianceFinding>;
  LI: Int32;
begin
  LFindings := AReport.Findings;
  Result := True;
  for LI := 0 to System.Length(LFindings) - 1 do
    if LFindings[LI].Category = TComplianceFindingCategory.Configuration then
      Result := False;
end;

function TTestComplianceLoopback.SharedFleet: IFleetTicketKeyManager;
begin
  Result := TFleetTicketKeyManager.Create as IFleetTicketKeyManager;
  Result.InstallKey(Crypto.Primitives.GetRandom.GenerateBytes(16),
    TSecretBuffer.From(Crypto.Primitives.GetRandom.GenerateBytes(32)));
end;

function TTestComplianceLoopback.FleetScope: TBytes;
begin
  Result := Crypto.Primitives.GetRandom.GenerateBytes(32);
end;

function TTestComplianceLoopback.ResumingClient(const APolicy: ICompliancePolicy;
  const ACache: ISessionCache): ITlsClientConfig;
begin
  Result := TComplianceTls.BuildClient(APolicy, TComplianceTls.Client(APolicy,
    TServerVerification.WebPki(TTlsLibTestCertificates.EcP256RootStore))
    .WithSessionCache(ACache).WithResumptionScope(APolicy.SessionScope));
end;

function TTestComplianceLoopback.Tls12ResumingClient(const APolicy: ICompliancePolicy;
  const ACache: ISessionCache): ITlsClientConfig;
var
  LBuilder: ITlsClientConfigBuilder;
begin
  LBuilder := TComplianceTls.Client(APolicy, TServerVerification.WebPki(
    TTlsLibTestCertificates.EcP256RootStore));
  LBuilder.WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls12));
  Result := TComplianceTls.BuildClient(APolicy,
    LBuilder.WithSessionCache(ACache).WithResumptionScope(APolicy.SessionScope));
end;

function TTestComplianceLoopback.CompliantServer(const APolicy: ICompliancePolicy;
  const AStore: ISessionStore; const AFleet: IFleetTicketKeyManager;
  const AScope: TBytes): ITlsServerConfig;
var
  LBuilder: ITlsServerConfigBuilder;
begin
  LBuilder := TComplianceTls.Server(APolicy, ServerCredential(APolicy.Crypto))
    .WithResumptionScope(AScope).WithSessionStore(AStore);
  if AFleet <> nil then
    LBuilder.WithSessionTicketKeys(APolicy.CheckedTicketKeys(AFleet, AScope))
  else
    LBuilder.WithSessionTicketKeys(nil);
  Result := TComplianceTls.BuildServer(APolicy, LBuilder);
end;

function TTestComplianceLoopback.PlainServer(const AStore: ISessionStore;
  const AFleet: IFleetTicketKeyManager; const AScope: TBytes): ITlsServerConfig;
begin
  Result := TTlsPresets.Compatible(Crypto, Pkix).Server.WithCredential(ServerCredential)
    .WithResumption(True).WithResumptionScope(AScope).WithSessionStore(AStore)
    .WithSessionTicketKeys(AFleet).Build;
end;

procedure TTestComplianceLoopback.Connect(const AClientConfig: ITlsClientConfig;
  const AServerConfig: ITlsServerConfig; out AClient, AServer: ITlsEngine);
begin
  AClient := TTlsEngineFactory.CreateClientEngine(AClientConfig, Host);
  AServer := TTlsEngineFactory.CreateServerEngine(AServerConfig);
  RunHandshake(AClient, AServer);
  Pump(AServer, AClient);
end;

procedure TTestComplianceLoopback.TestCompliantServerResumesItsOwnTicket;
var
  LPolicy: ICompliancePolicy;
  LStore: ISessionStore;
  LFleet: IFleetTicketKeyManager;
  LClientConfig: ITlsClientConfig;
  LServerConfig: ITlsServerConfig;
  LClient, LServer: ITlsEngine;
begin
  LPolicy := NewPolicy;
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom) as ISessionStore;
  LFleet := SharedFleet;
  LClientConfig := ResumingClient(LPolicy, TInMemorySessionCache.Create as ISessionCache);
  LServerConfig := CompliantServer(LPolicy, LStore, LFleet, LPolicy.SessionScope);
  Connect(LClientConfig, LServerConfig, LClient, LServer);
  Connect(LClientConfig, LServerConfig, LClient, LServer);
  CheckFalse(LServer.IsTerminal, 'the second handshake did not fail');
  CheckTrue(LServer.ConnectionInfo.Resumed, 'the server resumed its own ticket');
end;

procedure TTestComplianceLoopback.TestCompliantFleetOnlyServerResumesItsOwnTicket;
var
  LPolicy: ICompliancePolicy;
  LClientConfig: ITlsClientConfig;
  LServerConfig: ITlsServerConfig;
  LClient, LServer: ITlsEngine;
begin
  LPolicy := NewPolicy;
  LClientConfig := ResumingClient(LPolicy, TInMemorySessionCache.Create as ISessionCache);
  LServerConfig := CompliantServer(LPolicy, nil, SharedFleet, FleetScope);
  Connect(LClientConfig, LServerConfig, LClient, LServer);
  Connect(LClientConfig, LServerConfig, LClient, LServer);
  CheckFalse(LServer.IsTerminal, 'the second handshake did not fail');
  CheckTrue(LServer.ConnectionInfo.Resumed, 'the ticket opened under the shared key');
end;

procedure TTestComplianceLoopback.TestPlainServerResumesItsOwnTicket;
var
  LPolicy: ICompliancePolicy;
  LStore: ISessionStore;
  LFleet: IFleetTicketKeyManager;
  LClientConfig: ITlsClientConfig;
  LServerConfig: ITlsServerConfig;
  LClient, LServer: ITlsEngine;
begin
  LPolicy := NewPolicy;
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom) as ISessionStore;
  LFleet := SharedFleet;
  LClientConfig := ResumingClient(LPolicy, TInMemorySessionCache.Create as ISessionCache);
  LServerConfig := PlainServer(LStore, LFleet, nil);
  Connect(LClientConfig, LServerConfig, LClient, LServer);
  Connect(LClientConfig, LServerConfig, LClient, LServer);
  CheckFalse(LServer.IsTerminal, 'the second handshake did not fail');
  CheckTrue(LServer.ConnectionInfo.Resumed, 'the setup resumes when the scopes agree');
end;

procedure TTestComplianceLoopback.TestPlainServerTicketDoesNotResumeOnCompliantServer;
var
  LPolicy: ICompliancePolicy;
  LStore: ISessionStore;
  LFleet: IFleetTicketKeyManager;
  LClientConfig: ITlsClientConfig;
  LClient, LServer: ITlsEngine;
begin
  LPolicy := NewPolicy;
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom) as ISessionStore;
  LFleet := SharedFleet;
  LClientConfig := ResumingClient(LPolicy, TInMemorySessionCache.Create as ISessionCache);
  Connect(LClientConfig, PlainServer(LStore, LFleet, nil), LClient, LServer);
  Connect(LClientConfig, CompliantServer(LPolicy, LStore, LFleet, LPolicy.SessionScope),
    LClient, LServer);
  CheckFalse(LServer.IsTerminal, 'the server fell back to a full handshake');
  CheckFalse(LClient.IsHandshaking, 'the full handshake completed');
  CheckFalse(LServer.ConnectionInfo.Resumed, 'the server did not resume the foreign ticket');
  CheckFalse(LClient.ConnectionInfo.Resumed, 'the client saw a full handshake');
end;

procedure TTestComplianceLoopback.TestCompliantServerTicketDoesNotResumeOnPlainServer;
var
  LPolicy: ICompliancePolicy;
  LStore: ISessionStore;
  LFleet: IFleetTicketKeyManager;
  LClientConfig: ITlsClientConfig;
  LClient, LServer: ITlsEngine;
begin
  LPolicy := NewPolicy;
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom) as ISessionStore;
  LFleet := SharedFleet;
  LClientConfig := ResumingClient(LPolicy, TInMemorySessionCache.Create as ISessionCache);
  Connect(LClientConfig, CompliantServer(LPolicy, LStore, LFleet, LPolicy.SessionScope),
    LClient, LServer);
  Connect(LClientConfig, PlainServer(LStore, LFleet, nil), LClient, LServer);
  CheckFalse(LServer.IsTerminal, 'the server fell back to a full handshake');
  CheckFalse(LClient.IsHandshaking, 'the full handshake completed');
  CheckFalse(LServer.ConnectionInfo.Resumed, 'the server did not resume the compliant ticket');
  CheckFalse(LClient.ConnectionInfo.Resumed, 'the client saw a full handshake');
end;

procedure TTestComplianceLoopback.TestPlainTicketDoesNotResumeOnCompliantFleetOnly;
var
  LPolicy: ICompliancePolicy;
  LFleet: IFleetTicketKeyManager;
  LClientConfig: ITlsClientConfig;
  LClient, LServer: ITlsEngine;
begin
  LPolicy := NewPolicy;
  LFleet := SharedFleet;
  LClientConfig := ResumingClient(LPolicy, TInMemorySessionCache.Create as ISessionCache);
  Connect(LClientConfig, PlainServer(nil, LFleet, nil), LClient, LServer);
  Connect(LClientConfig, CompliantServer(LPolicy, nil, LFleet, FleetScope), LClient, LServer);
  CheckFalse(LServer.IsTerminal, 'the server fell back to a full handshake');
  CheckFalse(LClient.IsHandshaking, 'the full handshake completed');
  CheckFalse(LServer.ConnectionInfo.Resumed, 'a ticket sealed under the shared key alone');
  CheckFalse(LClient.ConnectionInfo.Resumed, 'the client saw a full handshake');
end;

procedure TTestComplianceLoopback.TestCopiedScopeResumesAcrossPlainAndCompliantServers;
var
  LPolicy: ICompliancePolicy;
  LStore: ISessionStore;
  LFleet: IFleetTicketKeyManager;
  LScope: TBytes;
  LClientConfig: ITlsClientConfig;
  LClient, LServer: ITlsEngine;
begin
  LPolicy := NewPolicy;
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom) as ISessionStore;
  LFleet := SharedFleet;
  LScope := LPolicy.SessionScope;
  LClientConfig := ResumingClient(LPolicy, TInMemorySessionCache.Create as ISessionCache);
  Connect(LClientConfig, PlainServer(LStore, LFleet, LScope), LClient, LServer);
  Connect(LClientConfig, CompliantServer(LPolicy, LStore, LFleet, LScope), LClient, LServer);
  CheckFalse(LServer.IsTerminal, 'the second handshake did not fail');
  CheckTrue(LServer.ConnectionInfo.Resumed,
    'control: with one scope on both servers the store is shared, which the scope exists to stop');
  CheckTrue(LClient.ConnectionInfo.Resumed, 'and the client saw the resumption');
end;

procedure TTestComplianceLoopback.TestCopiedScopeResumesAcrossPlainAndCompliantFleetOnly;
var
  LPolicy: ICompliancePolicy;
  LFleet: IFleetTicketKeyManager;
  LScope: TBytes;
  LClientConfig: ITlsClientConfig;
  LClient, LServer: ITlsEngine;
begin
  LPolicy := NewPolicy;
  LFleet := SharedFleet;
  LScope := FleetScope;
  LClientConfig := ResumingClient(LPolicy, TInMemorySessionCache.Create as ISessionCache);
  Connect(LClientConfig, PlainServer(nil, LFleet, LScope), LClient, LServer);
  Connect(LClientConfig, CompliantServer(LPolicy, nil, LFleet, LScope), LClient, LServer);
  CheckFalse(LServer.IsTerminal, 'the second handshake did not fail');
  CheckTrue(LServer.ConnectionInfo.Resumed,
    'control: with one scope on both servers the shared key opens the ticket');
  CheckTrue(LClient.ConnectionInfo.Resumed, 'and the client saw the resumption');
end;

procedure TTestComplianceLoopback.TestFleetServersWithTheSameFleetScopeResumeAcrossEachOther;
var
  LPolicy: ICompliancePolicy;
  LFleet: IFleetTicketKeyManager;
  LScope: TBytes;
  LClientConfig: ITlsClientConfig;
  LClient, LServer: ITlsEngine;
begin
  LPolicy := NewPolicy;
  LFleet := SharedFleet;
  LScope := FleetScope;
  LClientConfig := ResumingClient(LPolicy, TInMemorySessionCache.Create as ISessionCache);
  Connect(LClientConfig, CompliantServer(LPolicy, nil, LFleet, LScope), LClient, LServer);
  Connect(LClientConfig, CompliantServer(LPolicy, nil, LFleet, LScope), LClient, LServer);
  CheckFalse(LServer.IsTerminal, 'the second handshake did not fail');
  CheckTrue(LServer.ConnectionInfo.Resumed, 'the second server opened the first one''s ticket');
  CheckTrue(LClient.ConnectionInfo.Resumed, 'and the client saw the resumption');
end;

procedure TTestComplianceLoopback.TestFleetServerWithAnotherFleetScopeDoesNotResume;
var
  LPolicy: ICompliancePolicy;
  LFleet: IFleetTicketKeyManager;
  LClientConfig: ITlsClientConfig;
  LClient, LServer: ITlsEngine;
begin
  LPolicy := NewPolicy;
  LFleet := SharedFleet;
  LClientConfig := ResumingClient(LPolicy, TInMemorySessionCache.Create as ISessionCache);
  Connect(LClientConfig, CompliantServer(LPolicy, nil, LFleet, FleetScope), LClient, LServer);
  Connect(LClientConfig, CompliantServer(LPolicy, nil, LFleet, FleetScope), LClient, LServer);
  CheckFalse(LServer.IsTerminal, 'the server fell back to a full handshake');
  CheckFalse(LClient.IsHandshaking, 'the full handshake completed');
  CheckFalse(LServer.ConnectionInfo.Resumed, 'the same keys under another scope do not resume');
  CheckFalse(LClient.ConnectionInfo.Resumed, 'the client saw a full handshake');
end;

procedure TTestComplianceLoopback.TestTls12CompliantServerResumesItsOwnSessionThroughTheStore;
var
  LPolicy: ICompliancePolicy;
  LConfig: ITlsServerConfig;
  LClientConfig: ITlsClientConfig;
  LClient, LServer: ITlsEngine;
begin
  LPolicy := NewPolicy;
  LConfig := CompliantServer(LPolicy,
    TInMemorySessionStore.Create(Crypto.Primitives.GetRandom) as ISessionStore, nil,
    LPolicy.SessionScope);
  LClientConfig := Tls12ResumingClient(LPolicy, TInMemorySessionCache.Create as ISessionCache);
  Connect(LClientConfig, LConfig, LClient, LServer);
  Connect(LClientConfig, LConfig, LClient, LServer);
  CheckEquals(TlsWireVersionTls12, LClient.ConnectionInfo.NegotiatedVersion.WireValue, 'TLS 1.2');
  CheckFalse(LServer.IsTerminal, 'the second handshake did not fail');
  CheckTrue(LServer.ConnectionInfo.Resumed, 'the server resumed its own session');
  CheckTrue(LClient.ConnectionInfo.Resumed, 'and the client saw the resumption');
end;

procedure TTestComplianceLoopback.TestTls12CopiedScopeResumesAcrossPlainAndCompliantServers;
var
  LPolicy: ICompliancePolicy;
  LStore: ISessionStore;
  LScope: TBytes;
  LClientConfig: ITlsClientConfig;
  LClient, LServer: ITlsEngine;
begin
  LPolicy := NewPolicy;
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom) as ISessionStore;
  LScope := LPolicy.SessionScope;
  LClientConfig := Tls12ResumingClient(LPolicy, TInMemorySessionCache.Create as ISessionCache);
  Connect(LClientConfig, PlainServer(LStore, nil, LScope), LClient, LServer);
  Connect(LClientConfig, CompliantServer(LPolicy, LStore, nil, LScope), LClient, LServer);
  CheckEquals(TlsWireVersionTls12, LClient.ConnectionInfo.NegotiatedVersion.WireValue, 'TLS 1.2');
  CheckFalse(LServer.IsTerminal, 'the second handshake did not fail');
  CheckTrue(LServer.ConnectionInfo.Resumed,
    'control: with one scope on both servers the store is shared, which the scope exists to stop');
  CheckTrue(LClient.ConnectionInfo.Resumed, 'and the client saw the resumption');
end;

function TTestComplianceLoopback.CountTicketEvents(const AEngine: ITlsEngine): Int32;
var
  LEvent: ITlsEvent;
begin
  Result := 0;
  while AEngine.NextEvent(LEvent) do
    if LEvent.Kind = TTlsEventKind.SessionTicketReceived then
      System.Inc(Result);
end;

procedure TTestComplianceLoopback.TestTls12ServerWithStoreAndKeysIssuesATicket;
var
  LPolicy: ICompliancePolicy;
  LClient, LServer: ITlsEngine;
begin
  LPolicy := NewPolicy;
  Connect(Tls12ResumingClient(LPolicy, TInMemorySessionCache.Create as ISessionCache),
    CompliantServer(LPolicy, TInMemorySessionStore.Create(Crypto.Primitives.GetRandom)
    as ISessionStore, SharedFleet, LPolicy.SessionScope), LClient, LServer);
  CheckEquals(TlsWireVersionTls12, LClient.ConnectionInfo.NegotiatedVersion.WireValue, 'TLS 1.2');
  CheckEquals(1, CountTicketEvents(LClient), 'the TLS 1.2 server seals a ticket with its keys');
end;

procedure TTestComplianceLoopback.TestTls12ServerWithStoreAloneIssuesNoTicket;
var
  LPolicy: ICompliancePolicy;
  LClient, LServer: ITlsEngine;
begin
  LPolicy := NewPolicy;
  Connect(Tls12ResumingClient(LPolicy, TInMemorySessionCache.Create as ISessionCache),
    CompliantServer(LPolicy, TInMemorySessionStore.Create(Crypto.Primitives.GetRandom)
    as ISessionStore, nil, LPolicy.SessionScope), LClient, LServer);
  CheckEquals(0, CountTicketEvents(LClient),
    'control: without keys the TLS 1.2 server resumes by session id and seals nothing');
end;

procedure TTestComplianceLoopback.TestTls12PlainSessionDoesNotResumeOnCompliantServer;
var
  LPolicy: ICompliancePolicy;
  LStore: ISessionStore;
  LClientConfig: ITlsClientConfig;
  LClient, LServer: ITlsEngine;
begin
  LPolicy := NewPolicy;
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom) as ISessionStore;
  LClientConfig := Tls12ResumingClient(LPolicy, TInMemorySessionCache.Create as ISessionCache);
  Connect(LClientConfig, PlainServer(LStore, nil, nil), LClient, LServer);
  Connect(LClientConfig, CompliantServer(LPolicy, LStore, nil, LPolicy.SessionScope), LClient,
    LServer);
  CheckEquals(TlsWireVersionTls12, LClient.ConnectionInfo.NegotiatedVersion.WireValue, 'TLS 1.2');
  CheckFalse(LServer.IsTerminal, 'the server fell back to a full handshake');
  CheckFalse(LClient.IsHandshaking, 'the full handshake completed');
  CheckFalse(LServer.ConnectionInfo.Resumed, 'the server did not resume the foreign session');
  CheckFalse(LClient.ConnectionInfo.Resumed, 'the client saw a full handshake');
end;

procedure TTestComplianceLoopback.TestTls13HandshakeRelaxed;
var
  LPolicy: ICompliancePolicy;
  LClient, LServer: ITlsEngine;
begin
  LPolicy := NewPolicy;
  LClient := TTlsEngineFactory.CreateClientEngine(ClientConfig(LPolicy), Host);
  LServer := TTlsEngineFactory.CreateServerEngine(ServerConfig(LPolicy));
  RunHandshake(LClient, LServer);
  CheckFalse(LClient.IsHandshaking, 'the client finished');
  CheckFalse(LServer.IsHandshaking, 'the server finished');
  CheckFalse(LClient.IsTerminal, 'the client did not fail');
  CheckFalse(LServer.IsTerminal, 'the server did not fail');
  CheckEquals(TlsWireVersionTls13, LClient.ConnectionInfo.NegotiatedVersion.WireValue,
    'TLS 1.3');
  CheckAppDataFlows(LClient, LServer);
end;

procedure TTestComplianceLoopback.TestTls13ConnectionUsesRuleSuiteAndGroup;
var
  LPolicy: ICompliancePolicy;
  LClient, LServer: ITlsEngine;
begin
  LPolicy := NewPolicy;
  LClient := TTlsEngineFactory.CreateClientEngine(ClientConfig(LPolicy), Host);
  LServer := TTlsEngineFactory.CreateServerEngine(ServerConfig(LPolicy));
  RunHandshake(LClient, LServer);
  CheckTrue(TArrayUtilities.Contains<UInt16>(LPolicy.Rules.CipherSuites,
    LClient.ConnectionInfo.CipherSuite), 'the suite is one of the rules');
  CheckEquals(TNamedGroupCatalog.Secp256r1, LClient.ConnectionInfo.NamedGroup, 'P-256');
  CheckEquals(LClient.ConnectionInfo.CipherSuite, LServer.ConnectionInfo.CipherSuite,
    'both ends agree');
end;

procedure TTestComplianceLoopback.TestTls13AppDataFlowsRelaxed;
var
  LPolicy: ICompliancePolicy;
  LClient, LServer: ITlsEngine;
begin
  LPolicy := NewPolicy;
  LClient := TTlsEngineFactory.CreateClientEngine(ClientConfig(LPolicy), Host);
  LServer := TTlsEngineFactory.CreateServerEngine(ServerConfig(LPolicy));
  RunHandshake(LClient, LServer);
  CheckAppDataFlows(LClient, LServer);
end;

procedure TTestComplianceLoopback.TestAdmitReportOfTls13ClientHasOnlyPlatformFindings;
var
  LPolicy: ICompliancePolicy;
  LReport: IComplianceReport;
begin
  LPolicy := NewPolicy;
  LReport := LPolicy.Admit(ClientConfig(LPolicy));
  CheckEquals(Ord(TComplianceVerdict.NotCompliant), Ord(LReport.Verdict),
    'relaxed is never silent');
  CheckTrue(ReportHasChainFinding(LReport), 'the portable chain check is reported');
  CheckTrue(NoConfigurationFinding(LReport), 'and nothing else is configuration');
end;

procedure TTestComplianceLoopback.TestTls12EmsHandshakeRelaxed;
var
  LPolicy: ICompliancePolicy;
  LClient, LServer: ITlsEngine;
begin
  LPolicy := NewPolicy;
  LClient := TTlsEngineFactory.CreateClientEngine(Tls12ClientConfig(LPolicy), Host);
  LServer := TTlsEngineFactory.CreateServerEngine(ServerConfig(LPolicy));
  RunHandshake(LClient, LServer);
  CheckFalse(LClient.IsHandshaking, 'the client finished');
  CheckFalse(LClient.IsTerminal, 'the client did not fail');
  CheckFalse(LServer.IsTerminal, 'the server did not fail');
  CheckEquals(TlsWireVersionTls12, LClient.ConnectionInfo.NegotiatedVersion.WireValue,
    'TLS 1.2');
  CheckAppDataFlows(LClient, LServer);
end;

procedure TTestComplianceLoopback.TestTls12ConnectionUsesEmsAndAesGcm;
var
  LPolicy: ICompliancePolicy;
  LClient, LServer: ITlsEngine;
begin
  LPolicy := NewPolicy;
  LClient := TTlsEngineFactory.CreateClientEngine(Tls12ClientConfig(LPolicy), Host);
  LServer := TTlsEngineFactory.CreateServerEngine(ServerConfig(LPolicy));
  RunHandshake(LClient, LServer);
  CheckTrue(LClient.ConnectionInfo.ExtendedMasterSecret, 'extended master secret (RFC 7627)');
  CheckTrue(TArrayUtilities.Contains<UInt16>(
    TArray<UInt16>.Create(TCipherSuites12.EcdheEcdsaAes128GcmSha256,
    TCipherSuites12.EcdheEcdsaAes256GcmSha384), LClient.ConnectionInfo.CipherSuite),
    'ECDHE-ECDSA with AES-GCM');
end;

procedure TTestComplianceLoopback.TestNonEmsPeerRefused;
var
  LPolicy: ICompliancePolicy;
  LClient, LServer: ITlsEngine;
begin
  LPolicy := NewPolicy;
  LClient := NonEmsClient;
  LServer := TTlsEngineFactory.CreateServerEngine(ServerConfig(LPolicy));
  RunHandshake(LClient, LServer);
  CheckTrue(LServer.IsTerminal, 'the server ended the handshake');
end;

procedure TTestComplianceLoopback.TestNonEmsPeerRefusedWithHandshakeFailure;
var
  LPolicy: ICompliancePolicy;
  LClient, LServer: ITlsEngine;
begin
  LPolicy := NewPolicy;
  LClient := NonEmsClient;
  LServer := TTlsEngineFactory.CreateServerEngine(ServerConfig(LPolicy));
  RunHandshake(LClient, LServer);
  CheckEquals(Ord(TTlsAlertDescription.HandshakeFailure),
    Ord(LServer.LastError.Alert.Description), 'a fatal handshake_failure (RFC 7627 5.2)');
end;

procedure TTestComplianceLoopback.TestX25519OnlyPeerRefused;
var
  LPolicy: ICompliancePolicy;
  LClient, LServer: ITlsEngine;
begin
  LPolicy := NewPolicy;
  LClient := OutsideClient(TArray<UInt16>.Create(TNamedGroupCatalog.X25519),
    TArray<UInt16>.Create(TCipherSuites13.Aes128GcmSha256));
  LServer := TTlsEngineFactory.CreateServerEngine(ServerConfig(LPolicy));
  RunHandshake(LClient, LServer);
  CheckTrue(LServer.IsTerminal, 'no shared group, so no handshake');
  CheckEquals(Ord(TTlsAlertDescription.HandshakeFailure),
    Ord(LServer.LastError.Alert.Description), 'a fatal handshake_failure');
end;

procedure TTestComplianceLoopback.TestChaChaOnlyPeerRefused;
var
  LPolicy: ICompliancePolicy;
  LClient, LServer: ITlsEngine;
begin
  LPolicy := NewPolicy;
  LClient := OutsideClient(TArray<UInt16>.Create(TNamedGroupCatalog.Secp256r1),
    TArray<UInt16>.Create(TCipherSuites13.ChaCha20Poly1305Sha256));
  LServer := TTlsEngineFactory.CreateServerEngine(ServerConfig(LPolicy));
  RunHandshake(LClient, LServer);
  CheckTrue(LServer.IsTerminal, 'no shared suite, so no handshake');
  CheckEquals(Ord(TTlsAlertDescription.HandshakeFailure),
    Ord(LServer.LastError.Alert.Description), 'a fatal handshake_failure');
end;

procedure TTestComplianceLoopback.TestEachRuleGroupHandshakes;
var
  LPolicy: ICompliancePolicy;
  LGroups: TArray<UInt16>;
  LClientBuilder: ITlsClientConfigBuilder;
  LServerBuilder: ITlsServerConfigBuilder;
  LClient, LServer: ITlsEngine;
  LI: Int32;
begin
  LPolicy := NewPolicy;
  LGroups := LPolicy.Rules.NamedGroups;
  CheckTrue(System.Length(LGroups) > 0, 'the rules list groups');
  for LI := 0 to System.Length(LGroups) - 1 do
  begin
    LClientBuilder := TComplianceTls.Client(LPolicy, TServerVerification.WebPki(
      TTlsLibTestCertificates.EcP256RootStore));
    LClientBuilder.WithPreferredGroups(TArray<UInt16>.Create(LGroups[LI]));
    LServerBuilder := TComplianceTls.Server(LPolicy, ServerCredential(LPolicy.Crypto));
    LServerBuilder.WithPreferredGroups(TArray<UInt16>.Create(LGroups[LI]));
    LClient := TTlsEngineFactory.CreateClientEngine(TComplianceTls.BuildClient(LPolicy,
      LClientBuilder), Host);
    LServer := TTlsEngineFactory.CreateServerEngine(TComplianceTls.BuildServer(LPolicy,
      LServerBuilder));
    RunHandshake(LClient, LServer);
    CheckFalse(LClient.IsTerminal, TNamedGroupCatalog.Name(LGroups[LI]) + ' client');
    CheckFalse(LServer.IsTerminal, TNamedGroupCatalog.Name(LGroups[LI]) + ' server');
    CheckFalse(LClient.IsHandshaking, TNamedGroupCatalog.Name(LGroups[LI]) + ' client finished');
    CheckFalse(LServer.IsHandshaking, TNamedGroupCatalog.Name(LGroups[LI]) + ' server finished');
    CheckEquals(LGroups[LI], LClient.ConnectionInfo.NamedGroup,
      TNamedGroupCatalog.Name(LGroups[LI]));
    CheckAppDataFlows(LClient, LServer);
  end;
end;

procedure TTestComplianceLoopback.TestEachRuleGroupHandshakesInTls12;
var
  LPolicy: ICompliancePolicy;
  LGroups: TArray<UInt16>;
  LClientBuilder: ITlsClientConfigBuilder;
  LServerBuilder: ITlsServerConfigBuilder;
  LClient, LServer: ITlsEngine;
  LI: Int32;
begin
  LPolicy := NewPolicy;
  LGroups := LPolicy.Rules.NamedGroups;
  CheckTrue(System.Length(LGroups) > 0, 'the rules list groups');
  for LI := 0 to System.Length(LGroups) - 1 do
  begin
    LClientBuilder := TComplianceTls.Client(LPolicy, TServerVerification.WebPki(
      TTlsLibTestCertificates.EcP256RootStore));
    LClientBuilder.WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls12));
    // a TLS 1.2 ECDSA certificate must be on a curve the client offers, and the credential is P-256
    if LGroups[LI] = TNamedGroupCatalog.Secp256r1 then
      LClientBuilder.WithPreferredGroups(TArray<UInt16>.Create(TNamedGroupCatalog.Secp256r1))
    else
      LClientBuilder.WithPreferredGroups(TArray<UInt16>.Create(TNamedGroupCatalog.Secp256r1,
        LGroups[LI]));
    LServerBuilder := TComplianceTls.Server(LPolicy, ServerCredential(LPolicy.Crypto));
    LServerBuilder.WithPreferredGroups(TArray<UInt16>.Create(LGroups[LI]));
    LClient := TTlsEngineFactory.CreateClientEngine(TComplianceTls.BuildClient(LPolicy,
      LClientBuilder), Host);
    LServer := TTlsEngineFactory.CreateServerEngine(TComplianceTls.BuildServer(LPolicy,
      LServerBuilder));
    RunHandshake(LClient, LServer);
    CheckFalse(LClient.IsTerminal, TNamedGroupCatalog.Name(LGroups[LI]) + ' client');
    CheckFalse(LServer.IsTerminal, TNamedGroupCatalog.Name(LGroups[LI]) + ' server');
    CheckFalse(LClient.IsHandshaking, TNamedGroupCatalog.Name(LGroups[LI]) + ' client finished');
    CheckFalse(LServer.IsHandshaking, TNamedGroupCatalog.Name(LGroups[LI]) + ' server finished');
    CheckEquals(TlsWireVersionTls12, LClient.ConnectionInfo.NegotiatedVersion.WireValue,
      TNamedGroupCatalog.Name(LGroups[LI]) + ' version');
    CheckEquals(LGroups[LI], LClient.ConnectionInfo.NamedGroup,
      TNamedGroupCatalog.Name(LGroups[LI]) + ' group');
    CheckAppDataFlows(LClient, LServer);
  end;
end;

{$IFDEF TLSLIB_MSWINDOWS}

procedure TTestComplianceLoopback.TestHostRootsClientHandshakesWithPrivateChain;
var
  LPolicy: ICompliancePolicy;
  LClient, LServer: ITlsEngine;
begin
  LPolicy := NewPolicy;
  LClient := TTlsEngineFactory.CreateClientEngine(TComplianceTls.BuildClient(LPolicy,
    TComplianceTls.Client(LPolicy, TSystemTrustRoots.HostRoots(
    TTlsLibTestCertificates.EcP256RootStore))), Host);
  LServer := TTlsEngineFactory.CreateServerEngine(ServerConfig(LPolicy));
  RunHandshake(LClient, LServer);
  CheckFalse(LClient.IsHandshaking, 'the OS verifier trusted the host root alone');
  CheckFalse(LClient.IsTerminal, 'the client did not fail');
  CheckFalse(LServer.IsTerminal, 'the server did not fail');
  CheckEquals(TlsWireVersionTls13, LClient.ConnectionInfo.NegotiatedVersion.WireValue, 'TLS 1.3');
  CheckAppDataFlows(LClient, LServer);
end;

procedure TTestComplianceLoopback.TestOsRootsClientRefusesPrivateChainWithUnknownCa;
var
  LPolicy: ICompliancePolicy;
  LClient, LServer: ITlsEngine;
begin
  LPolicy := NewPolicy;
  LClient := TTlsEngineFactory.CreateClientEngine(TComplianceTls.BuildClient(LPolicy,
    TComplianceTls.Client(LPolicy, TSystemTrustRoots.OsRoots)), Host);
  LServer := TTlsEngineFactory.CreateServerEngine(ServerConfig(LPolicy));
  RunHandshake(LClient, LServer);
  CheckTrue(LClient.IsTerminal, 'the OS roots do not vouch for the private root');
  CheckEquals(Ord(TTlsAlertDescription.UnknownCa), Ord(LClient.LastError.Alert.Description),
    'unknown_ca');
end;

procedure TTestComplianceLoopback.TestMtlsServerAdmitsACompliantClientChain;
var
  LPolicy: ICompliancePolicy;
  LClientCa: TBytes;
  LCredential: TTlsCredential;
  LServerConfig: ITlsServerConfig;
  LClient, LServer: ITlsEngine;
begin
  LPolicy := NewPolicy;
  LCredential := ClientAuthCredential(LClientCa);
  LServerConfig := TComplianceTls.BuildServer(LPolicy, TComplianceTls.WithPeerAuth(LPolicy,
    TComplianceTls.Server(LPolicy, ServerCredential(LPolicy.Crypto)), TClientAuthMode.Required,
    TTrustAnchorStore.Create(TArray<TBytes>.Create(LClientCa)) as ITrustAnchorStore));
  CheckTrue(LServerConfig.ClientVerifierSource is TOSVerifierSource,
    'the OS verifier checks the client chain');
  LServer := TTlsEngineFactory.CreateServerEngine(LServerConfig);
  LClient := TTlsEngineFactory.CreateClientEngine(TComplianceTls.BuildClient(LPolicy,
    TComplianceTls.Client(LPolicy, TSystemTrustRoots.HostRoots(
    TTlsLibTestCertificates.EcP256RootStore)).WithCredential(LCredential)), Host);
  RunHandshake(LClient, LServer);
  CheckFalse(LServer.IsTerminal, 'the server did not fail');
  CheckFalse(LServer.IsHandshaking, 'the server finished');
  CheckFalse(LClient.IsTerminal, 'the client did not fail');
  CheckAppDataFlows(LClient, LServer);
end;

procedure TTestComplianceLoopback.MtlsHandshake(const AClientCa: ITrustAnchorStore;
  out AClient, AServer: ITlsEngine);
var
  LPolicy: ICompliancePolicy;
  LClientCa: TBytes;
  LCredential: TTlsCredential;
begin
  LPolicy := NewPolicy;
  LCredential := ClientAuthCredential(LClientCa);
  AServer := TTlsEngineFactory.CreateServerEngine(TComplianceTls.BuildServer(LPolicy,
    TComplianceTls.WithPeerAuth(LPolicy, TComplianceTls.Server(LPolicy,
    ServerCredential(LPolicy.Crypto)), TClientAuthMode.Required, AClientCa)));
  AClient := TTlsEngineFactory.CreateClientEngine(TComplianceTls.BuildClient(LPolicy,
    TComplianceTls.Client(LPolicy, TSystemTrustRoots.HostRoots(
    TTlsLibTestCertificates.EcP256RootStore)).WithCredential(LCredential)), Host);
  RunHandshake(AClient, AServer);
end;

procedure TTestComplianceLoopback.TestMtlsServerAdmitsTheClientChainOfItsClientCa;
var
  LClientCa: TBytes;
  LClient, LServer: ITlsEngine;
begin
  ClientAuthCredential(LClientCa);
  MtlsHandshake(TTrustAnchorStore.Create(TArray<TBytes>.Create(LClientCa)) as ITrustAnchorStore,
    LClient, LServer);
  CheckFalse(LServer.IsTerminal, 'control: the server did not fail');
  CheckFalse(LServer.IsHandshaking, 'control: the server finished');
end;

procedure TTestComplianceLoopback.TestMtlsServerRefusesAClientChainOutsideItsClientCa;
var
  LClient, LServer: ITlsEngine;
begin
  MtlsHandshake(TTlsLibTestCertificates.EcP256RootStore, LClient, LServer);
  CheckTrue(LServer.IsTerminal, 'the client chain does not reach the client CA');
end;

procedure TTestComplianceLoopback.TestMtlsServerRefusalOutsideItsClientCaCarriesUnknownCa;
var
  LClient, LServer: ITlsEngine;
begin
  MtlsHandshake(TTlsLibTestCertificates.EcP256RootStore, LClient, LServer);
  CheckEquals(Ord(TTlsAlertDescription.UnknownCa), Ord(LServer.LastError.Alert.Description),
    'unknown_ca');
end;

{$ENDIF TLSLIB_MSWINDOWS}

initialization

{$IFDEF FPC}
  RegisterTest(TTestComplianceLoopback);
{$ELSE}
  RegisterTest(TTestComplianceLoopback.Suite);
{$ENDIF FPC}

end.
