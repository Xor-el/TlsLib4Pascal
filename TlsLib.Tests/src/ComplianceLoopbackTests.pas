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
  published
    procedure TestTls13HandshakeRelaxed;
    procedure TestTls13ConnectionUsesRuleSuiteAndGroup;
    procedure TestTls13AppDataFlowsRelaxed;
    procedure TestAdmitReportOfTls13ClientHasOnlyPlatformFindings;
    procedure TestAdmitReportOfServerHasNoConfigurationFinding;
    procedure TestTls12EmsHandshakeRelaxed;
    procedure TestTls12ConnectionUsesEmsAndAesGcm;
    procedure TestNonEmsPeerRefused;
    procedure TestNonEmsPeerRefusedWithHandshakeFailure;
    procedure TestX25519OnlyPeerRefused;
    procedure TestChaChaOnlyPeerRefused;
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
  CheckEquals(TlsWireVersionTls13, LClient.ConnectionInfo.NegotiatedVersion.WireValue,
    'TLS 1.3');
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

procedure TTestComplianceLoopback.TestAdmitReportOfServerHasNoConfigurationFinding;
var
  LPolicy: ICompliancePolicy;
  LReport: IComplianceReport;
begin
  LPolicy := NewPolicy;
  LReport := LPolicy.Admit(ServerConfig(LPolicy));
  CheckTrue(NoConfigurationFinding(LReport), 'no configuration finding');
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
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestComplianceLoopback);
{$ELSE}
  RegisterTest(TTestComplianceLoopback.Suite);
{$ENDIF FPC}

end.
