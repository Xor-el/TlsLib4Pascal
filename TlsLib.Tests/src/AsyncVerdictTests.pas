{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit AsyncVerdictTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  TlpTlsAlert,
  TlpTlsLibExceptions,
  TlpITlsTransport,
  TlpTlsStreamPump,
  MockTransport,
  TlpTlsVersion,
  TlpTlsCredential,
  TlpICryptoProvider,
  TlpITlsConfig,
  TlpITlsConfigBuilder,
  TlpCertificateVerifierSource,
  TlpTlsPresets,
  TlpTrustPolicy,
  TlpTlsConnectionInfo,
  TlpITlsEngine,
  TlpTlsEngineFactory,
  TlpIClock,
  TlpClock,
  TlpIHttpFetcher,
  TlpLiveRevocation,
  TlpDefaultCryptoProvider,
  MockCryptoProvider,
  MockPkixProvider,
  TlpIPkixProvider,
  MockHttpFetcher,
  MockVerifyHooks,
  TlsLibTestCertificates,
  TlsLibTestBase;

type
  /// <summary>
  /// The async peer-certificate verdict (the deferred-verdict seam): the client parks after
  /// its built-in trust pipeline accepts the server chain, and only an explicit positive
  /// verdict resumes it. These drive two engines directly (no socket, no thread) so the park
  /// point can be inspected, and prove the fail-closed and augment-only invariants: no
  /// verdict never completes, a rejection aborts with bad_certificate, and an accept can
  /// never resurrect a chain the pipeline already rejected.
  /// </summary>
  TTestAsyncVerdict = class(TTlsLibAlgorithmTestCase)
  strict private
  const
    MaxPumpRounds = Int32(64);
    function ClientConfig(AAsync: Boolean; ADeadlineMs: Cardinal): ITlsClientConfig;
    function ServerConfig: ITlsServerConfig;
    function MtlsClientConfig: ITlsClientConfig;
    function MtlsServerConfig(AAsync: Boolean): ITlsServerConfig;
    // a mutual-TLS server that pins the accepted client chain, built through the real
    // builder + CreateServerEngine so the test exercises the factory composition, not a hand-wrapped
    // decorator
    function MtlsServerConfigPinned(const APins: TArray<TBytes>): ITlsServerConfig;
    // a server presenting the OCSP-stapling cert set with AStaple sealed on its credential, and a
    // client that requests a staple and defers revocation (live, or host-decision), so the park is
    // exercised end-to-end. The client's host check is disabled to isolate the revocation behaviour.
    function StapledServer(const AStaple: TBytes): ITlsEngine;
    function StaplingRevocationClient(AHostDecision: Boolean;
      out AServer: ITlsEngine; const AStaple: TBytes): ITlsEngine;
    function NewClient(const AConfig: ITlsClientConfig; const AHost: string;
      out AServer: ITlsEngine): ITlsEngine;
    /// <summary>A mutual-TLS pair: the server requests client auth and (optionally) parks on
    /// the client-certificate verdict; the client presents its credential.</summary>
    function NewMtls(AServerAsync: Boolean; out AServer: ITlsEngine): ITlsEngine;
    /// <summary>A mutual-TLS pair pinned to one version, the server on Hard client-cert
    /// revocation + an async resolver: the never-stapled client cert must be DEFERRED to the
    /// resolver (parked), not rejected inline.</summary>
    function NewHardMtls(AForce12: Boolean; out AServer: ITlsEngine): ITlsEngine;
    class procedure PumpOneWay(const AFrom, ATo: ITlsEngine); static;
    /// <summary>Exchanges flights until the client parks for a verdict, either side turns
    /// terminal, or both handshakes settle. Bounded so a stuck state cannot spin forever.</summary>
    procedure DriveUntilParkOrSettled(const AClient, AServer: ITlsEngine);
    /// <summary>Exchanges flights until both handshakes settle (or a bound is hit).</summary>
    procedure DriveToCompletion(const AClient, AServer: ITlsEngine);
    class function TakeCertificateEvent(const AEngine: ITlsEngine;
      out AEvent: ICertificateReceivedEvent): Boolean; static;
    /// <summary>Drains AEngine's events for the first peer fatal alert (the alert the peer put
    /// on the wire), returning its description; used to assert the reject alert byte-for-byte.</summary>
    class function TakePeerAlert(const AEngine: ITlsEngine;
      out AAlert: TTlsAlertDescription): Boolean; static;
    /// <summary>A pair pinned to TLS 1.2 or 1.3 in which the verifying side parks on a host verdict:
    /// the client verifies the server (AMtls False) or the server verifies the client's certificate
    /// (AMtls True). ARefuseSignature makes that verifying side's crypto reject the peer's handshake
    /// signature while its certificate chain still validates.</summary>
    function VersionedPair(AForce12, AMtls, ARefuseSignature: Boolean;
      out AServer: ITlsEngine): ITlsEngine;
    /// <summary>A Hard-posture client with live-revocation deferral and a server without a staple, so
    /// the client parks for the live check.</summary>
    function LiveRevocationClient(APosture: TRevocationPosture;
      out AServer: ITlsEngine): ITlsEngine;
    /// <summary>The verifying side refused the peer's signature before parking: terminal with
    /// decrypt_error, never awaiting a verdict and never having raised a CertificateReceived event.</summary>
    procedure CheckRefusedBeforePark(const AVerifier: ITlsEngine);
    /// <summary>Drives to the park, then resolves it with a Soft checker whose only OCSP responder
    /// is unreachable.</summary>
    procedure ResolveWithUnreachableResponder(const AClient, AServer: ITlsEngine);
    /// <summary>The pair parks after the peer's signature, accepts, and completes.</summary>
    procedure CheckParksThenCompletes(const AClient, AServer: ITlsEngine; AMtls: Boolean);
  published
    // the park follows the peer's key proof
    procedure TestTls13ClientRefusesBadServerSignatureBeforePark;
    procedure TestTls12ClientRefusesBadServerSignatureBeforePark;
    procedure TestTls13ServerRefusesBadClientSignatureBeforePark;
    procedure TestTls12ServerRefusesBadClientSignatureBeforePark;
    procedure TestTls12ClientParksThenAcceptCompletes;
    procedure TestTls12ServerParksThenAcceptCompletes;
    // the configured posture reaches the resolver through the engine
    procedure TestParkEventCarriesTheConfiguredPosture;
    procedure TestHardConfigurationRejectsUnreachableResponderBehindASoftChecker;
    procedure TestSoftConfigurationAcceptsUnreachableResponderBehindASoftChecker;
    // the verify callback runs last (after pinning) and sees both the presented and validated chains
    procedure TestVerifyCallbackRunsAfterPinning;
    procedure TestClientVerifyCallbackSeesPresentedChainAndValidatedPath;
    procedure TestClientVerifyCallbackSeesNoValidatedPathUnderSkip;
    procedure TestParkEventReportsNoValidatedPathUnderSkip;
    procedure TestConnectionInfoReportsNoValidatedPathUnderSkip;
    procedure TestServerVerifyCallbackSeesPresentedChainAndValidatedPath;
    procedure TestParkThenAcceptCompletes;
    procedure TestCertificateReceivedEventCarriesLeaf;
    procedure TestRejectFailsClosedWithBadCertificate;
    procedure TestParkedResumeOntoBadRecordFailsClosedNotRaise;
    procedure TestStartHandshakeAfterAbortQueuesNothingBehindTheAlert;
    procedure TestNoVerdictNeverCompletes;
    procedure TestResolverTimeoutRejectFailsClosed;
    procedure TestAcceptCannotResurrectPipelineRejectedChain;
    procedure TestDisabledResolvesInlineNoPark;
    procedure TestServerParkThenAcceptCompletes;
    procedure TestServerExporterWithheldWhileParked;
    procedure TestServerExporterWithheldUntilClientFinished;
    // the server park carries the pipeline-validated client path (issuer at index 1), distinct from
    // the presented leaf-only chain, so a live resolver authenticates against the PKIX issuer
    procedure TestServerParkEventCarriesValidatedPath;
    // PR3 behaviour end-to-end: under live-revocation a definitive Good staple settles revocation
    // inline, so the client completes WITHOUT the now-redundant park; an unstapled peer still parks;
    // and a host-decision park is never skipped by a Good staple
    procedure TestGoodStapleLiveRevocationSkipsPark;
    procedure TestNoStapleLiveRevocationParks;
    procedure TestGoodStapleHostDecisionStillParks;
    // a server that requests client auth but sets no verdict deferral must decide the client chain
    // inline and complete - it must never park (the park is armed only by a verdict-deferral setting)
    procedure TestServerClientAuthWithoutDeferralDoesNotPark;
    // server-side client-certificate SPKI pinning, end-to-end through CreateServerEngine: a matching
    // pin completes, a non-matching pin aborts with bad_certificate (the blocker regression)
    procedure TestMtlsServerClientPinMatchCompletes;
    procedure TestMtlsServerClientPinMismatchAborts;
    // the connection snapshot keeps the presented chain and the validated path apart: an inline mutual
    // handshake surfaces the client's leaf-only presented chain and the longer pipeline-built path
    procedure TestConnectionInfoSeparatesPresentedChainFromValidatedPath;
    procedure TestServerRejectFailsClosedWithBadCertificate;
    procedure TestRejectWithRevokedAlertReachesPeer;
    procedure TestServerRejectWithRevokedAlertReachesPeer;
    // server-side Hard client-cert revocation, end to end, both TLS versions: the Hard verifier
    // DEFERS the never-stapled client cert to the resolver (parks, not inline-reject), then a
    // revoked verdict aborts with certificate_revoked
    procedure TestServerHardClientRevocationParksThenRevokedTls13;
    procedure TestServerHardClientRevocationParksThenRevokedTls12;
    procedure TestPumpWriteAfterTerminalReportsTheRecordedAlert;
    procedure TestPumpReportsTheVerdictRejectReason;
    procedure TestPumpAbortSendsTheFatalAlertToThePeer;
    procedure TestPumpDrainEventsReportsPeerFatalAlertWithoutRaising;
    procedure TestPumpDrainEventsReportsCloseNotify;
    procedure TestPumpResolveVerdictWithoutResolverFailsClosed;
  end;

implementation

{ TTestAsyncVerdict }

function TTestAsyncVerdict.ClientConfig(AAsync: Boolean;
  ADeadlineMs: Cardinal): ITlsClientConfig;
var
  LClient: ITlsClientConfigBuilder;
begin
  LClient := TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithServerVerification(TServerVerification.WebPki(
      TTlsLibTestCertificates.Field('Certs/ClientAuthChain.txt', 'root_cert')).Build);
  if AAsync then
    LClient.WithAsyncCertificateVerdict(ADeadlineMs);
  Result := LClient.Build;
end;

function TTestAsyncVerdict.ServerConfig: ITlsServerConfig;
begin
  Result := TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithCredential(TTlsCredential.Load(Crypto, Pkix,
      TTlsLibTestCertificates.Field('Certs/ClientAuthChain.txt', 'leaf_cert'),
      TTlsLibTestCertificates.Field('Certs/ClientAuthChain.txt', 'leaf_key'))).Build;
end;

function TTestAsyncVerdict.NewClient(const AConfig: ITlsClientConfig;
  const AHost: string; out AServer: ITlsEngine): ITlsEngine;
begin
  Result := TTlsEngineFactory.CreateClientEngine(AConfig, AHost);
  AServer := TTlsEngineFactory.CreateServerEngine(ServerConfig);
end;

function TTestAsyncVerdict.MtlsClientConfig: ITlsClientConfig;
begin
  // the client trusts the server root and presents its own credential when the server
  // requests client authentication (the same vector leaf serves both directions)
  Result := TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithServerVerification(TServerVerification.WebPki(
      TTlsLibTestCertificates.Field('Certs/ClientAuthChain.txt', 'root_cert')).Build)
    .WithCredential(TTlsCredential.Load(Crypto, Pkix,
      TTlsLibTestCertificates.Field('Certs/ClientAuthChain.txt', 'leaf_cert'),
      TTlsLibTestCertificates.Field('Certs/ClientAuthChain.txt', 'leaf_key'))).Build;
end;

function TTestAsyncVerdict.MtlsServerConfig(AAsync: Boolean): ITlsServerConfig;
var
  LServer: ITlsServerConfigBuilder;
begin
  LServer := TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithCredential(TTlsCredential.Load(Crypto, Pkix,
      TTlsLibTestCertificates.Field('Certs/ClientAuthChain.txt', 'leaf_cert'),
      TTlsLibTestCertificates.Field('Certs/ClientAuthChain.txt', 'leaf_key')))
    .WithClientVerification(TClientVerification.WebPki(
      TTlsLibTestCertificates.Field('Certs/ClientAuthChain.txt', 'root_cert')).Build)
    .WithPeerAuth(TClientAuthMode.Required);
  if AAsync then
    LServer.WithAsyncCertificateVerdict(0);
  Result := LServer.Build;
end;

function TTestAsyncVerdict.MtlsServerConfigPinned(
  const APins: TArray<TBytes>): ITlsServerConfig;
begin
  Result := TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithCredential(TTlsCredential.Load(Crypto, Pkix,
      TTlsLibTestCertificates.Field('Certs/ClientAuthChain.txt', 'leaf_cert'),
      TTlsLibTestCertificates.Field('Certs/ClientAuthChain.txt', 'leaf_key')))
    .WithClientVerification(TClientVerification.WebPki(
      TTlsLibTestCertificates.Field('Certs/ClientAuthChain.txt', 'root_cert')).Build)
    .WithPeerAuth(TClientAuthMode.Required)
    .WithCertificatePinning(APins).Build;
end;

function TTestAsyncVerdict.StapledServer(const AStaple: TBytes): ITlsEngine;
var
  LCred: TTlsCredential;
begin
  // present the leaf + its issuer, and seal the OCSP staple on the credential so the server sends
  // a CertificateStatus when the client requests one
  LCred.CertificateChain := TArray<TBytes>.Create(
    TTlsLibTestCertificates.Field('Certs/OcspStapling.txt', 'leaf_cert'),
    TTlsLibTestCertificates.Field('Certs/OcspStapling.txt', 'issuer_cert'));
  LCred.PrivateKey := Crypto.Signing.ImportSigningKey(
    TTlsLibTestCertificates.Field('Certs/OcspStapling.txt', 'leaf_key'), nil);
  LCred.OcspStaple := AStaple;
  Result := TTlsEngineFactory.CreateServerEngine(
    TTlsPresets.Compatible(Crypto, Pkix).Server.WithCredential(LCred).Build);
end;

function TTestAsyncVerdict.StaplingRevocationClient(AHostDecision: Boolean;
  out AServer: ITlsEngine; const AStaple: TBytes): ITlsEngine;
var
  LClient: ITlsClientConfigBuilder;
begin
  // request a staple and require revocation; the host check is disabled so the test isolates the
  // revocation park from the leaf's SAN identity
  LClient := TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithServerVerification(TServerVerification.WebPki(
      TTlsLibTestCertificates.Field('Certs/OcspStapling.txt', 'root_cert'))
    .WithRevocation(TRevocationPosture.Hard).Build)
    .WithDangerousDisableServerNameCheck
    .WithOcspStaplingRequest(True);
  if AHostDecision then
    LClient.WithAsyncCertificateVerdict(0)
  else
    LClient.WithLiveRevocationVerdict(0);
  AServer := StapledServer(AStaple);
  Result := TTlsEngineFactory.CreateClientEngine(LClient.Build, 'localhost');
end;

function TTestAsyncVerdict.NewHardMtls(AForce12: Boolean;
  out AServer: ITlsEngine): ITlsEngine;
var
  LVer: TArray<UInt16>;
  // hold the owner builders alive: a role facet keeps only a raw back-reference to its owner,
  // so building both configs must not let either owner be released mid-use
  LClientOwner, LServerOwner: ITlsConfigBuilder;
  LClient: ITlsClientConfigBuilder;
  LServer: ITlsServerConfigBuilder;
  LClientCfg: ITlsClientConfig;
  LServerCfg: ITlsServerConfig;
begin
  if AForce12 then
    LVer := TArray<UInt16>.Create(TlsWireVersionTls12)
  else
    LVer := TArray<UInt16>.Create(TlsWireVersionTls13, TlsWireVersionTls12);
  // the client presents its credential and verifies the server inline (default Soft); only the
  // SERVER runs Hard client-cert revocation with an async resolver, so only it parks
  LClientOwner := TTlsPresets.Compatible(Crypto, Pkix);
  LClient := LClientOwner.Client
    .WithSupportedVersions(LVer)
    .WithServerVerification(TServerVerification.WebPki(
      TTlsLibTestCertificates.Field('Certs/ClientAuthChain.txt', 'root_cert')).Build)
    .WithCredential(TTlsCredential.Load(Crypto, Pkix,
      TTlsLibTestCertificates.Field('Certs/ClientAuthChain.txt', 'leaf_cert'),
      TTlsLibTestCertificates.Field('Certs/ClientAuthChain.txt', 'leaf_key')));
  LClientCfg := LClient.Build;

  LServerOwner := TTlsPresets.Compatible(Crypto, Pkix);
  LServer := LServerOwner.Server
    .WithSupportedVersions(LVer)
    .WithCredential(TTlsCredential.Load(Crypto, Pkix,
      TTlsLibTestCertificates.Field('Certs/ClientAuthChain.txt', 'leaf_cert'),
      TTlsLibTestCertificates.Field('Certs/ClientAuthChain.txt', 'leaf_key')))
    .WithClientVerification(TClientVerification.WebPki(
      TTlsLibTestCertificates.Field('Certs/ClientAuthChain.txt', 'root_cert'))
    .WithRevocation(TRevocationPosture.Hard).Build)
    .WithPeerAuth(TClientAuthMode.Required)
    .WithLiveRevocationVerdict(0);
  LServerCfg := LServer.Build;

  Result := TTlsEngineFactory.CreateClientEngine(LClientCfg, 'localhost');
  AServer := TTlsEngineFactory.CreateServerEngine(LServerCfg);
end;

function TTestAsyncVerdict.NewMtls(AServerAsync: Boolean;
  out AServer: ITlsEngine): ITlsEngine;
begin
  Result := TTlsEngineFactory.CreateClientEngine(MtlsClientConfig, 'localhost');
  AServer := TTlsEngineFactory.CreateServerEngine(MtlsServerConfig(AServerAsync));
end;

class procedure TTestAsyncVerdict.PumpOneWay(const AFrom, ATo: ITlsEngine);
var
  LBuf: TBytes;
  LGot: Int32;
begin
  LBuf := nil;
  SetLength(LBuf, 16384);
  repeat
    LGot := AFrom.TakeOutgoing(LBuf, 0);
    if LGot > 0 then
      ATo.ProcessInput(LBuf, 0, LGot);
  until LGot = 0;
end;

procedure TTestAsyncVerdict.DriveUntilParkOrSettled(const AClient,
  AServer: ITlsEngine);
var
  LI: Int32;
begin
  for LI := 0 to MaxPumpRounds - 1 do
  begin
    PumpOneWay(AClient, AServer);
    PumpOneWay(AServer, AClient);
    if AClient.AwaitingCertificateVerdict or AServer.AwaitingCertificateVerdict then
      Exit;
    if AClient.IsTerminal or AServer.IsTerminal then
      Exit;
    if (not AClient.IsHandshaking) and (not AServer.IsHandshaking) then
      Exit;
  end;
end;

procedure TTestAsyncVerdict.DriveToCompletion(const AClient, AServer: ITlsEngine);
var
  LI: Int32;
begin
  for LI := 0 to MaxPumpRounds - 1 do
  begin
    PumpOneWay(AClient, AServer);
    PumpOneWay(AServer, AClient);
    if AClient.IsTerminal or AServer.IsTerminal then
      Exit;
    if (not AClient.IsHandshaking) and (not AServer.IsHandshaking) then
      Exit;
  end;
end;

class function TTestAsyncVerdict.TakeCertificateEvent(const AEngine: ITlsEngine;
  out AEvent: ICertificateReceivedEvent): Boolean;
var
  LEvent: ITlsEvent;
begin
  Result := False;
  AEvent := nil;
  while AEngine.NextEvent(LEvent) do
    if (LEvent.Kind = TTlsEventKind.CertificateReceived) and
      Supports(LEvent, ICertificateReceivedEvent, AEvent) then
      Exit(True);
end;

function TTestAsyncVerdict.VersionedPair(AForce12, AMtls, ARefuseSignature: Boolean;
  out AServer: ITlsEngine): ITlsEngine;
var
  LVer: TArray<UInt16>;
  LClientCrypto, LServerCrypto, LRejecting: ICryptoProvider;
  LBuilder: ICryptoProviderBuilder;
  LClientOwner, LServerOwner: ITlsConfigBuilder;
  LClient: ITlsClientConfigBuilder;
  LServer: ITlsServerConfigBuilder;
begin
  if AForce12 then
    LVer := TArray<UInt16>.Create(TlsWireVersionTls12)
  else
    LVer := TArray<UInt16>.Create(TlsWireVersionTls13);
  LClientCrypto := Crypto;
  LServerCrypto := Crypto;
  if ARefuseSignature then
  begin
    LBuilder := TCryptoProviderBuilder.Create;
    LRejecting := LBuilder.WithPrimitives(Crypto.Primitives)
      .WithSigning(TRejectingVerifierSigning.Create(Crypto.Signing) as ISigningCrypto).Build;
    if AMtls then
      LServerCrypto := LRejecting
    else
      LClientCrypto := LRejecting;
  end;

  LClientOwner := TTlsPresets.Compatible(LClientCrypto, Pkix);
  LClient := LClientOwner.Client.WithSupportedVersions(LVer)
    .WithServerVerification(TServerVerification.WebPki(
      TTlsLibTestCertificates.Field('Certs/ClientAuthChain.txt', 'root_cert')).Build);
  if AMtls then
    LClient.WithCredential(TTlsCredential.Load(LClientCrypto, Pkix,
      TTlsLibTestCertificates.Field('Certs/ClientAuthChain.txt', 'leaf_cert'),
      TTlsLibTestCertificates.Field('Certs/ClientAuthChain.txt', 'leaf_key')))
  else
    LClient.WithAsyncCertificateVerdict(0);

  LServerOwner := TTlsPresets.Compatible(LServerCrypto, Pkix);
  LServer := LServerOwner.Server.WithSupportedVersions(LVer)
    .WithCredential(TTlsCredential.Load(LServerCrypto, Pkix,
      TTlsLibTestCertificates.Field('Certs/ClientAuthChain.txt', 'leaf_cert'),
      TTlsLibTestCertificates.Field('Certs/ClientAuthChain.txt', 'leaf_key')));
  if AMtls then
    LServer.WithClientVerification(TClientVerification.WebPki(
      TTlsLibTestCertificates.Field('Certs/ClientAuthChain.txt', 'root_cert')).Build)
      .WithPeerAuth(TClientAuthMode.Required).WithAsyncCertificateVerdict(0);

  Result := TTlsEngineFactory.CreateClientEngine(LClient.Build, 'localhost');
  AServer := TTlsEngineFactory.CreateServerEngine(LServer.Build);
end;

function TTestAsyncVerdict.LiveRevocationClient(APosture: TRevocationPosture;
  out AServer: ITlsEngine): ITlsEngine;
var
  LOwner: ITlsConfigBuilder;
  LClient: ITlsClientConfigBuilder;
begin
  LOwner := TTlsPresets.Compatible(Crypto, Pkix);
  LClient := LOwner.Client
    .WithServerVerification(TServerVerification.WebPki(
      TTlsLibTestCertificates.Field('Certs/ClientAuthChain.txt', 'root_cert'))
      .WithRevocation(APosture).Build)
    .WithLiveRevocationVerdict(0);
  Result := TTlsEngineFactory.CreateClientEngine(LClient.Build, 'localhost');
  AServer := TTlsEngineFactory.CreateServerEngine(ServerConfig);
end;

procedure TTestAsyncVerdict.CheckRefusedBeforePark(const AVerifier: ITlsEngine);
var
  LEvent: ICertificateReceivedEvent;
begin
  CheckTrue(AVerifier.IsTerminal, 'a bad handshake signature aborts the verifying side');
  CheckEquals(Ord(TTlsAlertDescription.DecryptError),
    Ord(AVerifier.LastError.Alert.Description), 'the abort is decrypt_error');
  CheckFalse(AVerifier.AwaitingCertificateVerdict, 'it never awaited a verdict');
  CheckFalse(TakeCertificateEvent(AVerifier, LEvent), 'and never raised a CertificateReceived event');
end;

procedure TTestAsyncVerdict.CheckParksThenCompletes(const AClient, AServer: ITlsEngine;
  AMtls: Boolean);
var
  LVerifier: ITlsEngine;
  LEvent: ICertificateReceivedEvent;
begin
  if AMtls then
    LVerifier := AServer
  else
    LVerifier := AClient;
  AClient.StartHandshake;
  DriveUntilParkOrSettled(AClient, AServer);
  CheckTrue(LVerifier.AwaitingCertificateVerdict, 'the verifying side parks once the signature verified');
  CheckTrue(TakeCertificateEvent(LVerifier, LEvent), 'the park raised its event for the resolver');
  CheckTrue(LVerifier.IsHandshaking, 'the handshake is held until the verdict arrives');
  LVerifier.SetCertificateVerdict(True, TTlsAlertDescription.BadCertificate);
  DriveToCompletion(AClient, AServer);
  CheckFalse(AClient.IsTerminal or AServer.IsTerminal, 'neither side failed');
  CheckFalse(AClient.IsHandshaking or AServer.IsHandshaking, 'both handshakes completed');
end;

procedure TTestAsyncVerdict.TestTls13ClientRefusesBadServerSignatureBeforePark;
var
  LClient, LServer: ITlsEngine;
  LForce12, LMtls, LRefuseSignature: Boolean;
begin
  LForce12 := False;
  LMtls := False;
  LRefuseSignature := True;
  LClient := VersionedPair(LForce12, LMtls, LRefuseSignature, LServer);
  LClient.StartHandshake;
  DriveUntilParkOrSettled(LClient, LServer);
  CheckRefusedBeforePark(LClient);
end;

procedure TTestAsyncVerdict.TestTls12ClientRefusesBadServerSignatureBeforePark;
var
  LClient, LServer: ITlsEngine;
  LForce12, LMtls, LRefuseSignature: Boolean;
begin
  LForce12 := True;
  LMtls := False;
  LRefuseSignature := True;
  LClient := VersionedPair(LForce12, LMtls, LRefuseSignature, LServer);
  LClient.StartHandshake;
  DriveUntilParkOrSettled(LClient, LServer);
  CheckRefusedBeforePark(LClient);
end;

procedure TTestAsyncVerdict.TestTls13ServerRefusesBadClientSignatureBeforePark;
var
  LClient, LServer: ITlsEngine;
  LForce12, LMtls, LRefuseSignature: Boolean;
begin
  LForce12 := False;
  LMtls := True;
  LRefuseSignature := True;
  LClient := VersionedPair(LForce12, LMtls, LRefuseSignature, LServer);
  LClient.StartHandshake;
  DriveUntilParkOrSettled(LClient, LServer);
  CheckRefusedBeforePark(LServer);
end;

procedure TTestAsyncVerdict.TestTls12ServerRefusesBadClientSignatureBeforePark;
var
  LClient, LServer: ITlsEngine;
  LForce12, LMtls, LRefuseSignature: Boolean;
begin
  LForce12 := True;
  LMtls := True;
  LRefuseSignature := True;
  LClient := VersionedPair(LForce12, LMtls, LRefuseSignature, LServer);
  LClient.StartHandshake;
  DriveUntilParkOrSettled(LClient, LServer);
  CheckRefusedBeforePark(LServer);
end;

procedure TTestAsyncVerdict.TestTls12ClientParksThenAcceptCompletes;
var
  LClient, LServer: ITlsEngine;
  LForce12, LMtls, LRefuseSignature: Boolean;
begin
  LForce12 := True;
  LMtls := False;
  LRefuseSignature := False;
  LClient := VersionedPair(LForce12, LMtls, LRefuseSignature, LServer);
  CheckParksThenCompletes(LClient, LServer, False);
end;

procedure TTestAsyncVerdict.TestTls12ServerParksThenAcceptCompletes;
var
  LClient, LServer: ITlsEngine;
  LForce12, LMtls, LRefuseSignature: Boolean;
begin
  LForce12 := True;
  LMtls := True;
  LRefuseSignature := False;
  LClient := VersionedPair(LForce12, LMtls, LRefuseSignature, LServer);
  CheckParksThenCompletes(LClient, LServer, True);
end;

procedure TTestAsyncVerdict.TestParkEventCarriesTheConfiguredPosture;
var
  LClient, LServer: ITlsEngine;
  LEvent: ICertificateReceivedEvent;
begin
  LClient := LiveRevocationClient(TRevocationPosture.Hard, LServer);
  LClient.StartHandshake;
  DriveUntilParkOrSettled(LClient, LServer);
  CheckTrue(TakeCertificateEvent(LClient, LEvent), 'the park raised its event');
  CheckEquals(Ord(TRevocationPosture.Hard), Ord(LEvent.RevocationPosture),
    'the event carries the configured posture');
end;

procedure TTestAsyncVerdict.TestHardConfigurationRejectsUnreachableResponderBehindASoftChecker;
var
  LClient, LServer: ITlsEngine;
begin
  LClient := LiveRevocationClient(TRevocationPosture.Hard, LServer);
  ResolveWithUnreachableResponder(LClient, LServer);
  CheckTrue(LClient.IsTerminal, 'the Hard configuration rejects the unreachable responder');
  CheckEquals(Ord(TTlsAlertDescription.BadCertificateStatusResponse),
    Ord(LClient.LastError.Alert.Description), 'with bad_certificate_status_response');
end;

procedure TTestAsyncVerdict.TestSoftConfigurationAcceptsUnreachableResponderBehindASoftChecker;
var
  LClient, LServer: ITlsEngine;
begin
  LClient := LiveRevocationClient(TRevocationPosture.Soft, LServer);
  ResolveWithUnreachableResponder(LClient, LServer);
  CheckFalse(LClient.IsTerminal, 'a Soft configuration soft-fails the unreachable responder');
  CheckFalse(LClient.AwaitingCertificateVerdict,
    'the verdict was delivered, the client is not parked');
  CheckFalse(LClient.IsHandshaking, 'the client completed the handshake');
end;

procedure TTestAsyncVerdict.ResolveWithUnreachableResponder(const AClient,
  AServer: ITlsEngine);
var
  LEvent: ICertificateReceivedEvent;
  LSpy: TMockPkixProvider;
  LSpyRef: IPkixProvider;
  LChecker: TLiveRevocationChecker;
begin
  AClient.StartHandshake;
  DriveUntilParkOrSettled(AClient, AServer);
  CheckTrue(TakeCertificateEvent(AClient, LEvent), 'the park raised its event');
  LSpy := TMockPkixProvider.Create(Pkix);
  LSpyRef := LSpy as IPkixProvider;
  LSpy.OverrideOcspUrls(TArray<string>.Create('http://ocsp.test/'));
  LChecker := TLiveRevocationChecker.Create(LSpyRef, TSystemClock.Create as ITlsClock,
    TSystemMonotonicClock.Create as ITlsMonotonicClock,
    TMockHttpFetcher.Create as IHttpFetcher, TRevocationPosture.Soft,
    TLiveRevocationMethod.Ocsp, 0);
  try
    TTlsStreamPump.ResolveVerdict(AClient, LEvent, LChecker.ResolveVerdict, TPeerRole.Server);
  finally
    LChecker.Free;
  end;
end;

procedure TTestAsyncVerdict.TestVerifyCallbackRunsAfterPinning;
var
  LClient, LServer: ITlsEngine;
  LOwner: ITlsConfigBuilder;
  LSpy: TVerifyCallbackSpy;
begin
  // a pin that matches nothing rejects the chain; the callback, running last, is never asked
  LSpy := Own<TVerifyCallbackSpy>(TVerifyCallbackSpy.Create(True));
  LOwner := TTlsPresets.Compatible(Crypto, Pkix);
  LClient := TTlsEngineFactory.CreateClientEngine(LOwner.Client
    .WithServerVerification(TServerVerification.WebPki(
      TTlsLibTestCertificates.Field('Certs/ClientAuthChain.txt', 'root_cert')).Build)
    .WithCertificatePinning(TArray<TBytes>.Create(Crypto.Primitives.GetRandom.GenerateBytes(32)))
    .WithCertificateVerifyCallback(LSpy.Callback).Build, 'localhost');
  LServer := TTlsEngineFactory.CreateServerEngine(ServerConfig);
  LClient.StartHandshake;
  DriveToCompletion(LClient, LServer);
  CheckTrue(LClient.IsTerminal, 'the mismatched pin aborts the client');
  CheckEquals(Ord(TTlsAlertDescription.BadCertificate),
    Ord(LClient.LastError.Alert.Description), 'with bad_certificate from the pin');
  CheckEquals(0, LSpy.Calls, 'the callback runs after pinning, so a pin rejection never reaches it');
end;

procedure TTestAsyncVerdict.TestClientVerifyCallbackSeesPresentedChainAndValidatedPath;
var
  LClient, LServer: ITlsEngine;
  LOwner: ITlsConfigBuilder;
  LSpy: TVerifyCallbackSpy;
begin
  LSpy := Own<TVerifyCallbackSpy>(TVerifyCallbackSpy.Create(True));
  LOwner := TTlsPresets.Compatible(Crypto, Pkix);
  LClient := TTlsEngineFactory.CreateClientEngine(LOwner.Client
    .WithServerVerification(TServerVerification.WebPki(
      TTlsLibTestCertificates.Field('Certs/ClientAuthChain.txt', 'root_cert')).Build)
    .WithCertificateVerifyCallback(LSpy.Callback).Build, 'localhost');
  LServer := TTlsEngineFactory.CreateServerEngine(ServerConfig);
  LClient.StartHandshake;
  DriveToCompletion(LClient, LServer);
  CheckFalse(LClient.IsTerminal, 'the accepting callback leaves the handshake alone');
  CheckEquals(1, System.Length(LSpy.Presented), 'the server presented its leaf only');
  CheckEquals(2, System.Length(LSpy.Validated), 'the validated path runs leaf then the trust anchor');
  CheckEqualBytes('the validated path ends at the configured anchor',
    TTlsLibTestCertificates.Field('Certs/ClientAuthChain.txt', 'root_cert'), LSpy.Validated[1]);
end;

procedure TTestAsyncVerdict.TestClientVerifyCallbackSeesNoValidatedPathUnderSkip;
var
  LClient, LServer: ITlsEngine;
  LOwner: ITlsConfigBuilder;
  LSpy: TVerifyCallbackSpy;
begin
  LSpy := Own<TVerifyCallbackSpy>(TVerifyCallbackSpy.Create(True));
  LOwner := TTlsPresets.Compatible(Crypto, Pkix);
  LClient := TTlsEngineFactory.CreateClientEngine(LOwner.Client
    .WithServerVerification(TServerVerification.DangerousSkip)
    .WithCertificateVerifyCallback(LSpy.Callback).Build, 'localhost');
  LServer := TTlsEngineFactory.CreateServerEngine(ServerConfig);
  LClient.StartHandshake;
  DriveToCompletion(LClient, LServer);
  CheckFalse(LClient.IsTerminal, 'the skipped verification accepts');
  CheckEquals(1, System.Length(LSpy.Presented), 'the presented chain reaches the callback');
  CheckEquals(0, System.Length(LSpy.Validated), 'no path was validated, so none is reported');
end;

procedure TTestAsyncVerdict.TestParkEventReportsNoValidatedPathUnderSkip;
var
  LClient, LServer: ITlsEngine;
  LOwner: ITlsConfigBuilder;
  LEvent: ICertificateReceivedEvent;
begin
  LOwner := TTlsPresets.Compatible(Crypto, Pkix);
  LClient := TTlsEngineFactory.CreateClientEngine(LOwner.Client
    .WithServerVerification(TServerVerification.DangerousSkip).WithAsyncCertificateVerdict(0)
    .Build, 'localhost');
  LServer := TTlsEngineFactory.CreateServerEngine(ServerConfig);
  LClient.StartHandshake;
  DriveUntilParkOrSettled(LClient, LServer);
  CheckTrue(TakeCertificateEvent(LClient, LEvent), 'the park raised its event');
  CheckEquals(0, System.Length(LEvent.ValidatedPath), 'nothing was validated, so no path is reported');
  CheckEquals(1, System.Length(LEvent.Chain), 'the presented chain is reported');
end;

procedure TTestAsyncVerdict.TestConnectionInfoReportsNoValidatedPathUnderSkip;
var
  LClient, LServer: ITlsEngine;
  LOwner: ITlsConfigBuilder;
begin
  LOwner := TTlsPresets.Compatible(Crypto, Pkix);
  LClient := TTlsEngineFactory.CreateClientEngine(LOwner.Client
    .WithServerVerification(TServerVerification.DangerousSkip).Build, 'localhost');
  LServer := TTlsEngineFactory.CreateServerEngine(ServerConfig);
  LClient.StartHandshake;
  DriveToCompletion(LClient, LServer);
  CheckEquals(0, System.Length(LClient.ConnectionInfo.ValidatedPath),
    'nothing was validated, so no path is reported');
  CheckEquals(1, System.Length(LClient.ConnectionInfo.PeerCertificates),
    'the presented chain is reported');
end;

procedure TTestAsyncVerdict.TestServerVerifyCallbackSeesPresentedChainAndValidatedPath;
var
  LClient, LServer: ITlsEngine;
  LOwner: ITlsConfigBuilder;
  LSpy: TVerifyCallbackSpy;
begin
  LSpy := Own<TVerifyCallbackSpy>(TVerifyCallbackSpy.Create(True));
  LOwner := TTlsPresets.Compatible(Crypto, Pkix);
  LClient := TTlsEngineFactory.CreateClientEngine(MtlsClientConfig, 'localhost');
  LServer := TTlsEngineFactory.CreateServerEngine(LOwner.Server
    .WithCredential(TTlsCredential.Load(Crypto, Pkix,
      TTlsLibTestCertificates.Field('Certs/ClientAuthChain.txt', 'leaf_cert'),
      TTlsLibTestCertificates.Field('Certs/ClientAuthChain.txt', 'leaf_key')))
    .WithClientVerification(TClientVerification.WebPki(
      TTlsLibTestCertificates.Field('Certs/ClientAuthChain.txt', 'root_cert')).Build)
    .WithPeerAuth(TClientAuthMode.Required).WithCertificateVerifyCallback(LSpy.Callback).Build);
  LClient.StartHandshake;
  DriveToCompletion(LClient, LServer);
  CheckFalse(LServer.IsTerminal, 'the accepting callback leaves the handshake alone');
  CheckEquals(1, System.Length(LSpy.Presented), 'the client presented its leaf only');
  CheckEquals(2, System.Length(LSpy.Validated), 'the validated path runs leaf then the trust anchor');
end;

procedure TTestAsyncVerdict.TestParkThenAcceptCompletes;
var
  LClient, LServer: ITlsEngine;
begin
  LClient := NewClient(ClientConfig(True, 0), 'localhost', LServer);
  LClient.StartHandshake;
  DriveUntilParkOrSettled(LClient, LServer);

  CheckTrue(LClient.AwaitingCertificateVerdict,
    'the client should park awaiting the certificate verdict');
  CheckTrue(LClient.IsHandshaking, 'a parked handshake is still in progress');
  CheckFalse(LClient.IsTerminal, 'a parked handshake has not failed');

  LClient.SetCertificateVerdict(True, TTlsAlertDescription.BadCertificate);
  DriveToCompletion(LClient, LServer);

  CheckFalse(LClient.IsTerminal, 'the accepted handshake must not be terminal');
  CheckFalse(LClient.IsHandshaking, 'the accepted client handshake must complete');
  CheckFalse(LServer.IsHandshaking, 'the server handshake must complete');
  CheckFalse(LClient.AwaitingCertificateVerdict,
    'the verdict was resolved, so nothing is awaited');
  CheckEquals(Int64(TlsWireVersionTls13),
    Int64(LClient.ConnectionInfo.NegotiatedVersion.WireValue),
    'the resumed handshake negotiates TLS 1.3');
end;

procedure TTestAsyncVerdict.TestCertificateReceivedEventCarriesLeaf;
var
  LClient, LServer: ITlsEngine;
  LEvent: ICertificateReceivedEvent;
  LChain: TArray<TBytes>;
begin
  LClient := NewClient(ClientConfig(True, 0), 'localhost', LServer);
  LClient.StartHandshake;
  DriveUntilParkOrSettled(LClient, LServer);

  CheckTrue(TakeCertificateEvent(LClient, LEvent),
    'a CertificateReceived event must be raised on the park');
  LChain := LEvent.Chain;
  CheckTrue(System.Length(LChain) >= 1, 'the event carries the peer chain');
  CheckTrue(AreEqual(
    TTlsLibTestCertificates.Field('Certs/ClientAuthChain.txt', 'leaf_cert'), LChain[0]),
    'the leaf certificate is the first chain entry');
  CheckEquals('localhost', LEvent.HostName, 'the event carries the expected host');
end;

procedure TTestAsyncVerdict.TestRejectFailsClosedWithBadCertificate;
var
  LClient, LServer: ITlsEngine;
begin
  LClient := NewClient(ClientConfig(True, 0), 'localhost', LServer);
  LClient.StartHandshake;
  DriveUntilParkOrSettled(LClient, LServer);
  CheckTrue(LClient.AwaitingCertificateVerdict, 'the client should be parked');

  LClient.SetCertificateVerdict(False, TTlsAlertDescription.BadCertificate);

  CheckTrue(LClient.IsTerminal, 'a rejected verdict aborts the handshake (fail-closed)');
  CheckFalse(LClient.AwaitingCertificateVerdict, 'the verdict has been resolved');
  CheckEquals(Int64(Ord(TTlsAlertDescription.BadCertificate)),
    Int64(Ord(LClient.LastError.Alert.Description)),
    'a rejected verdict aborts with bad_certificate');
end;

procedure TTestAsyncVerdict.TestParkedResumeOntoBadRecordFailsClosedNotRaise;
var
  LClient, LServer: ITlsEngine;
  LBad: TBytes;
begin
  // resuming a parked verdict drains the buffered flight (CertificateVerify, Finished) and any
  // record behind it. A malformed/undecryptable record there raises inside the machine; the
  // engine must catch it, abort with the alert and stay non-terminal-free (terminal), NOT let the
  // exception escape SetCertificateVerdict with no alert on the wire: a handshake exception must
  // surface a fatal alert and leave the engine terminal.
  LClient := NewClient(ClientConfig(True, 0), 'localhost', LServer);
  LClient.StartHandshake;
  DriveUntilParkOrSettled(LClient, LServer);
  CheckTrue(LClient.AwaitingCertificateVerdict, 'the client should be parked');

  // frame an extra application_data record behind the buffered flight: content type 23, legacy
  // version 0x0303, 32 bytes of ciphertext that cannot authenticate under the application read key
  // the Finished is about to install. It is pulled after the handshake completes, during the
  // resume drain, and fails its AEAD tag (bad_record_mac).
  LBad := nil;
  SetLength(LBad, 5 + 32);
  LBad[0] := 23;
  LBad[1] := 3;
  LBad[2] := 3;
  LBad[3] := 0;
  LBad[4] := 32;
  LClient.ProcessInput(LBad, 0, System.Length(LBad));

  // must not raise out of SetCertificateVerdict
  LClient.SetCertificateVerdict(True, TTlsAlertDescription.BadCertificate);

  CheckTrue(LClient.IsTerminal,
    'a bad record behind the resumed flight aborts the engine instead of escaping as an exception');
  CheckEquals(Int64(Ord(TTlsAlertDescription.BadRecordMac)),
    Int64(Ord(LClient.LastError.Alert.Description)),
    'the undecryptable record aborts with bad_record_mac');
  CheckTrue(LClient.WantsWrite, 'the fatal alert is queued for the peer');
end;

procedure TTestAsyncVerdict.TestStartHandshakeAfterAbortQueuesNothingBehindTheAlert;
var
  LClient, LServer: ITlsEngine;
  LOut: TBytes;
begin
  LClient := NewClient(ClientConfig(False, 0), 'localhost', LServer);
  LClient.SendAlert(TTlsAlertDescription.HandshakeFailure);
  System.SetLength(LOut, 4096);
  LClient.TakeOutgoing(LOut, 0);
  CheckTrue(LClient.IsTerminal, 'the engine is terminal after its fatal alert');
  LClient.StartHandshake;
  CheckFalse(LClient.WantsWrite, 'no ClientHello is queued after the alert');
end;

procedure TTestAsyncVerdict.TestNoVerdictNeverCompletes;
var
  LClient, LServer: ITlsEngine;
begin
  LClient := NewClient(ClientConfig(True, 0), 'localhost', LServer);
  LClient.StartHandshake;
  DriveUntilParkOrSettled(LClient, LServer);
  CheckTrue(LClient.AwaitingCertificateVerdict, 'the client should be parked');

  // no verdict is delivered: the handshake must make no further progress - never a silent
  // pass. Extra transport churn must not let it complete on its own.
  DriveToCompletion(LClient, LServer);

  CheckTrue(LClient.AwaitingCertificateVerdict,
    'without a verdict the client stays parked');
  CheckTrue(LClient.IsHandshaking, 'without a verdict the handshake never completes');
  CheckFalse(LClient.IsTerminal, 'the parked handshake has not failed of its own accord');
end;

procedure TTestAsyncVerdict.TestResolverTimeoutRejectFailsClosed;
var
  LClient, LServer: ITlsEngine;
begin
  // a resolver that cannot decide in time returns a failure; that path is
  // SetCertificateVerdict(False, <alert>) - fail-closed (the engine owns no timer)
  LClient := NewClient(ClientConfig(True, 1), 'localhost', LServer);
  LClient.StartHandshake;
  DriveUntilParkOrSettled(LClient, LServer);
  CheckTrue(LClient.AwaitingCertificateVerdict, 'the client should be parked');

  LClient.SetCertificateVerdict(False, TTlsAlertDescription.BadCertificate); // the resolver's timeout action

  CheckTrue(LClient.IsTerminal, 'a resolver-timeout reject aborts the handshake (fail-closed)');
  CheckEquals(Int64(Ord(TTlsAlertDescription.BadCertificate)),
    Int64(Ord(LClient.LastError.Alert.Description)),
    'the reject aborts with bad_certificate');
end;

procedure TTestAsyncVerdict.TestAcceptCannotResurrectPipelineRejectedChain;
var
  LClient, LServer: ITlsEngine;
begin
  // async enabled, but the expected host does not match the leaf SAN (localhost): the
  // built-in pipeline rejects the chain during endpoint-identity, BEFORE any park. An
  // async accept must not be able to rescue it - augment-only.
  LClient := NewClient(ClientConfig(True, 0), 'wrong.invalid', LServer);
  LClient.StartHandshake;
  DriveUntilParkOrSettled(LClient, LServer);

  CheckFalse(LClient.AwaitingCertificateVerdict,
    'a pipeline rejection must not reach the async park');
  CheckTrue(LClient.IsTerminal, 'the pipeline rejection aborts the handshake');

  // an accept after the pipeline already rejected is a no-op: the engine is terminal and
  // the handshake can never complete
  LClient.SetCertificateVerdict(True, TTlsAlertDescription.BadCertificate);
  CheckTrue(LClient.IsTerminal, 'accept cannot resurrect a pipeline-rejected chain');
  CheckTrue(LClient.IsHandshaking = False, 'the terminal engine never handshakes again');
end;

procedure TTestAsyncVerdict.TestDisabledResolvesInlineNoPark;
var
  LClient, LServer: ITlsEngine;
begin
  // with async disabled (the default), the verdict resolves inline: the handshake completes
  // without ever parking or awaiting a verdict
  LClient := NewClient(ClientConfig(False, 0), 'localhost', LServer);
  LClient.StartHandshake;
  DriveToCompletion(LClient, LServer);

  CheckFalse(LClient.AwaitingCertificateVerdict,
    'the inline path never awaits a verdict');
  CheckFalse(LClient.IsHandshaking, 'the inline handshake completes');
  CheckFalse(LClient.IsTerminal, 'the inline handshake succeeds');
end;

procedure TTestAsyncVerdict.TestServerParkThenAcceptCompletes;
var
  LClient, LServer: ITlsEngine;
begin
  // the symmetric server-side seam: a server requesting client auth parks on the client
  // certificate verdict, and an accept resumes to completion
  LClient := NewMtls(True, LServer);
  LClient.StartHandshake;
  DriveUntilParkOrSettled(LClient, LServer);

  CheckTrue(LServer.AwaitingCertificateVerdict,
    'the server should park awaiting the client-certificate verdict');
  CheckFalse(LClient.AwaitingCertificateVerdict,
    'the client resolves its own verdict inline (async is server-only here)');

  LServer.SetCertificateVerdict(True, TTlsAlertDescription.BadCertificate);
  DriveToCompletion(LClient, LServer);

  CheckFalse(LServer.IsTerminal, 'the accepted server handshake must not be terminal');
  CheckFalse(LServer.IsHandshaking, 'the server handshake must complete');
  CheckFalse(LClient.IsHandshaking, 'the client handshake must complete');
end;

procedure TTestAsyncVerdict.TestServerExporterWithheldWhileParked;
var
  LClient, LServer: ITlsEngine;
begin
  // a TLS 1.3 server derives its exporter secret at half-RTT (it has sent its Finished), but while
  // it is parked on an async client-certificate verdict the peer identity is still being decided,
  // so the exporter is withheld - never exported over an unverified client. It becomes available
  // the moment the verdict clears the park (before the buffered client flight even finishes driving
  // completion), and matches the client's after.
  LClient := NewMtls(True, LServer);
  LClient.StartHandshake;
  DriveUntilParkOrSettled(LClient, LServer);
  CheckTrue(LServer.AwaitingCertificateVerdict,
    'the server should park awaiting the client-certificate verdict');

  CheckEquals(0, System.Length(LServer.ExportKeyingMaterial('EXPORTER-test', 32)),
    'the server withholds the half-RTT exporter while parked on the client-cert verdict');

  LServer.SetCertificateVerdict(True, TTlsAlertDescription.BadCertificate);
  CheckEquals(32, System.Length(LServer.ExportKeyingMaterial('EXPORTER-test', 32)),
    'the exporter is available again once the verdict clears the park, not only at Connected');

  DriveToCompletion(LClient, LServer);
  CheckFalse(LServer.IsHandshaking, 'the server handshake must complete');
  CheckEqualBytes('client and server export the same keying material after completion',
    LClient.ExportKeyingMaterial('EXPORTER-test', 32),
    LServer.ExportKeyingMaterial('EXPORTER-test', 32));
end;

procedure TTestAsyncVerdict.TestServerExporterWithheldUntilClientFinished;
var
  LClient, LServer: ITlsEngine;
begin
  // without any park: under client authentication the half-RTT exporter stays withheld until the
  // client's Finished has arrived, since until then the client's identity is unproven
  LClient := NewMtls(False, LServer);
  LClient.StartHandshake;
  PumpOneWay(LClient, LServer);
  PumpOneWay(LServer, LClient);
  CheckFalse(LServer.IsTerminal, 'the server took the first flight');
  CheckTrue(LServer.IsHandshaking, 'the server still waits for the client flight');
  CheckEquals(0, System.Length(LServer.ExportKeyingMaterial('EXPORTER-test', 32)),
    'the server withholds the half-RTT exporter while client authentication is pending');

  DriveToCompletion(LClient, LServer);
  CheckFalse(LServer.IsHandshaking, 'the server handshake must complete');
  CheckEqualBytes('client and server export the same keying material after completion',
    LClient.ExportKeyingMaterial('EXPORTER-test', 32),
    LServer.ExportKeyingMaterial('EXPORTER-test', 32));
end;

procedure TTestAsyncVerdict.TestServerParkEventCarriesValidatedPath;
var
  LClient, LServer: ITlsEngine;
  LEvent: ICertificateReceivedEvent;
  LPresented, LValidated: TArray<TBytes>;
begin
  // the mTLS server parks on the client certificate; the CertificateReceived event carries both the
  // chain as presented and the validated path. The client presents a leaf-only credential, but the
  // pipeline assembles the issuer, so the validated path is longer and terminates at the trust root
  LClient := NewMtls(True, LServer);
  LClient.StartHandshake;
  DriveUntilParkOrSettled(LClient, LServer);
  CheckTrue(LServer.AwaitingCertificateVerdict, 'the server should be parked');

  CheckTrue(TakeCertificateEvent(LServer, LEvent),
    'a CertificateReceived event is raised on the server park');
  LPresented := LEvent.Chain;
  LValidated := LEvent.ValidatedPath;
  CheckTrue(AreEqual(
    TTlsLibTestCertificates.Field('Certs/ClientAuthChain.txt', 'leaf_cert'), LPresented[0]),
    'the presented chain leaf is the client leaf');
  CheckTrue(System.Length(LValidated) >= 2,
    'the validated path carries the assembled issuer, not just the leaf');
  CheckTrue(AreEqual(
    TTlsLibTestCertificates.Field('Certs/ClientAuthChain.txt', 'leaf_cert'), LValidated[0]),
    'the validated path leaf is the client leaf');
  CheckTrue(AreEqual(TTlsLibTestCertificates.Field('Certs/ClientAuthChain.txt', 'root_cert'),
    LValidated[System.High(LValidated)]),
    'the validated path terminates at the configured trust anchor');
end;

procedure TTestAsyncVerdict.TestGoodStapleLiveRevocationSkipsPark;
var
  LClient, LServer: ITlsEngine;
  LEvent: ICertificateReceivedEvent;
  LHostDecision: Boolean;
begin
  // under live-revocation, a current Good staple settles revocation inline, so the redundant live
  // park is skipped: the client never awaits a verdict and completes the handshake
  LHostDecision := False;
  LClient := StaplingRevocationClient(LHostDecision, LServer,
    TTlsLibTestCertificates.Field('Certs/OcspStapling.txt', 'ocsp_good'));
  LClient.StartHandshake;
  DriveToCompletion(LClient, LServer);

  CheckFalse(LClient.AwaitingCertificateVerdict,
    'a Good-stapled live-revocation client skips the redundant park');
  CheckFalse(TakeCertificateEvent(LClient, LEvent),
    'no CertificateReceived event is raised when the park is skipped');
  CheckFalse(LClient.IsHandshaking, 'the handshake completed without a park');
  CheckFalse(LClient.IsTerminal, 'the handshake succeeded');
end;

procedure TTestAsyncVerdict.TestNoStapleLiveRevocationParks;
var
  LClient, LServer: ITlsEngine;
  LHostDecision: Boolean;
begin
  // the same client with no staple: revocation is indeterminate and deferred, so the park runs -
  // proving the skip is gated on the settled staple, not on the live-revocation mode itself
  LHostDecision := False;
  LClient := StaplingRevocationClient(LHostDecision, LServer, nil);
  LClient.StartHandshake;
  DriveUntilParkOrSettled(LClient, LServer);

  CheckTrue(LClient.AwaitingCertificateVerdict,
    'an unstapled live-revocation client parks for the live check');
end;

procedure TTestAsyncVerdict.TestGoodStapleHostDecisionStillParks;
var
  LClient, LServer: ITlsEngine;
  LHostDecision: Boolean;
begin
  // a host-decision park is a separate policy (prompt on every accepted peer): a Good staple never
  // skips it
  LHostDecision := True;
  LClient := StaplingRevocationClient(LHostDecision, LServer,
    TTlsLibTestCertificates.Field('Certs/OcspStapling.txt', 'ocsp_good'));
  LClient.StartHandshake;
  DriveUntilParkOrSettled(LClient, LServer);

  CheckTrue(LClient.AwaitingCertificateVerdict,
    'a host-decision park is not skipped by a Good staple');
end;

procedure TTestAsyncVerdict.TestServerClientAuthWithoutDeferralDoesNotPark;
var
  LClient, LServer: ITlsEngine;
begin
  // the server requests client auth but arms no async verdict: it verifies the client chain inline
  // (default Soft) and completes. Neither side parks - the deferral park is armed only by a resolver
  LClient := NewMtls(False, LServer);
  LClient.StartHandshake;
  DriveToCompletion(LClient, LServer);

  CheckFalse(LServer.AwaitingCertificateVerdict,
    'a Requested-auth server with no deferral must not park on the client chain');
  CheckFalse(LClient.AwaitingCertificateVerdict, 'the client resolves inline');
  CheckFalse(LServer.IsHandshaking, 'the server handshake completes inline');
  CheckFalse(LClient.IsHandshaking, 'the client handshake completes inline');
  CheckFalse(LServer.IsTerminal, 'the inline mutual handshake succeeds');
end;

procedure TTestAsyncVerdict.TestMtlsServerClientPinMatchCompletes;
var
  LClient, LServer: ITlsEngine;
begin
  // the server pins the client leaf's SPKI; the presented client chain carries it, so the pinned
  // mutual handshake completes
  LClient := TTlsEngineFactory.CreateClientEngine(MtlsClientConfig, 'localhost');
  LServer := TTlsEngineFactory.CreateServerEngine(
    MtlsServerConfigPinned(TArray<TBytes>.Create(
      TTlsLibTestCertificates.SpkiSha256(Crypto, Pkix,
        TTlsLibTestCertificates.Field('Certs/ClientAuthChain.txt', 'leaf_cert')))));
  LClient.StartHandshake;
  DriveToCompletion(LClient, LServer);
  CheckFalse(LServer.IsHandshaking or LClient.IsHandshaking,
    'a matching client-cert pin completes the mutual handshake');
  CheckFalse(LServer.IsTerminal or LClient.IsTerminal,
    'a matching client-cert pin: no failure');
end;

procedure TTestAsyncVerdict.TestMtlsServerClientPinMismatchAborts;
var
  LClient, LServer: ITlsEngine;
  LWrongPin: TBytes;
begin
  // the server pins a key the client does not present; it must REJECT the client certificate
  // (bad_certificate), not silently accept it. This drives the real CreateServerEngine composition,
  // so it fails if server-side pinning is not wired.
  LWrongPin := nil;
  SetLength(LWrongPin, 32);
  FillChar(LWrongPin[0], 32, $AB);
  LClient := TTlsEngineFactory.CreateClientEngine(MtlsClientConfig, 'localhost');
  LServer := TTlsEngineFactory.CreateServerEngine(
    MtlsServerConfigPinned(TArray<TBytes>.Create(LWrongPin)));
  LClient.StartHandshake;
  DriveToCompletion(LClient, LServer);
  CheckTrue(LServer.IsTerminal, 'a non-matching client-cert pin fails closed');
  CheckEquals(Int64(Ord(TTlsAlertDescription.BadCertificate)),
    Int64(Ord(LServer.LastError.Alert.Description)),
    'a client-cert pin mismatch is bad_certificate');
end;

procedure TTestAsyncVerdict.TestConnectionInfoSeparatesPresentedChainFromValidatedPath;
var
  LClient, LServer: ITlsEngine;
  LInfo: TTlsConnectionInfo;
begin
  // an inline mutual handshake (no async park): the client presents a leaf-only credential, but the
  // server's pipeline assembles the issuer, so the presented chain and the validated path differ
  LClient := NewMtls(False, LServer);
  LClient.StartHandshake;
  DriveToCompletion(LClient, LServer);
  CheckFalse(LServer.IsHandshaking, 'the server handshake completes inline');
  CheckFalse(LServer.IsTerminal, 'the inline mutual handshake succeeds');

  LInfo := LServer.ConnectionInfo;
  CheckEquals(1, System.Length(LInfo.PeerCertificates),
    'the presented client chain is the leaf-only credential');
  CheckTrue(AreEqual(
    TTlsLibTestCertificates.Field('Certs/ClientAuthChain.txt', 'leaf_cert'),
    LInfo.PeerCertificates[0]),
    'the presented chain leaf is the client leaf');
  CheckTrue(System.Length(LInfo.ValidatedPath) >= 2,
    'the validated path assembles the issuer beyond the presented leaf');
  CheckTrue(AreEqual(
    TTlsLibTestCertificates.Field('Certs/ClientAuthChain.txt', 'leaf_cert'),
    LInfo.ValidatedPath[0]),
    'the validated path leaf is the client leaf');
  CheckTrue(AreEqual(TTlsLibTestCertificates.Field('Certs/ClientAuthChain.txt', 'root_cert'),
    LInfo.ValidatedPath[System.High(LInfo.ValidatedPath)]),
    'the validated path terminates at the configured trust anchor');
end;

procedure TTestAsyncVerdict.TestServerRejectFailsClosedWithBadCertificate;
var
  LClient, LServer: ITlsEngine;
begin
  LClient := NewMtls(True, LServer);
  LClient.StartHandshake;
  DriveUntilParkOrSettled(LClient, LServer);
  CheckTrue(LServer.AwaitingCertificateVerdict, 'the server should be parked');

  LServer.SetCertificateVerdict(False, TTlsAlertDescription.BadCertificate);

  CheckTrue(LServer.IsTerminal,
    'a rejected client-certificate verdict aborts the handshake (fail-closed)');
  CheckEquals(Int64(Ord(TTlsAlertDescription.BadCertificate)),
    Int64(Ord(LServer.LastError.Alert.Description)),
    'a rejected client-certificate verdict aborts with bad_certificate');
end;

class function TTestAsyncVerdict.TakePeerAlert(const AEngine: ITlsEngine;
  out AAlert: TTlsAlertDescription): Boolean;
var
  LEvent: ITlsEvent;
  LAlertEvent: IPeerAlertEvent;
begin
  Result := False;
  AAlert := TTlsAlertDescription.BadCertificate;
  while AEngine.NextEvent(LEvent) do
    if (LEvent.Kind = TTlsEventKind.PeerAlert) and
      Supports(LEvent, IPeerAlertEvent, LAlertEvent) and
      LAlertEvent.Alert.HasKnownDescription then
    begin
      AAlert := LAlertEvent.Alert.Description;
      Exit(True);
    end;
end;

procedure TTestAsyncVerdict.TestRejectWithRevokedAlertReachesPeer;
var
  LClient, LServer: ITlsEngine;
  LAlert: TTlsAlertDescription;
begin
  // a definitive live-revocation reject aborts with certificate_revoked, and that
  // exact alert must reach the peer on the wire - not the generic bad_certificate
  LClient := NewClient(ClientConfig(True, 0), 'localhost', LServer);
  LClient.StartHandshake;
  DriveUntilParkOrSettled(LClient, LServer);
  CheckTrue(LClient.AwaitingCertificateVerdict, 'the client should be parked');

  LClient.SetCertificateVerdict(False, TTlsAlertDescription.CertificateRevoked);

  CheckTrue(LClient.IsTerminal, 'a revoked verdict aborts the handshake (fail-closed)');
  CheckEquals(Int64(Ord(TTlsAlertDescription.CertificateRevoked)),
    Int64(Ord(LClient.LastError.Alert.Description)),
    'the client emits certificate_revoked');
  // the alert record reaches the server as a peer fatal alert carrying certificate_revoked
  PumpOneWay(LClient, LServer);
  CheckTrue(TakePeerAlert(LServer, LAlert), 'the server receives a peer fatal alert');
  CheckEquals(Int64(Ord(TTlsAlertDescription.CertificateRevoked)), Int64(Ord(LAlert)),
    'the wire alert the peer receives is certificate_revoked');
end;

procedure TTestAsyncVerdict.TestServerRejectWithRevokedAlertReachesPeer;
var
  LClient, LServer: ITlsEngine;
  LAlert: TTlsAlertDescription;
begin
  // the symmetric server-side path: a server rejecting a live-revoked client certificate
  // aborts with certificate_revoked and the client receives that exact alert
  LClient := NewMtls(True, LServer);
  LClient.StartHandshake;
  DriveUntilParkOrSettled(LClient, LServer);
  CheckTrue(LServer.AwaitingCertificateVerdict, 'the server should be parked');

  LServer.SetCertificateVerdict(False, TTlsAlertDescription.CertificateRevoked);

  CheckTrue(LServer.IsTerminal, 'a revoked client-cert verdict aborts (fail-closed)');
  CheckEquals(Int64(Ord(TTlsAlertDescription.CertificateRevoked)),
    Int64(Ord(LServer.LastError.Alert.Description)),
    'the server emits certificate_revoked');
  PumpOneWay(LServer, LClient);
  CheckTrue(TakePeerAlert(LClient, LAlert), 'the client receives a peer fatal alert');
  CheckEquals(Int64(Ord(TTlsAlertDescription.CertificateRevoked)), Int64(Ord(LAlert)),
    'the wire alert the peer receives is certificate_revoked');
end;

procedure TTestAsyncVerdict.TestServerHardClientRevocationParksThenRevokedTls13;
var
  LClient, LServer: ITlsEngine;
  LForce12: Boolean;
begin
  // TLS 1.3 mutual TLS, server on Hard client-cert revocation + an async resolver: the client
  // cert carries no staple, so a Hard server would reject inline UNLESS it defers to the
  // resolver. It must PARK (deferred), then a revoked verdict aborts with certificate_revoked.
  LForce12 := False;
  LClient := NewHardMtls(LForce12, LServer);
  LClient.StartHandshake;
  DriveUntilParkOrSettled(LClient, LServer);
  CheckTrue(LServer.AwaitingCertificateVerdict,
    'Hard client-cert revocation must defer the unstapled cert to the resolver (park)');
  CheckFalse(LServer.IsTerminal, 'the server must not have inline-rejected under Hard');

  LServer.SetCertificateVerdict(False, TTlsAlertDescription.CertificateRevoked);
  CheckTrue(LServer.IsTerminal, 'a revoked verdict aborts (fail-closed)');
  CheckEquals(Int64(Ord(TTlsAlertDescription.CertificateRevoked)),
    Int64(Ord(LServer.LastError.Alert.Description)),
    'the server emits certificate_revoked');
end;

procedure TTestAsyncVerdict.TestServerHardClientRevocationParksThenRevokedTls12;
var
  LClient, LServer: ITlsEngine;
  LForce12: Boolean;
begin
  // the same, pinned to TLS 1.2 - the 1.2 server machine parks on the client-chain verdict too
  LForce12 := True;
  LClient := NewHardMtls(LForce12, LServer);
  LClient.StartHandshake;
  DriveUntilParkOrSettled(LClient, LServer);
  CheckTrue(LServer.AwaitingCertificateVerdict,
    'Hard client-cert revocation must defer the unstapled cert to the resolver (park)');
  CheckFalse(LServer.IsTerminal, 'the server must not have inline-rejected under Hard');

  LServer.SetCertificateVerdict(False, TTlsAlertDescription.CertificateRevoked);
  CheckTrue(LServer.IsTerminal, 'a revoked verdict aborts (fail-closed)');
  CheckEquals(Int64(Ord(TTlsAlertDescription.CertificateRevoked)),
    Int64(Ord(LServer.LastError.Alert.Description)),
    'the server emits certificate_revoked');
end;

procedure TTestAsyncVerdict.TestPumpWriteAfterTerminalReportsTheRecordedAlert;
var
  LClient, LServer: ITlsEngine;
  LRead: TMemoryPipe;
  LTransport: ITlsTransport;
  LTransportBuffer: TBytes;
  LAlert: TTlsAlertDescription;
  LFailed: Boolean;
begin
  LClient := NewClient(ClientConfig(False, 0), 'localhost', LServer);
  LClient.StartHandshake;
  DriveToCompletion(LClient, LServer);
  LRead := TMemoryPipe.Create;
  try
    LTransport := TMemoryTransport.Create(LRead, TMemoryPipe.Create);
    LClient.SendAlert(TTlsAlertDescription.HandshakeFailure);
    // a write on an engine that already recorded a fatal alert reports that alert, not a generic
    // closed-write error
    LFailed := False;
    LAlert := TTlsAlertDescription.CloseNotify;
    try
      TTlsStreamPump.WriteApp(LClient, LTransport, LTransportBuffer, DecodeHex('01'), 0, 1);
    except
      on E: ETlsStreamError do
      begin
        LFailed := True;
        if E.HasAlert then
          LAlert := E.Alert;
      end;
    end;
    CheckTrue(LFailed, 'the write fails');
    CheckTrue(LAlert = TTlsAlertDescription.HandshakeFailure,
      'with the alert the engine recorded');
  finally
    LTransport := nil;
    LRead.Free;
  end;
end;

procedure TTestAsyncVerdict.TestPumpReportsTheVerdictRejectReason;
var
  LClient, LServer: ITlsEngine;
  LRead: TMemoryPipe;
  LTransport: ITlsTransport;
  LTransportBuffer: TBytes;
  LMessage: string;
  LForce12: Boolean;
begin
  LForce12 := False;
  LClient := NewHardMtls(LForce12, LServer);
  LClient.StartHandshake;
  DriveUntilParkOrSettled(LClient, LServer);
  CheckTrue(LServer.AwaitingCertificateVerdict, 'the server parked on the client chain');
  LServer.SetCertificateVerdict(False, TTlsAlertDescription.BadCertificate);
  LRead := TMemoryPipe.Create;
  try
    LTransport := TMemoryTransport.Create(LRead, TMemoryPipe.Create);
    LMessage := '';
    try
      TTlsStreamPump.WriteApp(LServer, LTransport, LTransportBuffer, DecodeHex('01'), 0, 1);
    except
      on E: ETlsStreamError do
        LMessage := E.Message;
    end;
    CheckEquals('the peer certificate was rejected by the host''s verdict', LMessage,
      'the pump error carries the verdict reject reason');
  finally
    LTransport := nil;
    LRead.Free;
  end;
end;

procedure TTestAsyncVerdict.TestPumpAbortSendsTheFatalAlertToThePeer;
var
  LClient, LServer: ITlsEngine;
  LRead, LWrite: TMemoryPipe;
  LTransport: ITlsTransport;
  LWire, LTransportBuffer: TBytes;
  LGot: Int32;
begin
  LClient := NewClient(ClientConfig(False, 0), 'localhost', LServer);
  LClient.StartHandshake;
  DriveToCompletion(LClient, LServer);
  LRead := TMemoryPipe.Create;
  LWrite := TMemoryPipe.Create;
  try
    LTransport := TMemoryTransport.Create(LRead, LWrite);
    // a host that refuses the peer once the handshake finished sends bad_certificate, not a clean
    // close
    TTlsStreamPump.Abort(LClient, LTransport, LTransportBuffer,
      TTlsAlertDescription.BadCertificate);
    CheckTrue(LClient.IsTerminal, 'the engine is terminal');
    LWire := nil;
    SetLength(LWire, 4096);
    // closing first makes a missing flush read as empty instead of blocking the suite
    LWrite.Close;
    LGot := LWrite.Read(LWire, 0, System.Length(LWire));
    CheckTrue(LGot > 0, 'the alert reached the transport');
    LServer.ProcessInput(LWire, 0, LGot);
    CheckTrue(LServer.IsTerminal, 'the peer aborts');
    CheckTrue(LServer.LastError.Alert.Description = TTlsAlertDescription.BadCertificate,
      'with the bad_certificate it was sent');
  finally
    LTransport := nil;
    LRead.Free;
  end;
end;

procedure TTestAsyncVerdict.TestPumpDrainEventsReportsPeerFatalAlertWithoutRaising;
var
  LClient, LServer: ITlsEngine;
  LAlert: IPeerAlertEvent;
  LClosed: Boolean;
  LCert: ICertificateReceivedEvent;
begin
  LClient := NewClient(ClientConfig(False, 0), 'localhost', LServer);
  LClient.StartHandshake;
  DriveToCompletion(LClient, LServer);
  CheckFalse(LClient.IsHandshaking, 'the handshake completes');
  // the server sends a fatal alert; the shared classifier reports it and never raises
  LServer.SendAlert(TTlsAlertDescription.HandshakeFailure);
  PumpOneWay(LServer, LClient);
  CheckTrue(TTlsStreamPump.DrainEvents(LClient, LAlert, LClosed, LCert),
    'a peer fatal alert is a terminal event');
  CheckTrue(LAlert <> nil, 'the peer alert is reported, not raised');
  CheckFalse(LClosed, 'a fatal alert is not a clean close');
  CheckEquals(Int64(Ord(TTlsAlertDescription.HandshakeFailure)),
    Int64(Ord(LAlert.Alert.Description)),
    'the reported alert carries the peer''s description');
end;

procedure TTestAsyncVerdict.TestPumpDrainEventsReportsCloseNotify;
var
  LClient, LServer: ITlsEngine;
  LAlert: IPeerAlertEvent;
  LClosed: Boolean;
  LCert: ICertificateReceivedEvent;
begin
  LClient := NewClient(ClientConfig(False, 0), 'localhost', LServer);
  LClient.StartHandshake;
  DriveToCompletion(LClient, LServer);
  CheckFalse(LClient.IsHandshaking, 'the handshake completes');
  LServer.SendClose;
  PumpOneWay(LServer, LClient);
  CheckTrue(TTlsStreamPump.DrainEvents(LClient, LAlert, LClosed, LCert),
    'a peer close_notify is a terminal event');
  CheckTrue(LAlert = nil, 'a clean close is not a peer alert');
  CheckTrue(LClosed, 'the peer close_notify is reported');
  CheckTrue(LClient.IsInboundClosed, 'the engine records the inbound close');
end;

procedure TTestAsyncVerdict.TestPumpResolveVerdictWithoutResolverFailsClosed;
var
  LClient, LServer: ITlsEngine;
  LEvent: ICertificateReceivedEvent;
begin
  LClient := NewClient(ClientConfig(True, 0), 'localhost', LServer);
  LClient.StartHandshake;
  DriveUntilParkOrSettled(LClient, LServer);
  CheckTrue(TakeCertificateEvent(LClient, LEvent),
    'the park raised the peer-certificate event');
  // the client verifies the server's chain: with no resolver the shared verdict fails closed
  TTlsStreamPump.ResolveVerdict(LClient, LEvent, nil, TPeerRole.Server);
  CheckTrue(LClient.IsTerminal, 'a nil resolver fails the parked verdict closed');
  CheckEquals(Int64(Ord(TTlsAlertDescription.CertificateUnknown)),
    Int64(Ord(LClient.LastError.Alert.Description)),
    'the fail-closed abort is certificate_unknown');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestAsyncVerdict);
{$ELSE}
  RegisterTest(TTestAsyncVerdict.Suite);
{$ENDIF FPC}

end.
