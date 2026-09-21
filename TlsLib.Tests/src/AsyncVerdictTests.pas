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
  Classes,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  TlpTlsAlert,
  TlpTlsVersion,
  TlpTlsCredential,
  TlpITlsConfig,
  TlpITlsConfigBuilder,
  TlpTlsPresets,
  TlpTrustPolicy,
  TlpITlsEngine,
  TlpTlsEngineFactory,
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
    function TrustRoot: TBytes;
    function LeafCert: TBytes;
    function LeafKey: TBytes;
    function ClientConfig(AAsync: Boolean; ADeadlineMs: Cardinal): ITlsClientConfig;
    function ServerConfig: ITlsServerConfig;
    function MtlsClientConfig: ITlsClientConfig;
    function MtlsServerConfig(AAsync: Boolean): ITlsServerConfig;
    function OcspVec(const AName: string): TBytes;
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
  published
    procedure TestParkThenAcceptCompletes;
    procedure TestCertificateReceivedEventCarriesLeaf;
    procedure TestRejectFailsClosedWithBadCertificate;
    procedure TestParkedResumeOntoBadRecordFailsClosedNotRaise;
    procedure TestNoVerdictNeverCompletes;
    procedure TestResolverTimeoutRejectFailsClosed;
    procedure TestAcceptCannotResurrectPipelineRejectedChain;
    procedure TestDisabledResolvesInlineNoPark;
    procedure TestServerParkThenAcceptCompletes;
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
    procedure TestServerRejectFailsClosedWithBadCertificate;
    procedure TestRejectWithRevokedAlertReachesPeer;
    procedure TestServerRejectWithRevokedAlertReachesPeer;
    // server-side Hard client-cert revocation, end to end, both TLS versions: the Hard verifier
    // DEFERS the never-stapled client cert to the resolver (parks, not inline-reject), then a
    // revoked verdict aborts with certificate_revoked
    procedure TestServerHardClientRevocationParksThenRevokedTls13;
    procedure TestServerHardClientRevocationParksThenRevokedTls12;
  end;

implementation

{ TTestAsyncVerdict }

function TTestAsyncVerdict.TrustRoot: TBytes;
var
  LV: TStringList;
begin
  LV := LoadVectorFields('Certs/ClientAuthChain.txt');
  try
    Result := DecodeHex(LV.Values['root_cert']);
  finally
    LV.Free;
  end;
end;

function TTestAsyncVerdict.LeafCert: TBytes;
var
  LV: TStringList;
begin
  LV := LoadVectorFields('Certs/ClientAuthChain.txt');
  try
    Result := DecodeHex(LV.Values['leaf_cert']);
  finally
    LV.Free;
  end;
end;

function TTestAsyncVerdict.LeafKey: TBytes;
var
  LV: TStringList;
begin
  LV := LoadVectorFields('Certs/ClientAuthChain.txt');
  try
    Result := DecodeHex(LV.Values['leaf_key']);
  finally
    LV.Free;
  end;
end;

function TTestAsyncVerdict.ClientConfig(AAsync: Boolean;
  ADeadlineMs: Cardinal): ITlsClientConfig;
var
  LClient: ITlsClientConfigBuilder;
begin
  LClient := TTlsPresets.Compatible(Provider).Client.WithTrustAnchors(TrustRoot);
  if AAsync then
    LClient.WithAsyncCertificateVerdict(True, ADeadlineMs);
  Result := LClient.Build;
end;

function TTestAsyncVerdict.ServerConfig: ITlsServerConfig;
begin
  Result := TTlsPresets.Compatible(Provider).Server
    .WithCredential(LeafCert, LeafKey).Build;
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
  Result := TTlsPresets.Compatible(Provider).Client
    .WithTrustAnchors(TrustRoot)
    .WithCredential(LeafCert, LeafKey).Build;
end;

function TTestAsyncVerdict.MtlsServerConfig(AAsync: Boolean): ITlsServerConfig;
var
  LServer: ITlsServerConfigBuilder;
begin
  LServer := TTlsPresets.Compatible(Provider).Server
    .WithCredential(LeafCert, LeafKey)
    .WithTrustAnchors(TrustRoot)
    .WithPeerAuth(TClientAuthMode.Required);
  if AAsync then
    LServer.WithAsyncCertificateVerdict(True, 0);
  Result := LServer.Build;
end;

function TTestAsyncVerdict.OcspVec(const AName: string): TBytes;
var
  LV: TStringList;
begin
  LV := LoadVectorFields('Certs/OcspStapling.txt');
  try
    Result := DecodeHex(LV.Values[AName]);
  finally
    LV.Free;
  end;
end;

function TTestAsyncVerdict.StapledServer(const AStaple: TBytes): ITlsEngine;
var
  LCred: TTlsCredential;
begin
  // present the leaf + its issuer, and seal the OCSP staple on the credential so the server sends
  // a CertificateStatus when the client requests one
  LCred.CertificateChain := TArray<TBytes>.Create(OcspVec('leaf_cert'), OcspVec('issuer_cert'));
  LCred.PrivateKey := Provider.Signing.ImportSigningKey(OcspVec('leaf_key'));
  LCred.OcspStaple := AStaple;
  Result := TTlsEngineFactory.CreateServerEngine(
    TTlsPresets.Compatible(Provider).Server.WithCredential(LCred).Build);
end;

function TTestAsyncVerdict.StaplingRevocationClient(AHostDecision: Boolean;
  out AServer: ITlsEngine; const AStaple: TBytes): ITlsEngine;
var
  LClient: ITlsClientConfigBuilder;
begin
  // request a staple and require revocation; the host check is disabled so the test isolates the
  // revocation park from the leaf's SAN identity
  LClient := TTlsPresets.Compatible(Provider).Client
    .WithTrustAnchors(OcspVec('root_cert'))
    .WithDangerousDisableServerNameCheck
    .WithOcspStaplingRequest(True)
    .WithRevocation(TRevocationPosture.Hard);
  if AHostDecision then
    LClient.WithAsyncCertificateVerdict(True, 0)
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
  LClientOwner := TTlsPresets.Compatible(Provider);
  LClient := LClientOwner.Client
    .WithSupportedVersions(LVer)
    .WithTrustAnchors(TrustRoot)
    .WithCredential(LeafCert, LeafKey);
  LClientCfg := LClient.Build;

  LServerOwner := TTlsPresets.Compatible(Provider);
  LServer := LServerOwner.Server
    .WithSupportedVersions(LVer)
    .WithCredential(LeafCert, LeafKey)
    .WithTrustAnchors(TrustRoot)
    .WithPeerAuth(TClientAuthMode.Required)
    .WithRevocation(TRevocationPosture.Hard)
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

  LClient.SetCertificateVerdict(True);
  DriveToCompletion(LClient, LServer);

  CheckFalse(LClient.IsTerminal, 'the accepted handshake must not be terminal');
  CheckFalse(LClient.IsHandshaking, 'the accepted client handshake must complete');
  CheckFalse(LServer.IsHandshaking, 'the server handshake must complete');
  CheckFalse(LClient.AwaitingCertificateVerdict,
    'the verdict was resolved, so nothing is awaited');
  CheckEquals(Int64(TlsWireVersionTls13),
    Int64(LClient.NegotiatedVersion.WireValue),
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
  CheckTrue(AreEqual(LeafCert, LChain[0]),
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

  LClient.SetCertificateVerdict(False);

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
  // exception escape SetCertificateVerdict with no alert on the wire (regression guard for BL-7).
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
  LClient.SetCertificateVerdict(True);

  CheckTrue(LClient.IsTerminal,
    'a bad record behind the resumed flight aborts the engine instead of escaping as an exception');
  CheckEquals(Int64(Ord(TTlsAlertDescription.BadRecordMac)),
    Int64(Ord(LClient.LastError.Alert.Description)),
    'the undecryptable record aborts with bad_record_mac');
  CheckTrue(LClient.WantsWrite, 'the fatal alert is queued for the peer');
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
  // SetCertificateVerdict(False) - fail-closed (the engine owns no timer)
  LClient := NewClient(ClientConfig(True, 1), 'localhost', LServer);
  LClient.StartHandshake;
  DriveUntilParkOrSettled(LClient, LServer);
  CheckTrue(LClient.AwaitingCertificateVerdict, 'the client should be parked');

  LClient.SetCertificateVerdict(False); // the resolver's timeout action

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
  LClient.SetCertificateVerdict(True);
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

  LServer.SetCertificateVerdict(True);
  DriveToCompletion(LClient, LServer);

  CheckFalse(LServer.IsTerminal, 'the accepted server handshake must not be terminal');
  CheckFalse(LServer.IsHandshaking, 'the server handshake must complete');
  CheckFalse(LClient.IsHandshaking, 'the client handshake must complete');
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
  CheckTrue(AreEqual(LeafCert, LPresented[0]), 'the presented chain leaf is the client leaf');
  CheckTrue(System.Length(LValidated) >= 2,
    'the validated path carries the assembled issuer, not just the leaf');
  CheckTrue(AreEqual(LeafCert, LValidated[0]), 'the validated path leaf is the client leaf');
  CheckTrue(AreEqual(TrustRoot, LValidated[System.High(LValidated)]),
    'the validated path terminates at the configured trust anchor');
end;

procedure TTestAsyncVerdict.TestGoodStapleLiveRevocationSkipsPark;
var
  LClient, LServer: ITlsEngine;
  LEvent: ICertificateReceivedEvent;
begin
  // under live-revocation, a current Good staple settles revocation inline, so the redundant live
  // park is skipped: the client never awaits a verdict and completes the handshake
  LClient := StaplingRevocationClient({AHostDecision=} False, LServer, OcspVec('ocsp_good'));
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
begin
  // the same client with no staple: revocation is indeterminate and deferred, so the park runs -
  // proving the skip is gated on the settled staple, not on the live-revocation mode itself
  LClient := StaplingRevocationClient({AHostDecision=} False, LServer, nil);
  LClient.StartHandshake;
  DriveUntilParkOrSettled(LClient, LServer);

  CheckTrue(LClient.AwaitingCertificateVerdict,
    'an unstapled live-revocation client parks for the live check');
end;

procedure TTestAsyncVerdict.TestGoodStapleHostDecisionStillParks;
var
  LClient, LServer: ITlsEngine;
begin
  // a host-decision park is a separate policy (prompt on every accepted peer): a Good staple never
  // skips it
  LClient := StaplingRevocationClient({AHostDecision=} True, LServer, OcspVec('ocsp_good'));
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

procedure TTestAsyncVerdict.TestServerRejectFailsClosedWithBadCertificate;
var
  LClient, LServer: ITlsEngine;
begin
  LClient := NewMtls(True, LServer);
  LClient.StartHandshake;
  DriveUntilParkOrSettled(LClient, LServer);
  CheckTrue(LServer.AwaitingCertificateVerdict, 'the server should be parked');

  LServer.SetCertificateVerdict(False);

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
begin
  // TLS 1.3 mutual TLS, server on Hard client-cert revocation + an async resolver: the client
  // cert carries no staple, so a Hard server would reject inline UNLESS it defers to the
  // resolver. It must PARK (deferred), then a revoked verdict aborts with certificate_revoked.
  LClient := NewHardMtls({AForce12=} False, LServer);
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
begin
  // the same, pinned to TLS 1.2 - the 1.2 server machine parks on the client-chain verdict too
  LClient := NewHardMtls({AForce12=} True, LServer);
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

initialization

{$IFDEF FPC}
  RegisterTest(TTestAsyncVerdict);
{$ELSE}
  RegisterTest(TTestAsyncVerdict.Suite);
{$ENDIF FPC}

end.
