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
    procedure TestDeadlineSurfacedToDriver;
    procedure TestRejectFailsClosedWithBadCertificate;
    procedure TestNoVerdictNeverCompletes;
    procedure TestDeadlineExpiryFailsClosed;
    procedure TestAcceptCannotResurrectPipelineRejectedChain;
    procedure TestDisabledResolvesInlineNoPark;
    procedure TestServerParkThenAcceptCompletes;
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
  LV := LoadVectorFields('Certs/EcP256Chain.txt');
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
  LV := LoadVectorFields('Certs/EcP256Chain.txt');
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
  LV := LoadVectorFields('Certs/EcP256Chain.txt');
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
    .WithAsyncCertificateVerdict(True, 0);
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

procedure TTestAsyncVerdict.TestDeadlineSurfacedToDriver;
var
  LClient, LServer: ITlsEngine;
begin
  LClient := NewClient(ClientConfig(True, 2500), 'localhost', LServer);
  CheckEquals(Int64(2500), Int64(LClient.AsyncCertificateVerdictDeadlineMs),
    'the configured deadline is surfaced to the driver');
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

procedure TTestAsyncVerdict.TestDeadlineExpiryFailsClosed;
var
  LClient, LServer: ITlsEngine;
begin
  // the driver enforces the deadline (the engine owns no timer); on expiry it calls the
  // verdict path with a failure. That path is SetCertificateVerdict(False) - fail-closed.
  LClient := NewClient(ClientConfig(True, 1), 'localhost', LServer);
  LClient.StartHandshake;
  DriveUntilParkOrSettled(LClient, LServer);
  CheckTrue(LClient.AwaitingCertificateVerdict, 'the client should be parked');

  LClient.SetCertificateVerdict(False); // the driver's deadline-expiry action

  CheckTrue(LClient.IsTerminal, 'an expired deadline aborts the handshake (fail-closed)');
  CheckEquals(Int64(Ord(TTlsAlertDescription.BadCertificate)),
    Int64(Ord(LClient.LastError.Alert.Description)),
    'a deadline expiry aborts with bad_certificate');
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
  CheckEquals(Int64(0), Int64(LClient.AsyncCertificateVerdictDeadlineMs),
    'a disabled async verdict surfaces no deadline');
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
