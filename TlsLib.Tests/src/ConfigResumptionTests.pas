{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ConfigResumptionTests;

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
  TlpTlsVersion,
  TlpICryptoProvider,
  TlpICertificateTrust,
  TlpCertificateVerifier,
  TlpServerName,
  TlpTlsAlert,
  TlpTrustPolicy,
  TlpTlsCredential,
  TlpISession,
  TlpInMemorySessionCache,
  TlpInMemorySessionStore,
  TlpITlsConfig,
  TlpITlsConfigBuilder,
  TlpTlsPresets,
  TlpTlsEngineFactory,
  TlpITlsEngine,
  TlsLibTestBase;

type
  TTestConfigResumption = class(TTlsLibAlgorithmTestCase)
  private
  const
    ServerHost = 'localhost';
  var
    FCerts: TStringList;
    FOcsp: TStringList;
    function ServerCredential: TTlsCredential;
    function ClientTrust: ITrustAnchorStore;
    /// <summary>One field of the OCSP-stapling fixture (root/issuer/leaf certs, leaf key and the
    /// Good OCSP response).</summary>
    function OcspField(const AName: string): TBytes;
    /// <summary>The stapling server credential: leaf + issuer with a current Good OCSP response
    /// sealed on it, so a staple-requesting client completes a full handshake under a Hard posture.</summary>
    function StaplingCredential: TTlsCredential;
    /// <summary>A TLS 1.3 stapling server that issues AIssueTickets resumable tickets.</summary>
    function NewStaplingServer13(const AStore: ISessionStore;
      AIssueTickets: Int32): ITlsEngine;
    /// <summary>A TLS 1.2 stapling server that resumes by default.</summary>
    function NewStaplingServer12(const AStore: ISessionStore): ITlsEngine;
    /// <summary>A permissive (default Soft) TLS 1.3 client that trusts the stapling root and seeds
    /// the cache.</summary>
    function NewStaplingSeedClient13(const ACache: ISessionCache;
      const AScope: TBytes): ITlsEngine;
    /// <summary>The TLS 1.2 seed client twin.</summary>
    function NewStaplingSeedClient12(const ACache: ISessionCache;
      const AScope: TBytes): ITlsEngine;
    /// <summary>A Hard + Reverify TLS 1.3 client with the given verdict deferral: LiveRevocation
    /// still offers resumption, None / HostDecision are withheld by the engine factory.</summary>
    function NewHardReverifyClient13(const ACache: ISessionCache;
      const AScope: TBytes; ADeferral: TVerdictDeferral): ITlsEngine;
    /// <summary>The TLS 1.2 Hard + Reverify client twin.</summary>
    function NewHardReverifyClient12(const ACache: ISessionCache;
      const AScope: TBytes; ADeferral: TVerdictDeferral): ITlsEngine;
    /// <summary>A Hard + ReuseOriginal TLS 1.3 client: it never re-verifies on resume, so the
    /// gate leaves resumption offered.</summary>
    function NewHardReuseOriginalClient13(const ACache: ISessionCache;
      const AScope: TBytes): ITlsEngine;
    /// <summary>A TLS 1.3 client engine built through the public config surface. A non-empty
    /// AScope opts the config into sharing sessions with configs given the same scope.</summary>
    function NewClient13(const ACache: ISessionCache; AResumption: Boolean;
      const AScope: TBytes = nil): ITlsEngine;
    /// <summary>A TLS 1.3 client whose server-cert verifier rejects every chain (a strict config).</summary>
    function NewRejectingClient13(const ACache: ISessionCache): ITlsEngine;
    /// <summary>Like NewRejectingClient13 but with Reverify, so it re-checks a resumed server.</summary>
    function NewReverifyRejectClient13(const ACache: ISessionCache;
      const AScope: TBytes = nil): ITlsEngine;
    /// <summary>A permissive client with Reverify + async verdict: the resumption handshake
    /// re-checks inline (accepts) then parks at ServerFinished for the out-of-band verdict.</summary>
    function NewReverifyAsyncClient13(const ACache: ISessionCache;
      const AScope: TBytes = nil): ITlsEngine;
    /// <summary>A TLS 1.3 server engine; AIssueTickets tickets, resumption toggle.</summary>
    function NewServer13(const AStore: ISessionStore; AIssueTickets: Int32;
      AResumption: Boolean): ITlsEngine;
    function NewClient12(const ACache: ISessionCache;
      const AScope: TBytes = nil): ITlsEngine;
    /// <summary>A permissive TLS 1.2 client with Reverify + async verdict: the abbreviated
    /// resumption handshake re-checks inline (accepts) then parks at the abbreviated
    /// ServerFinished for the out-of-band verdict.</summary>
    function NewReverifyAsyncClient12(const ACache: ISessionCache;
      const AScope: TBytes = nil): ITlsEngine;
    function NewServer12(const AStore: ISessionStore): ITlsEngine;
    function Drain(const AEngine: ITlsEngine): TBytes;
    procedure Feed(const AEngine: ITlsEngine; const AWire: TBytes);
    procedure Pump(const ASrc, ADst: ITlsEngine);
    procedure PumpToCompletion(const AClient, AServer: ITlsEngine);
    /// <summary>Like PumpToCompletion but resolves a parked peer-certificate verdict with
    /// AAccept/AAlert, so the async park (initial-cert or reverify-on-resume) can proceed.</summary>
    procedure PumpToCompletionResolving(const AClient, AServer: ITlsEngine;
      AAccept: Boolean; AAlert: TTlsAlertDescription);
    function ReadAllApp(const AEngine: ITlsEngine): TBytes;
    procedure CheckAppDataFlows(const AClient, AServer: ITlsEngine);
    /// <summary>Whether a plaintext handshake flight carries a Certificate (type 11):
    /// present in a full TLS 1.2 handshake, absent in an abbreviated one.</summary>
    function FlightHasCertificate(const AWire: TBytes): Boolean;
    /// <summary>Runs to completion, returning whether the server's first flight carried a
    /// plaintext Certificate (TLS 1.2 full-vs-abbreviated tell).</summary>
    function DriveObservingServerCert(const AClient, AServer: ITlsEngine): Boolean;
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestTls13StoreResumptionViaConfig;
    procedure TestTls12ResumptionViaConfig;
    procedure TestDefaultServerIssuesTicketsOutOfBox;
    procedure TestResumptionOffServerIssuesNoTicket;
    procedure TestStrictPresetLeavesResumptionOff;
    procedure TestStrictResumptionReEnabledWithNoGuard;
    procedure TestSharedCacheDoesNotResumeAcrossConfigurations;
    procedure TestSharedCacheDoesNotResumeAcrossConfigurationsTls12;
    procedure TestSharedSessionScopeResumesAcrossRebuiltConfigs;
    procedure TestReverifyOnResumeRejectsUntrustedServer;
    procedure TestReverifyOnResumeAsyncParkAcceptsCompletes;
    procedure TestReverifyOnResumeAsyncParkRejectAborts;
    procedure TestExporterWithheldDuringReverifyPark;
    procedure TestTls12ReverifyOnResumeAsyncParkAcceptsCompletes;
    procedure TestTls12ReverifyOnResumeAsyncParkRejectAborts;
    procedure TestTls12ReverifyOnResumeExporterWithheld;
    // invariants that must not move: a resume that CAN obtain a fresh revocation verdict, or that
    // never re-verifies, still resumes exactly as before (guards against widening the gate)
    procedure TestHardReverifyWithLiveVerdictStillResumes;
    procedure TestTls12HardReverifyWithLiveVerdictStillResumes;
    procedure TestHardReuseOriginalStillResumes;
    procedure TestSoftReverifyWithoutLiveVerdictStillResumes;
    // the fallback: a Hard + Reverify client with no live-revocation channel withholds the
    // resumption offer and performs a full handshake (which can staple) instead of aborting it
    procedure TestHardReverifyWithoutLiveVerdictFallsBackToFullHandshake;
    procedure TestHardReverifyHostDecisionFallsBackToFullHandshake;
    procedure TestTls12HardReverifyWithoutLiveVerdictFallsBackToFullHandshake;
  end;

implementation

type
  // a whole-verifier that rejects every server chain (stands in for a strict pin / custom verifier)
  TRejectingServerVerifier = class(TInterfacedObject, IServerCertificateVerifier)
  public
    function VerifyServerCertificate(const AChain: TArray<TBytes>;
      const AServerName: TServerName; const AOcspStaple: TBytes;
      out AVerified: TVerifiedChain;
      out AAlert: TTlsAlertDescription): Boolean;
  end;

function TRejectingServerVerifier.VerifyServerCertificate(const AChain: TArray<TBytes>;
  const AServerName: TServerName; const AOcspStaple: TBytes;
  out AVerified: TVerifiedChain;
  out AAlert: TTlsAlertDescription): Boolean;
begin
  AVerified := Default(TVerifiedChain);
  AAlert := TTlsAlertDescription.BadCertificate;
  Result := False;
end;

{ TTestConfigResumption }

procedure TTestConfigResumption.SetUp;
begin
  inherited SetUp;
  FCerts := LoadVectorFields('Certs/EcP256Chain.txt');
  FOcsp := LoadVectorFields('Certs/OcspStapling.txt');
end;

procedure TTestConfigResumption.TearDown;
begin
  FOcsp.Free;
  FCerts.Free;
  inherited TearDown;
end;

function TTestConfigResumption.OcspField(const AName: string): TBytes;
begin
  Result := DecodeHex(FOcsp.Values[AName]);
end;

function TTestConfigResumption.StaplingCredential: TTlsCredential;
begin
  // leaf + issuer, with a current Good OCSP response sealed on the credential so the server
  // sends a CertificateStatus when the client requests one
  Result.CertificateChain := TArray<TBytes>.Create(OcspField('leaf_cert'),
    OcspField('issuer_cert'));
  Result.PrivateKey := Crypto.Signing.ImportSigningKey(OcspField('leaf_key'));
  Result.OcspStaple := OcspField('ocsp_good');
end;

function TTestConfigResumption.NewStaplingServer13(const AStore: ISessionStore;
  AIssueTickets: Int32): ITlsEngine;
var
  LConfig: ITlsServerConfig;
begin
  LConfig := TTlsPresets.Hardened(Crypto, Pkix).Server
    .WithCredential(StaplingCredential)
    .WithResumption(True)
    .WithSessionStore(AStore)
    .WithTicketCount(AIssueTickets)
    .Build;
  Result := TTlsEngineFactory.CreateServerEngine(LConfig);
end;

function TTestConfigResumption.NewStaplingServer12(
  const AStore: ISessionStore): ITlsEngine;
var
  LConfig: ITlsServerConfig;
begin
  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls12))
    .WithCredential(StaplingCredential)
    .WithSessionStore(AStore)
    .Build;
  Result := TTlsEngineFactory.CreateServerEngine(LConfig);
end;

function TTestConfigResumption.NewStaplingSeedClient13(const ACache: ISessionCache;
  const AScope: TBytes): ITlsEngine;
var
  LConfig: ITlsClientConfig;
begin
  // permissive: trusts the stapling root and completes a full handshake, caching the ticket the
  // strict client draws from; the host check is disabled to isolate the resumption behaviour
  LConfig := TTlsPresets.Hardened(Crypto, Pkix).Client
    .WithTrustAnchors(OcspField('root_cert'))
    .WithDangerousDisableServerNameCheck
    .WithResumption(True)
    .WithSessionCache(ACache, AScope)
    .Build;
  Result := TTlsEngineFactory.CreateClientEngine(LConfig, ServerHost);
end;

function TTestConfigResumption.NewStaplingSeedClient12(const ACache: ISessionCache;
  const AScope: TBytes): ITlsEngine;
var
  LConfig: ITlsClientConfig;
begin
  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls12))
    .WithTrustAnchors(OcspField('root_cert'))
    .WithDangerousDisableServerNameCheck
    .WithResumption(True)
    .WithSessionCache(ACache, AScope)
    .Build;
  Result := TTlsEngineFactory.CreateClientEngine(LConfig, ServerHost);
end;

function TTestConfigResumption.NewHardReverifyClient13(const ACache: ISessionCache;
  const AScope: TBytes; ADeferral: TVerdictDeferral): ITlsEngine;
var
  LClient: ITlsClientConfigBuilder;
begin
  LClient := TTlsPresets.Hardened(Crypto, Pkix).Client
    .WithTrustAnchors(OcspField('root_cert'))
    .WithDangerousDisableServerNameCheck
    .WithOcspStaplingRequest(True)
    .WithRevocation(TRevocationPosture.Hard)
    .WithResumeVerification(TResumeVerification.Reverify)
    .WithResumption(True)
    .WithSessionCache(ACache, AScope);
  if ADeferral = TVerdictDeferral.LiveRevocation then
    LClient.WithLiveRevocationVerdict(0)
  else if ADeferral = TVerdictDeferral.HostDecision then
    LClient.WithAsyncCertificateVerdict(True, 0);
  Result := TTlsEngineFactory.CreateClientEngine(LClient.Build, ServerHost);
end;

function TTestConfigResumption.NewHardReverifyClient12(const ACache: ISessionCache;
  const AScope: TBytes; ADeferral: TVerdictDeferral): ITlsEngine;
var
  LClient: ITlsClientConfigBuilder;
begin
  LClient := TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls12))
    .WithTrustAnchors(OcspField('root_cert'))
    .WithDangerousDisableServerNameCheck
    .WithOcspStaplingRequest(True)
    .WithRevocation(TRevocationPosture.Hard)
    .WithResumeVerification(TResumeVerification.Reverify)
    .WithResumption(True)
    .WithSessionCache(ACache, AScope);
  if ADeferral = TVerdictDeferral.LiveRevocation then
    LClient.WithLiveRevocationVerdict(0)
  else if ADeferral = TVerdictDeferral.HostDecision then
    LClient.WithAsyncCertificateVerdict(True, 0);
  Result := TTlsEngineFactory.CreateClientEngine(LClient.Build, ServerHost);
end;

function TTestConfigResumption.NewHardReuseOriginalClient13(
  const ACache: ISessionCache; const AScope: TBytes): ITlsEngine;
var
  LConfig: ITlsClientConfig;
begin
  // Hard posture but the default ReuseOriginal (no re-verify on resume), so the gate never fires
  LConfig := TTlsPresets.Hardened(Crypto, Pkix).Client
    .WithTrustAnchors(OcspField('root_cert'))
    .WithDangerousDisableServerNameCheck
    .WithOcspStaplingRequest(True)
    .WithRevocation(TRevocationPosture.Hard)
    .WithResumption(True)
    .WithSessionCache(ACache, AScope)
    .Build;
  Result := TTlsEngineFactory.CreateClientEngine(LConfig, ServerHost);
end;

function TTestConfigResumption.ServerCredential: TTlsCredential;
begin
  Result.CertificateChain := TArray<TBytes>.Create(DecodeHex(FCerts.Values['leaf_cert']));
  Result.PrivateKey := Crypto.Signing.ImportSigningKey(DecodeHex(FCerts.Values['leaf_key']));
end;

function TTestConfigResumption.ClientTrust: ITrustAnchorStore;
begin
  Result := TTrustAnchorStore.Create(
    TArray<TBytes>.Create(DecodeHex(FCerts.Values['root_cert']))) as ITrustAnchorStore;
end;

function TTestConfigResumption.NewClient13(const ACache: ISessionCache;
  AResumption: Boolean; const AScope: TBytes): ITlsEngine;
var
  LConfig: ITlsClientConfig;
begin
  // Hardened is TLS 1.3-only; the public surface wires the cache and resumption toggle
  LConfig := TTlsPresets.Hardened(Crypto, Pkix).Client
    .WithTrustStore(ClientTrust)
    .WithResumption(AResumption)
    .WithSessionCache(ACache, AScope)
    .Build;
  Result := TTlsEngineFactory.CreateClientEngine(LConfig, ServerHost);
end;

function TTestConfigResumption.NewRejectingClient13(
  const ACache: ISessionCache): ITlsEngine;
var
  LConfig: ITlsClientConfig;
begin
  LConfig := TTlsPresets.Hardened(Crypto, Pkix).Client
    .WithCertificateVerifier(TRejectingServerVerifier.Create as IServerCertificateVerifier)
    .WithResumption(True)
    .WithSessionCache(ACache)
    .Build;
  Result := TTlsEngineFactory.CreateClientEngine(LConfig, ServerHost);
end;

function TTestConfigResumption.NewReverifyRejectClient13(
  const ACache: ISessionCache; const AScope: TBytes): ITlsEngine;
var
  LConfig: ITlsClientConfig;
begin
  LConfig := TTlsPresets.Hardened(Crypto, Pkix).Client
    .WithCertificateVerifier(TRejectingServerVerifier.Create as IServerCertificateVerifier)
    .WithResumption(True)
    .WithResumeVerification(TResumeVerification.Reverify)
    .WithSessionCache(ACache, AScope)
    .Build;
  Result := TTlsEngineFactory.CreateClientEngine(LConfig, ServerHost);
end;

function TTestConfigResumption.NewReverifyAsyncClient13(
  const ACache: ISessionCache; const AScope: TBytes): ITlsEngine;
var
  LConfig: ITlsClientConfig;
begin
  // permissive trust accepts the server chain inline; Reverify + async verdict make the
  // resumption handshake re-check inline (accept) then park at ServerFinished for the verdict
  LConfig := TTlsPresets.Hardened(Crypto, Pkix).Client
    .WithTrustStore(ClientTrust)
    .WithResumption(True)
    .WithResumeVerification(TResumeVerification.Reverify)
    .WithAsyncCertificateVerdict(True, 0)
    .WithSessionCache(ACache, AScope)
    .Build;
  Result := TTlsEngineFactory.CreateClientEngine(LConfig, ServerHost);
end;

function TTestConfigResumption.NewServer13(const AStore: ISessionStore;
  AIssueTickets: Int32; AResumption: Boolean): ITlsEngine;
var
  LConfig: ITlsServerConfig;
begin
  LConfig := TTlsPresets.Hardened(Crypto, Pkix).Server
    .WithCredential(ServerCredential)
    .WithResumption(AResumption)
    .WithSessionStore(AStore)
    .WithTicketCount(AIssueTickets)
    .Build;
  Result := TTlsEngineFactory.CreateServerEngine(LConfig);
end;

function TTestConfigResumption.NewClient12(const ACache: ISessionCache;
  const AScope: TBytes): ITlsEngine;
var
  LConfig: ITlsClientConfig;
begin
  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls12))
    .WithTrustStore(ClientTrust)
    .WithSessionCache(ACache, AScope)
    .Build;
  Result := TTlsEngineFactory.CreateClientEngine(LConfig, ServerHost);
end;

function TTestConfigResumption.NewReverifyAsyncClient12(
  const ACache: ISessionCache; const AScope: TBytes): ITlsEngine;
var
  LConfig: ITlsClientConfig;
begin
  // permissive trust accepts the resumed chain inline; Reverify + async verdict make the
  // abbreviated resumption re-check inline (accept) then park for the out-of-band verdict
  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls12))
    .WithTrustStore(ClientTrust)
    .WithResumption(True)
    .WithResumeVerification(TResumeVerification.Reverify)
    .WithAsyncCertificateVerdict(True, 0)
    .WithSessionCache(ACache, AScope)
    .Build;
  Result := TTlsEngineFactory.CreateClientEngine(LConfig, ServerHost);
end;

function TTestConfigResumption.NewServer12(const AStore: ISessionStore): ITlsEngine;
var
  LConfig: ITlsServerConfig;
begin
  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls12))
    .WithCredential(ServerCredential)
    .WithSessionStore(AStore)
    .Build;
  Result := TTlsEngineFactory.CreateServerEngine(LConfig);
end;

function TTestConfigResumption.Drain(const AEngine: ITlsEngine): TBytes;
var
  LChunk: TBytes;
  LGot: Int32;
begin
  Result := nil;
  SetLength(LChunk, 65536);
  repeat
    LGot := AEngine.TakeOutgoing(LChunk, 0);
    if LGot > 0 then
      Result := ConcatBytes(Result, System.Copy(LChunk, 0, LGot));
  until LGot = 0;
end;

procedure TTestConfigResumption.Feed(const AEngine: ITlsEngine; const AWire: TBytes);
var
  LPos, LLen: Int32;
begin
  LPos := 0;
  while LPos + 5 <= System.Length(AWire) do
  begin
    LLen := (AWire[LPos + 3] shl 8) or AWire[LPos + 4];
    AEngine.ProcessInput(AWire, LPos, 5 + LLen);
    Inc(LPos, 5 + LLen);
  end;
end;

procedure TTestConfigResumption.Pump(const ASrc, ADst: ITlsEngine);
begin
  Feed(ADst, Drain(ASrc));
end;

procedure TTestConfigResumption.PumpToCompletion(const AClient, AServer: ITlsEngine);
var
  LIterations: Int32;
begin
  AClient.StartHandshake;
  LIterations := 0;
  while (AClient.IsHandshaking or AServer.IsHandshaking) and (LIterations < 16) do
  begin
    Pump(AClient, AServer);
    Pump(AServer, AClient);
    Inc(LIterations);
  end;
  // flush any post-handshake NewSessionTicket from the server to the client
  Pump(AServer, AClient);
end;

procedure TTestConfigResumption.PumpToCompletionResolving(const AClient,
  AServer: ITlsEngine; AAccept: Boolean; AAlert: TTlsAlertDescription);
var
  LIterations: Int32;
begin
  AClient.StartHandshake;
  LIterations := 0;
  while (AClient.IsHandshaking or AServer.IsHandshaking) and (LIterations < 16) do
  begin
    // resolve a parked peer-certificate verdict so the client can emit its withheld flight
    if AClient.AwaitingCertificateVerdict then
      AClient.SetCertificateVerdict(AAccept, AAlert);
    Pump(AClient, AServer);
    Pump(AServer, AClient);
    Inc(LIterations);
  end;
  Pump(AServer, AClient);
end;

function TTestConfigResumption.ReadAllApp(const AEngine: ITlsEngine): TBytes;
var
  LChunk: TBytes;
  LGot: Int32;
begin
  Result := nil;
  SetLength(LChunk, 65536);
  repeat
    LGot := AEngine.ReadAppData(LChunk, 0, System.Length(LChunk));
    if LGot > 0 then
      Result := ConcatBytes(Result, System.Copy(LChunk, 0, LGot));
  until LGot = 0;
end;

procedure TTestConfigResumption.CheckAppDataFlows(const AClient, AServer: ITlsEngine);
var
  LFromClient: TBytes;
begin
  LFromClient := DecodeHex('68656c6c6f2066726f6d2074686520636c69656e74');
  AClient.Write(LFromClient, 0, System.Length(LFromClient));
  Pump(AClient, AServer);
  CheckEqualBytes('the server decrypts the client application data', LFromClient,
    ReadAllApp(AServer));
end;

function TTestConfigResumption.FlightHasCertificate(const AWire: TBytes): Boolean;
var
  LPos, LRecLen, LInner, LMsgLen: Int32;
begin
  Result := False;
  LPos := 0;
  while LPos + 5 <= System.Length(AWire) do
  begin
    LRecLen := (AWire[LPos + 3] shl 8) or AWire[LPos + 4];
    // stop at the ChangeCipherSpec: records after it are encrypted and must not be walked
    // as plaintext handshake messages
    if AWire[LPos] = 20 then
      Exit;
    if AWire[LPos] = 22 then
    begin
      LInner := LPos + 5;
      while LInner + 4 <= LPos + 5 + LRecLen do
      begin
        LMsgLen := (AWire[LInner + 1] shl 16) or (AWire[LInner + 2] shl 8) or
          AWire[LInner + 3];
        if AWire[LInner] = 11 then // Certificate
          Exit(True);
        LInner := LInner + 4 + LMsgLen;
      end;
    end;
    Inc(LPos, 5 + LRecLen);
  end;
end;

function TTestConfigResumption.DriveObservingServerCert(
  const AClient, AServer: ITlsEngine): Boolean;
var
  LFlight: TBytes;
  LIterations: Int32;
begin
  AClient.StartHandshake;
  Pump(AClient, AServer);
  LFlight := Drain(AServer);
  Result := FlightHasCertificate(LFlight);
  Feed(AClient, LFlight);
  LIterations := 0;
  while (AClient.IsHandshaking or AServer.IsHandshaking) and (LIterations < 16) do
  begin
    Pump(AClient, AServer);
    Pump(AServer, AClient);
    Inc(LIterations);
  end;
end;

procedure TTestConfigResumption.TestTls13StoreResumptionViaConfig;
var
  LCache: ISessionCache;
  LScope: TBytes;
  LStore: ISessionStore;
  LClient, LServer: ITlsEngine;
begin
  // the public surface: a store-backed 1.3 server issues one stateful ticket; a later
  // handshake resumes it. The store single-use consumption proves the config wired through.
  // One logical client reconnecting keeps its scope, so both connections share it.
  LCache := TInMemorySessionCache.Create;
  LScope := Crypto.Primitives.GetRandom.GenerateBytes(16);
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);

  LClient := NewClient13(LCache, True, LScope);
  LServer := NewServer13(LStore, 1, True);
  PumpToCompletion(LClient, LServer);
  CheckFalse(LClient.IsHandshaking, 'the initial 1.3 handshake completed');
  CheckEquals(1, LStore.Count, 'the server stored one resumable session');
  CheckEquals(1, LCache.Count, 'the client cached the ticket');

  // the resuming server issues no new ticket, so a consumed store proves resumption
  LClient := NewClient13(LCache, True, LScope);
  LServer := NewServer13(LStore, 0, True);
  PumpToCompletion(LClient, LServer);
  CheckFalse(LServer.IsHandshaking, 'the resuming server completed');
  CheckFalse(LServer.IsTerminal, 'the resuming server did not fail');
  CheckEquals(0, LStore.Count, 'the stored session was consumed (resumed via the config)');
  CheckAppDataFlows(LClient, LServer);
end;

procedure TTestConfigResumption.TestTls12ResumptionViaConfig;
var
  LCache: ISessionCache;
  LScope: TBytes;
  LStore: ISessionStore;
  LClient, LServer: ITlsEngine;
begin
  // a TLS 1.2 client and server through the public surface: the second handshake resumes,
  // proven by the abbreviated server flight (no plaintext Certificate). One logical client
  // reconnecting shares its scope across both connections.
  LCache := TInMemorySessionCache.Create;
  LScope := Crypto.Primitives.GetRandom.GenerateBytes(16);
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);

  LClient := NewClient12(LCache, LScope);
  LServer := NewServer12(LStore);
  PumpToCompletion(LClient, LServer);
  CheckFalse(LClient.IsHandshaking, 'the initial 1.2 handshake completed');
  CheckEquals(1, LCache.Count, 'the client cached the 1.2 session');

  LClient := NewClient12(LCache, LScope);
  LServer := NewServer12(LStore);
  CheckFalse(DriveObservingServerCert(LClient, LServer),
    '1.2 resumption via the config is abbreviated (no Certificate)');
  CheckFalse(LServer.IsTerminal, 'the 1.2 resume did not fail');
  CheckAppDataFlows(LClient, LServer);
end;

procedure TTestConfigResumption.TestDefaultServerIssuesTicketsOutOfBox;
var
  LCache: ISessionCache;
  LScope: TBytes;
  LServerConfig: ITlsServerConfig;
  LClient, LServer: ITlsEngine;
begin
  // a server built through the public surface with only a credential - no WithSessionStore and
  // no WithDefaultSessionTicketKeys - resumes out of the box: the resume-by-default posture mints
  // a STEK, so the server issues a ticket the client caches and can later present. One frozen
  // config is reused across both handshakes so the same STEK opens the ticket. One logical client
  // reconnecting shares its scope across both connections.
  LCache := TInMemorySessionCache.Create;
  LScope := Crypto.Primitives.GetRandom.GenerateBytes(16);
  LServerConfig := TTlsPresets.Hardened(Crypto, Pkix).Server
    .WithCredential(ServerCredential).Build;

  LClient := NewClient13(LCache, True, LScope);
  LServer := TTlsEngineFactory.CreateServerEngine(LServerConfig);
  PumpToCompletion(LClient, LServer);
  CheckFalse(LClient.IsHandshaking, 'the initial handshake completed');
  CheckTrue(LCache.Count >= 1, 'the default server issued a ticket the client cached');

  LClient := NewClient13(LCache, True, LScope);
  LServer := TTlsEngineFactory.CreateServerEngine(LServerConfig);
  PumpToCompletion(LClient, LServer);
  CheckFalse(LServer.IsHandshaking, 'the resuming server completed');
  CheckFalse(LServer.IsTerminal, 'the resuming server did not fail');
  // prove it actually resumed via the out-of-box ticket, not a silent full-handshake fallback
  CheckTrue(LClient.ConnectionInfo.Resumed, 'the second handshake resumed off the auto-issued ticket');
  CheckAppDataFlows(LClient, LServer);
end;

procedure TTestConfigResumption.TestResumptionOffServerIssuesNoTicket;
var
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
begin
  // WithResumption(False) opts a server out even under the resume-by-default posture: no STEK is
  // engaged, so no ticket is issued and the client caches nothing
  LCache := TInMemorySessionCache.Create;
  LClient := NewClient13(LCache, True);
  LServer := TTlsEngineFactory.CreateServerEngine(TTlsPresets.Hardened(Crypto, Pkix).Server
    .WithCredential(ServerCredential).WithResumption(False).Build);
  PumpToCompletion(LClient, LServer);
  CheckFalse(LClient.IsHandshaking, 'the handshake completed');
  CheckEquals(0, LCache.Count, 'a resumption-off server issued no ticket');
end;

procedure TTestConfigResumption.TestStrictPresetLeavesResumptionOff;
var
  LCache: ISessionCache;
  LStore: ISessionStore;
  LClient, LServer: ITlsEngine;
begin
  // the Strict preset defaults resumption OFF: even with a cache and store supplied, the
  // factory does not engage them, so nothing is cached or stored
  LCache := TInMemorySessionCache.Create;
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);

  LClient := TTlsEngineFactory.CreateClientEngine(TTlsPresets.Strict(Crypto, Pkix).Client
    .WithTrustStore(ClientTrust).WithSessionCache(LCache).Build, ServerHost);
  LServer := TTlsEngineFactory.CreateServerEngine(TTlsPresets.Strict(Crypto, Pkix).Server
    .WithCredential(ServerCredential).WithSessionStore(LStore).Build);
  PumpToCompletion(LClient, LServer);
  CheckFalse(LClient.IsHandshaking, 'the Strict handshake completed');
  CheckEquals(0, LStore.Count, 'Strict left resumption off: nothing stored');
  CheckEquals(0, LCache.Count, 'Strict left resumption off: nothing cached');
  CheckAppDataFlows(LClient, LServer);
end;

procedure TTestConfigResumption.TestStrictResumptionReEnabledWithNoGuard;
var
  LCache: ISessionCache;
  LScope: TBytes;
  LStore: ISessionStore;
  LClient, LServer: ITlsEngine;
begin
  // Strict is a mutable starting point: re-enabling resumption on it needs no ceremony. One logical
  // client reconnecting shares its scope across both connections.
  LCache := TInMemorySessionCache.Create;
  LScope := Crypto.Primitives.GetRandom.GenerateBytes(16);
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);

  LClient := TTlsEngineFactory.CreateClientEngine(TTlsPresets.Strict(Crypto, Pkix).Client
    .WithResumption(True).WithTrustStore(ClientTrust).WithSessionCache(LCache, LScope).Build,
    ServerHost);
  LServer := TTlsEngineFactory.CreateServerEngine(TTlsPresets.Strict(Crypto, Pkix).Server
    .WithResumption(True).WithCredential(ServerCredential).WithSessionStore(LStore)
    .WithTicketCount(1).Build);
  PumpToCompletion(LClient, LServer);
  CheckEquals(1, LStore.Count, 're-enabled Strict stored a session');

  LClient := TTlsEngineFactory.CreateClientEngine(TTlsPresets.Strict(Crypto, Pkix).Client
    .WithResumption(True).WithTrustStore(ClientTrust).WithSessionCache(LCache, LScope).Build,
    ServerHost);
  LServer := TTlsEngineFactory.CreateServerEngine(TTlsPresets.Strict(Crypto, Pkix).Server
    .WithResumption(True).WithCredential(ServerCredential).WithSessionStore(LStore)
    .WithTicketCount(0).Build);
  PumpToCompletion(LClient, LServer);
  CheckFalse(LServer.IsTerminal, 're-enabled Strict resume did not fail');
  CheckEquals(0, LStore.Count, 're-enabled Strict resumed (store consumed)');
  CheckAppDataFlows(LClient, LServer);
end;

procedure TTestConfigResumption.TestSharedCacheDoesNotResumeAcrossConfigurations;
var
  LCache: ISessionCache;
  LServerConfig: ITlsServerConfig;
  LClient, LServer: ITlsEngine;
begin
  // a permissive client establishes and caches a resumable session; one STEK-backed server config
  // is reused so the ticket stays openable across the connections below
  LCache := TInMemorySessionCache.Create;
  LServerConfig := TTlsPresets.Hardened(Crypto, Pkix).Server
    .WithCredential(ServerCredential).Build;
  LClient := NewClient13(LCache, True);
  LServer := TTlsEngineFactory.CreateServerEngine(LServerConfig);
  PumpToCompletion(LClient, LServer);
  CheckFalse(LClient.IsHandshaking, 'the permissive handshake completed');
  CheckTrue(LCache.Count >= 1, 'the permissive client cached a session');

  // a client whose verifier rejects every chain, given the SAME cache instance but its own
  // configuration, must not see the permissive config's session (scopes differ by construction):
  // it runs a full handshake and its verifier rejects the server. Were it to resume, its verifier
  // would never be consulted (a resumed handshake sends no certificate) - the bypass this prevents.
  LClient := NewRejectingClient13(LCache);
  LServer := TTlsEngineFactory.CreateServerEngine(LServerConfig);
  PumpToCompletion(LClient, LServer);
  CheckFalse(LClient.ConnectionInfo.Resumed, 'a shared cache does not resume across configurations');
  CheckTrue(LClient.IsTerminal,
    'so the strict config runs a full handshake and its verifier rejects the server');
end;

procedure TTestConfigResumption.TestSharedCacheDoesNotResumeAcrossConfigurationsTls12;
var
  LCache: ISessionCache;
  LStore: ISessionStore;
  LClient, LServer: ITlsEngine;
begin
  // the 1.2 twin of the isolation property: one cache instance shared by two client configurations
  // (each its own fresh scope) does not resume across them
  LCache := TInMemorySessionCache.Create;
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);
  LClient := NewClient12(LCache);
  LServer := NewServer12(LStore);
  PumpToCompletion(LClient, LServer);
  CheckEquals(1, LCache.Count, 'the first 1.2 configuration cached a session');

  // a different configuration sharing the same cache cannot see it (scopes differ), so the server
  // flight carries a full Certificate rather than an abbreviated resume
  LClient := NewClient12(LCache);
  LServer := NewServer12(LStore);
  CheckTrue(DriveObservingServerCert(LClient, LServer),
    'a shared cache does not resume a 1.2 session across configurations');
end;

procedure TTestConfigResumption.TestSharedSessionScopeResumesAcrossRebuiltConfigs;
var
  LCache: ISessionCache;
  LScope: TBytes;
  LServerConfig: ITlsServerConfig;
  LClient, LServer: ITlsEngine;
begin
  // two client configurations given the SAME explicit scope share sessions through one cache (the
  // caller asserts they trust identically) - the pattern an app rebuilding its config per connection
  // relies on to keep resuming
  LCache := TInMemorySessionCache.Create;
  LScope := Crypto.Primitives.GetRandom.GenerateBytes(16);
  LServerConfig := TTlsPresets.Hardened(Crypto, Pkix).Server
    .WithCredential(ServerCredential).Build;
  LClient := NewClient13(LCache, True, LScope);
  LServer := TTlsEngineFactory.CreateServerEngine(LServerConfig);
  PumpToCompletion(LClient, LServer);
  CheckTrue(LCache.Count >= 1, 'the first scoped configuration cached a session');

  LClient := NewClient13(LCache, True, LScope);
  LServer := TTlsEngineFactory.CreateServerEngine(LServerConfig);
  PumpToCompletion(LClient, LServer);
  CheckTrue(LClient.ConnectionInfo.Resumed, 'a configuration with the same scope resumes the shared session');

  // a configuration with no explicit scope (a fresh per-build one) does not resume across them,
  // even sharing the same cache instance; a scoped session must remain for the check to be real
  CheckTrue(LCache.Count >= 1, 'a session remains for the unshared configuration to be denied');
  LClient := NewClient13(LCache, True);
  LServer := TTlsEngineFactory.CreateServerEngine(LServerConfig);
  PumpToCompletion(LClient, LServer);
  CheckFalse(LClient.ConnectionInfo.Resumed,
    'an unshared-scope configuration does not draw another configuration''s session');
end;

procedure TTestConfigResumption.TestReverifyOnResumeRejectsUntrustedServer;
var
  LCache: ISessionCache;
  LScope: TBytes;
  LServerConfig: ITlsServerConfig;
  LClient, LServer: ITlsEngine;
  LBefore: Int32;
begin
  // a permissive client caches a resumable session, storing the server chain it verified; the two
  // configs share a scope so the resuming one draws the stored session (they trust identically)
  LCache := TInMemorySessionCache.Create;
  LScope := Crypto.Primitives.GetRandom.GenerateBytes(16);
  LServerConfig := TTlsPresets.Hardened(Crypto, Pkix).Server
    .WithCredential(ServerCredential).Build;
  LClient := NewClient13(LCache, True, LScope);
  LServer := TTlsEngineFactory.CreateServerEngine(LServerConfig);
  PumpToCompletion(LClient, LServer);
  CheckFalse(LClient.IsHandshaking, 'the permissive handshake completed');
  CheckTrue(LCache.Count >= 1, 'the permissive client cached a session');

  // a client that opts into Reverify, resuming the SAME session, re-runs its verifier against the
  // stored server chain; its rejecting verifier refuses the resumed server, so it aborts. (The
  // default ReuseOriginal case - a resumption that does NOT re-verify - is covered by
  // TestSharedCacheDoesNotResumeAcrossConfigurations.)
  LBefore := LCache.Count;
  LClient := NewReverifyRejectClient13(LCache, LScope);
  LServer := TTlsEngineFactory.CreateServerEngine(LServerConfig);
  PumpToCompletion(LClient, LServer);
  // it drew the cached session (single-use Take), proving it resumed and then reverified - not a
  // full handshake that would also end terminal
  CheckEquals(LBefore - 1, LCache.Count, 'the client drew the cached session to resume it');
  CheckTrue(LClient.IsTerminal, 'Reverify re-checked the resumed server and rejected it');
end;

procedure TTestConfigResumption.TestReverifyOnResumeAsyncParkAcceptsCompletes;
var
  LCache: ISessionCache;
  LScope: TBytes;
  LServerConfig: ITlsServerConfig;
  LClient, LServer: ITlsEngine;
begin
  // a permissive client caches a resumable session (shared scope so the resuming config draws it)
  LCache := TInMemorySessionCache.Create;
  LScope := Crypto.Primitives.GetRandom.GenerateBytes(16);
  LServerConfig := TTlsPresets.Hardened(Crypto, Pkix).Server
    .WithCredential(ServerCredential).Build;
  LClient := NewClient13(LCache, True, LScope);
  LServer := TTlsEngineFactory.CreateServerEngine(LServerConfig);
  PumpToCompletion(LClient, LServer);
  CheckTrue(LCache.Count >= 1, 'the permissive client cached a session');

  // resume with Reverify + async: the inline reverify accepts, the handshake parks at
  // ServerFinished (the client Finished is withheld), and the accepted out-of-band verdict
  // drives the withheld continuation to completion
  LClient := NewReverifyAsyncClient13(LCache, LScope);
  LServer := TTlsEngineFactory.CreateServerEngine(LServerConfig);
  PumpToCompletionResolving(LClient, LServer, True,
    TTlsAlertDescription.BadCertificate);
  CheckTrue(LClient.ConnectionInfo.Resumed, 'the async reverify-on-resume handshake resumed');
  CheckFalse(LClient.IsHandshaking, 'the resumed handshake completed after the accepted park');
  CheckFalse(LClient.IsTerminal, 'an accepted verdict did not abort');
end;

procedure TTestConfigResumption.TestExporterWithheldDuringReverifyPark;
var
  LCache: ISessionCache;
  LScope: TBytes;
  LServerConfig: ITlsServerConfig;
  LClient, LServer: ITlsEngine;
  LIterations, LBefore: Int32;
begin
  // cache a resumable session (shared scope so the resuming config draws it)
  LCache := TInMemorySessionCache.Create;
  LScope := Crypto.Primitives.GetRandom.GenerateBytes(16);
  LServerConfig := TTlsPresets.Hardened(Crypto, Pkix).Server
    .WithCredential(ServerCredential).Build;
  LClient := NewClient13(LCache, True, LScope);
  LServer := TTlsEngineFactory.CreateServerEngine(LServerConfig);
  PumpToCompletion(LClient, LServer);

  // resume with reverify + async: drive until the client parks on the verdict. It has processed
  // ServerFinished (so its application/exporter secrets are derived), but the resumed identity is
  // not yet accepted.
  LBefore := LCache.Count;
  LClient := NewReverifyAsyncClient13(LCache, LScope);
  LServer := TTlsEngineFactory.CreateServerEngine(LServerConfig);
  LClient.StartHandshake;
  LIterations := 0;
  while (not LClient.AwaitingCertificateVerdict) and LClient.IsHandshaking and
    (LIterations < 16) do
  begin
    Pump(LClient, LServer);
    Pump(LServer, LClient);
    Inc(LIterations);
  end;
  CheckTrue(LClient.AwaitingCertificateVerdict, 'the client parked on the reverify verdict');
  // it drew the cached session (single-use Take) to reach this park, proving a resumption not a
  // full handshake (which would also park under an async verdict)
  CheckEquals(LBefore - 1, LCache.Count, 'the client drew the cached session to resume it');
  // the exporter is withheld while parked, even though the secret is derived - no keying
  // material is exported over an unverified resumed identity
  CheckEquals(0, System.Length(LClient.ExportKeyingMaterial('EXPORTER-test',
    DecodeHex('00010203'), True, 32)), 'no export while parked on the reverify verdict');

  // accept and complete; the exporter is then available
  LClient.SetCertificateVerdict(True, TTlsAlertDescription.BadCertificate);
  LIterations := 0;
  while LClient.IsHandshaking and (LIterations < 16) do
  begin
    Pump(LClient, LServer);
    Pump(LServer, LClient);
    Inc(LIterations);
  end;
  CheckFalse(LClient.IsHandshaking, 'the handshake completed after the accepted verdict');
  CheckEquals(32, System.Length(LClient.ExportKeyingMaterial('EXPORTER-test',
    DecodeHex('00010203'), True, 32)), 'the exporter is available after the peer is accepted');
end;

procedure TTestConfigResumption.TestReverifyOnResumeAsyncParkRejectAborts;
var
  LCache: ISessionCache;
  LScope: TBytes;
  LServerConfig: ITlsServerConfig;
  LClient, LServer: ITlsEngine;
  LBefore: Int32;
begin
  LCache := TInMemorySessionCache.Create;
  LScope := Crypto.Primitives.GetRandom.GenerateBytes(16);
  LServerConfig := TTlsPresets.Hardened(Crypto, Pkix).Server
    .WithCredential(ServerCredential).Build;
  LClient := NewClient13(LCache, True, LScope);
  LServer := TTlsEngineFactory.CreateServerEngine(LServerConfig);
  PumpToCompletion(LClient, LServer);
  CheckTrue(LCache.Count >= 1, 'the permissive client cached a session');

  // resume with Reverify + async, then REJECT the out-of-band verdict: the parked handshake
  // aborts fail-closed with the resolver's alert (augment-only); the client Finished is never sent
  LBefore := LCache.Count;
  LClient := NewReverifyAsyncClient13(LCache, LScope);
  LServer := TTlsEngineFactory.CreateServerEngine(LServerConfig);
  PumpToCompletionResolving(LClient, LServer, False,
    TTlsAlertDescription.CertificateRevoked);
  // it drew the cached session (single-use Take), proving it parked on a resumption not a full handshake
  CheckEquals(LBefore - 1, LCache.Count, 'the client drew the cached session to resume it');
  CheckTrue(LClient.IsTerminal, 'a rejected park aborted the resumed handshake');
end;

procedure TTestConfigResumption.TestTls12ReverifyOnResumeAsyncParkAcceptsCompletes;
var
  LCache: ISessionCache;
  LScope: TBytes;
  LStore: ISessionStore;
  LClient, LServer: ITlsEngine;
begin
  // a permissive 1.2 client caches a resumable session (shared scope so the resuming config draws it)
  LCache := TInMemorySessionCache.Create;
  LScope := Crypto.Primitives.GetRandom.GenerateBytes(16);
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);
  LClient := NewClient12(LCache, LScope);
  LServer := NewServer12(LStore);
  PumpToCompletion(LClient, LServer);
  CheckEquals(1, LCache.Count, 'the client cached the 1.2 session');

  // resume with Reverify + async: the inline reverify accepts, the abbreviated handshake parks at
  // the server Finished (the client Finished is withheld), and the accepted out-of-band verdict
  // drives the withheld continuation to completion
  LClient := NewReverifyAsyncClient12(LCache, LScope);
  LServer := NewServer12(LStore);
  PumpToCompletionResolving(LClient, LServer, True,
    TTlsAlertDescription.BadCertificate);
  CheckTrue(LClient.ConnectionInfo.Resumed, 'the async reverify-on-resume 1.2 handshake resumed');
  CheckFalse(LClient.IsHandshaking, 'the resumed handshake completed after the accepted park');
  CheckFalse(LClient.IsTerminal, 'an accepted verdict did not abort');
end;

procedure TTestConfigResumption.TestTls12ReverifyOnResumeAsyncParkRejectAborts;
var
  LCache: ISessionCache;
  LScope: TBytes;
  LStore: ISessionStore;
  LClient, LServer: ITlsEngine;
begin
  LCache := TInMemorySessionCache.Create;
  LScope := Crypto.Primitives.GetRandom.GenerateBytes(16);
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);
  LClient := NewClient12(LCache, LScope);
  LServer := NewServer12(LStore);
  PumpToCompletion(LClient, LServer);
  CheckEquals(1, LCache.Count, 'the client cached the 1.2 session');

  // resume, then REJECT the out-of-band verdict: the parked handshake aborts fail-closed with the
  // resolver's alert (augment-only); the client Finished is never sent, so the server also aborts
  LClient := NewReverifyAsyncClient12(LCache, LScope);
  LServer := NewServer12(LStore);
  PumpToCompletionResolving(LClient, LServer, False,
    TTlsAlertDescription.CertificateRevoked);
  // the client drew the one cached session (single-use Take), proving it resumed rather than
  // running a full handshake that would also end terminal
  CheckEquals(0, LCache.Count, 'the client drew the cached 1.2 session to resume it');
  CheckTrue(LClient.IsTerminal, 'a rejected park aborted the resumed 1.2 handshake');
  CheckTrue(LServer.IsTerminal, 'the abort reached the server');
end;

procedure TTestConfigResumption.TestTls12ReverifyOnResumeExporterWithheld;
var
  LCache: ISessionCache;
  LScope: TBytes;
  LStore: ISessionStore;
  LClient, LServer: ITlsEngine;
  LIterations: Int32;
begin
  LCache := TInMemorySessionCache.Create;
  LScope := Crypto.Primitives.GetRandom.GenerateBytes(16);
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);
  LClient := NewClient12(LCache, LScope);
  LServer := NewServer12(LStore);
  PumpToCompletion(LClient, LServer);

  // drive until the client parks on the verdict; no verdict is supplied, so the handshake must
  // not complete and no keying material may be exported over the unverified resumed identity
  LClient := NewReverifyAsyncClient12(LCache, LScope);
  LServer := NewServer12(LStore);
  LClient.StartHandshake;
  LIterations := 0;
  while (not LClient.AwaitingCertificateVerdict) and LClient.IsHandshaking and
    (LIterations < 16) do
  begin
    Pump(LClient, LServer);
    Pump(LServer, LClient);
    Inc(LIterations);
  end;
  CheckTrue(LClient.AwaitingCertificateVerdict, 'the 1.2 client parked on the reverify verdict');
  // it drew the one cached session (single-use Take) to reach this park, proving a resumption
  CheckEquals(0, LCache.Count, 'the client drew the cached 1.2 session to resume it');
  CheckTrue(LClient.IsHandshaking, 'the parked 1.2 handshake has not completed without a verdict');
  CheckEquals(0, System.Length(LClient.ExportKeyingMaterial('EXPORTER-test',
    DecodeHex('00010203'), True, 32)), 'no export while parked on the reverify verdict');
end;

procedure TTestConfigResumption.TestHardReverifyWithLiveVerdictStillResumes;
var
  LCache: ISessionCache;
  LScope: TBytes;
  LStore: ISessionStore;
  LClient, LServer: ITlsEngine;
  LBefore: Int32;
begin
  // a live-revocation deferral gives the reverified resume a fresh channel, so a Hard client with
  // WithLiveRevocationVerdict still resumes: the resume re-checks inline (accepts) then parks for
  // the live verdict, which the accepted resolution clears. Guards the gate from widening to
  // posture alone.
  LCache := TInMemorySessionCache.Create;
  LScope := Crypto.Primitives.GetRandom.GenerateBytes(16);
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);

  LClient := NewStaplingSeedClient13(LCache, LScope);
  LServer := NewStaplingServer13(LStore, 1);
  PumpToCompletion(LClient, LServer);
  CheckFalse(LClient.IsHandshaking, 'the seed full handshake completed');
  CheckTrue(LCache.Count >= 1, 'the seed client cached a session');

  LBefore := LCache.Count;
  LClient := NewHardReverifyClient13(LCache, LScope, TVerdictDeferral.LiveRevocation);
  LServer := NewStaplingServer13(LStore, 0);
  PumpToCompletionResolving(LClient, LServer, True, TTlsAlertDescription.BadCertificate);
  CheckEquals(LBefore - 1, LCache.Count, 'the client drew the cached session to resume it');
  CheckTrue(LClient.ConnectionInfo.Resumed, 'Hard + Reverify + LiveRevocation still resumes');
  CheckFalse(LClient.IsHandshaking, 'the resumed handshake completed after the accepted park');
  CheckFalse(LClient.IsTerminal, 'an accepted live verdict did not abort');
end;

procedure TTestConfigResumption.TestTls12HardReverifyWithLiveVerdictStillResumes;
var
  LCache: ISessionCache;
  LScope: TBytes;
  LStore: ISessionStore;
  LClient, LServer: ITlsEngine;
begin
  // the TLS 1.2 twin: a Hard + Reverify + LiveRevocation client resumes the abbreviated handshake,
  // re-checks inline, parks for the live verdict, and completes on the accepted resolution
  LCache := TInMemorySessionCache.Create;
  LScope := Crypto.Primitives.GetRandom.GenerateBytes(16);
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);

  LClient := NewStaplingSeedClient12(LCache, LScope);
  LServer := NewStaplingServer12(LStore);
  PumpToCompletion(LClient, LServer);
  CheckEquals(1, LCache.Count, 'the seed 1.2 client cached a session');

  LClient := NewHardReverifyClient12(LCache, LScope, TVerdictDeferral.LiveRevocation);
  LServer := NewStaplingServer12(LStore);
  PumpToCompletionResolving(LClient, LServer, True, TTlsAlertDescription.BadCertificate);
  // the abbreviated resume completes, so the server re-issues a ticket the client re-caches;
  // ConnectionInfo.Resumed (not the cache count) is the resume tell here
  CheckTrue(LClient.ConnectionInfo.Resumed,
    '1.2 Hard + Reverify + LiveRevocation still resumes');
  CheckFalse(LClient.IsHandshaking, 'the resumed 1.2 handshake completed after the accepted park');
  CheckFalse(LClient.IsTerminal, 'an accepted live verdict did not abort');
end;

procedure TTestConfigResumption.TestHardReuseOriginalStillResumes;
var
  LCache: ISessionCache;
  LScope: TBytes;
  LStore: ISessionStore;
  LClient, LServer: ITlsEngine;
  LBefore: Int32;
begin
  // ReuseOriginal never re-verifies on resume (a resumption sends no certificate), so a Hard
  // posture has nothing to satisfy: the gate is on Reverify only, and this still resumes
  LCache := TInMemorySessionCache.Create;
  LScope := Crypto.Primitives.GetRandom.GenerateBytes(16);
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);

  LClient := NewStaplingSeedClient13(LCache, LScope);
  LServer := NewStaplingServer13(LStore, 1);
  PumpToCompletion(LClient, LServer);
  CheckTrue(LCache.Count >= 1, 'the seed client cached a session');

  LBefore := LCache.Count;
  LClient := NewHardReuseOriginalClient13(LCache, LScope);
  LServer := NewStaplingServer13(LStore, 0);
  PumpToCompletion(LClient, LServer);
  CheckEquals(LBefore - 1, LCache.Count, 'the client drew the cached session to resume it');
  CheckTrue(LClient.ConnectionInfo.Resumed, 'Hard + ReuseOriginal still resumes');
  CheckFalse(LClient.IsTerminal, 'the ReuseOriginal resume did not abort');
end;

procedure TTestConfigResumption.TestSoftReverifyWithoutLiveVerdictStillResumes;
var
  LCache: ISessionCache;
  LScope: TBytes;
  LStore: ISessionStore;
  LClient, LServer: ITlsEngine;
  LConfig: ITlsClientConfig;
  LBefore: Int32;
begin
  // a Soft posture accepts an indeterminate (unstapled) resume inline, so a Soft + Reverify client
  // with no live deferral still resumes: the gate is Hard-only
  LCache := TInMemorySessionCache.Create;
  LScope := Crypto.Primitives.GetRandom.GenerateBytes(16);
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);

  LClient := NewStaplingSeedClient13(LCache, LScope);
  LServer := NewStaplingServer13(LStore, 1);
  PumpToCompletion(LClient, LServer);
  CheckTrue(LCache.Count >= 1, 'the seed client cached a session');

  LBefore := LCache.Count;
  // Soft (the default posture) + Reverify, no live deferral
  LConfig := TTlsPresets.Hardened(Crypto, Pkix).Client
    .WithTrustAnchors(OcspField('root_cert'))
    .WithDangerousDisableServerNameCheck
    .WithResumeVerification(TResumeVerification.Reverify)
    .WithResumption(True)
    .WithSessionCache(LCache, LScope)
    .Build;
  LClient := TTlsEngineFactory.CreateClientEngine(LConfig, ServerHost);
  LServer := NewStaplingServer13(LStore, 0);
  PumpToCompletion(LClient, LServer);
  CheckEquals(LBefore - 1, LCache.Count, 'the client drew the cached session to resume it');
  CheckTrue(LClient.ConnectionInfo.Resumed, 'Soft + Reverify (no live verdict) still resumes');
  CheckFalse(LClient.IsTerminal, 'the Soft reverify resume did not abort');
end;

procedure TTestConfigResumption.TestHardReverifyWithoutLiveVerdictFallsBackToFullHandshake;
var
  LCache: ISessionCache;
  LScope: TBytes;
  LStore: ISessionStore;
  LClient, LServer: ITlsEngine;
  LBefore: Int32;
begin
  // a Hard + Reverify client with no live-revocation channel could never obtain a fresh verdict on
  // a resume (no staple travels), so the engine withholds the offer: a full handshake runs instead
  // (the server staples a Good response, satisfying Hard), the cached session is never drawn, and
  // ConnectionInfo reports no resumption. A second connection behaves identically - no flip-flop.
  LCache := TInMemorySessionCache.Create;
  LScope := Crypto.Primitives.GetRandom.GenerateBytes(16);
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);

  LClient := NewStaplingSeedClient13(LCache, LScope);
  LServer := NewStaplingServer13(LStore, 2);
  PumpToCompletion(LClient, LServer);
  LBefore := LCache.Count;
  CheckTrue(LBefore >= 1, 'the seed client cached a session');

  LClient := NewHardReverifyClient13(LCache, LScope, TVerdictDeferral.None);
  LServer := NewStaplingServer13(LStore, 0);
  PumpToCompletion(LClient, LServer);
  CheckEquals(LBefore, LCache.Count,
    'the gated client never drew the cached session (no resumption offered)');
  CheckFalse(LClient.ConnectionInfo.Resumed, 'the gated client ran a full handshake');
  CheckFalse(LClient.IsHandshaking, 'the full handshake completed');
  CheckFalse(LClient.IsTerminal, 'the Good staple satisfied Hard on the full handshake');
  CheckAppDataFlows(LClient, LServer);

  // a second connection with another gated client is still full and still completes
  LClient := NewHardReverifyClient13(LCache, LScope, TVerdictDeferral.None);
  LServer := NewStaplingServer13(LStore, 0);
  PumpToCompletion(LClient, LServer);
  CheckEquals(LBefore, LCache.Count, 'the second connection also drew nothing');
  CheckFalse(LClient.ConnectionInfo.Resumed, 'the second connection is also a full handshake');
  CheckFalse(LClient.IsTerminal, 'the second full handshake completed (no flip-flop)');
end;

procedure TTestConfigResumption.TestHardReverifyHostDecisionFallsBackToFullHandshake;
var
  LCache: ISessionCache;
  LScope: TBytes;
  LStore: ISessionStore;
  LClient, LServer: ITlsEngine;
  LBefore: Int32;
begin
  // HostDecision cannot settle revocation on a resume either, so the offer is withheld: the full
  // handshake runs its ordinary initial-cert host-decision park, which the accepted verdict clears
  LCache := TInMemorySessionCache.Create;
  LScope := Crypto.Primitives.GetRandom.GenerateBytes(16);
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);

  LClient := NewStaplingSeedClient13(LCache, LScope);
  LServer := NewStaplingServer13(LStore, 2);
  PumpToCompletion(LClient, LServer);
  LBefore := LCache.Count;
  CheckTrue(LBefore >= 1, 'the seed client cached a session');

  LClient := NewHardReverifyClient13(LCache, LScope, TVerdictDeferral.HostDecision);
  LServer := NewStaplingServer13(LStore, 0);
  PumpToCompletionResolving(LClient, LServer, True, TTlsAlertDescription.BadCertificate);
  CheckEquals(LBefore, LCache.Count,
    'the gated client never drew the cached session (no resumption offered)');
  CheckFalse(LClient.ConnectionInfo.Resumed, 'the gated client ran a full handshake');
  CheckFalse(LClient.IsHandshaking, 'the full handshake completed after the host-decision park');
  CheckFalse(LClient.IsTerminal, 'the accepted host decision did not abort');
end;

procedure TTestConfigResumption.TestTls12HardReverifyWithoutLiveVerdictFallsBackToFullHandshake;
var
  LCache: ISessionCache;
  LScope: TBytes;
  LStore: ISessionStore;
  LClient, LServer: ITlsEngine;
  LBefore: Int32;
begin
  // the TLS 1.2 twin: the gated client withholds the session_ticket offer, so the server flight
  // carries a full Certificate (the abbreviated-vs-full tell), the cached session is untouched,
  // and ConnectionInfo reports no resumption
  LCache := TInMemorySessionCache.Create;
  LScope := Crypto.Primitives.GetRandom.GenerateBytes(16);
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);

  LClient := NewStaplingSeedClient12(LCache, LScope);
  LServer := NewStaplingServer12(LStore);
  PumpToCompletion(LClient, LServer);
  LBefore := LCache.Count;
  CheckTrue(LBefore >= 1, 'the seed 1.2 client cached a session');

  LClient := NewHardReverifyClient12(LCache, LScope, TVerdictDeferral.None);
  LServer := NewStaplingServer12(LStore);
  CheckTrue(DriveObservingServerCert(LClient, LServer),
    'the gated 1.2 client ran a full handshake (the server sent a Certificate)');
  CheckEquals(LBefore, LCache.Count,
    'the gated 1.2 client never drew the cached session (no resumption offered)');
  CheckFalse(LClient.ConnectionInfo.Resumed, 'the gated 1.2 client did not resume');
  CheckFalse(LClient.IsTerminal, 'the Good staple satisfied Hard on the full 1.2 handshake');
  CheckFalse(LClient.IsHandshaking, 'the gated 1.2 client completed the full handshake');
  CheckAppDataFlows(LClient, LServer);
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestConfigResumption);
{$ELSE}
  RegisterTest(TTestConfigResumption.Suite);
{$ENDIF FPC}

end.
