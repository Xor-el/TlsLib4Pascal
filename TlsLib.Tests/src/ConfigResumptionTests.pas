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
    function ServerCredential: TTlsCredential;
    function ClientTrust: ITrustAnchorStore;
    /// <summary>A TLS 1.3 client engine built through the public config surface.</summary>
    function NewClient13(const ACache: ISessionCache; AResumption: Boolean): ITlsEngine;
    /// <summary>A TLS 1.3 server engine; AIssueTickets tickets, resumption toggle.</summary>
    function NewServer13(const AStore: ISessionStore; AIssueTickets: Int32;
      AResumption: Boolean): ITlsEngine;
    function NewClient12(const ACache: ISessionCache): ITlsEngine;
    function NewServer12(const AStore: ISessionStore): ITlsEngine;
    function Drain(const AEngine: ITlsEngine): TBytes;
    procedure Feed(const AEngine: ITlsEngine; const AWire: TBytes);
    procedure Pump(const ASrc, ADst: ITlsEngine);
    procedure PumpToCompletion(const AClient, AServer: ITlsEngine);
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
  end;

implementation

{ TTestConfigResumption }

procedure TTestConfigResumption.SetUp;
begin
  inherited SetUp;
  FCerts := LoadVectorFields('Certs/EcP256Chain.txt');
end;

procedure TTestConfigResumption.TearDown;
begin
  FCerts.Free;
  inherited TearDown;
end;

function TTestConfigResumption.ServerCredential: TTlsCredential;
begin
  Result.CertificateChain := TArray<TBytes>.Create(DecodeHex(FCerts.Values['leaf_cert']));
  Result.PrivateKey := Provider.Signing.ImportSigningKey(DecodeHex(FCerts.Values['leaf_key']));
end;

function TTestConfigResumption.ClientTrust: ITrustAnchorStore;
begin
  Result := TTrustAnchorStore.Create(
    TArray<TBytes>.Create(DecodeHex(FCerts.Values['root_cert']))) as ITrustAnchorStore;
end;

function TTestConfigResumption.NewClient13(const ACache: ISessionCache;
  AResumption: Boolean): ITlsEngine;
var
  LConfig: ITlsClientConfig;
begin
  // Hardened is TLS 1.3-only; the public surface wires the cache and resumption toggle
  LConfig := TTlsPresets.Hardened(Provider).Client
    .WithTrustStore(ClientTrust)
    .WithResumption(AResumption)
    .WithSessionCache(ACache)
    .Build;
  Result := TTlsEngineFactory.CreateClientEngine(LConfig, ServerHost);
end;

function TTestConfigResumption.NewServer13(const AStore: ISessionStore;
  AIssueTickets: Int32; AResumption: Boolean): ITlsEngine;
var
  LConfig: ITlsServerConfig;
begin
  LConfig := TTlsPresets.Hardened(Provider).Server
    .WithCredential(ServerCredential)
    .WithResumption(AResumption)
    .WithSessionStore(AStore)
    .WithTicketCount(AIssueTickets)
    .Build;
  Result := TTlsEngineFactory.CreateServerEngine(LConfig);
end;

function TTestConfigResumption.NewClient12(const ACache: ISessionCache): ITlsEngine;
var
  LConfig: ITlsClientConfig;
begin
  LConfig := TTlsPresets.Compatible(Provider).Client
    .WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls12))
    .WithTrustStore(ClientTrust)
    .WithSessionCache(ACache)
    .Build;
  Result := TTlsEngineFactory.CreateClientEngine(LConfig, ServerHost);
end;

function TTestConfigResumption.NewServer12(const AStore: ISessionStore): ITlsEngine;
var
  LConfig: ITlsServerConfig;
begin
  LConfig := TTlsPresets.Compatible(Provider).Server
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
  LStore: ISessionStore;
  LClient, LServer: ITlsEngine;
begin
  // the public surface: a store-backed 1.3 server issues one stateful ticket; a later
  // handshake resumes it. The store single-use consumption proves the config wired through
  LCache := TInMemorySessionCache.Create;
  LStore := TInMemorySessionStore.Create(Provider.Primitives.GetRandom);

  LClient := NewClient13(LCache, True);
  LServer := NewServer13(LStore, 1, True);
  PumpToCompletion(LClient, LServer);
  CheckFalse(LClient.IsHandshaking, 'the initial 1.3 handshake completed');
  CheckEquals(1, LStore.Count, 'the server stored one resumable session');
  CheckEquals(1, LCache.Count, 'the client cached the ticket');

  // the resuming server issues no new ticket, so a consumed store proves resumption
  LClient := NewClient13(LCache, True);
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
  LStore: ISessionStore;
  LClient, LServer: ITlsEngine;
begin
  // a TLS 1.2 client and server through the public surface: the second handshake resumes,
  // proven by the abbreviated server flight (no plaintext Certificate)
  LCache := TInMemorySessionCache.Create;
  LStore := TInMemorySessionStore.Create(Provider.Primitives.GetRandom);

  LClient := NewClient12(LCache);
  LServer := NewServer12(LStore);
  PumpToCompletion(LClient, LServer);
  CheckFalse(LClient.IsHandshaking, 'the initial 1.2 handshake completed');
  CheckEquals(1, LCache.Count, 'the client cached the 1.2 session');

  LClient := NewClient12(LCache);
  LServer := NewServer12(LStore);
  CheckFalse(DriveObservingServerCert(LClient, LServer),
    '1.2 resumption via the config is abbreviated (no Certificate)');
  CheckFalse(LServer.IsTerminal, 'the 1.2 resume did not fail');
  CheckAppDataFlows(LClient, LServer);
end;

procedure TTestConfigResumption.TestDefaultServerIssuesTicketsOutOfBox;
var
  LCache: ISessionCache;
  LServerConfig: ITlsServerConfig;
  LClient, LServer: ITlsEngine;
begin
  // a server built through the public surface with only a credential - no WithSessionStore and
  // no WithDefaultSessionTicketKeys - resumes out of the box: the resume-by-default posture mints
  // a STEK, so the server issues a ticket the client caches and can later present. One frozen
  // config is reused across both handshakes so the same STEK opens the ticket
  LCache := TInMemorySessionCache.Create;
  LServerConfig := TTlsPresets.Hardened(Provider).Server
    .WithCredential(ServerCredential).Build;

  LClient := NewClient13(LCache, True);
  LServer := TTlsEngineFactory.CreateServerEngine(LServerConfig);
  PumpToCompletion(LClient, LServer);
  CheckFalse(LClient.IsHandshaking, 'the initial handshake completed');
  CheckTrue(LCache.Count >= 1, 'the default server issued a ticket the client cached');

  LClient := NewClient13(LCache, True);
  LServer := TTlsEngineFactory.CreateServerEngine(LServerConfig);
  PumpToCompletion(LClient, LServer);
  CheckFalse(LServer.IsHandshaking, 'the resuming server completed');
  CheckFalse(LServer.IsTerminal, 'the resuming server did not fail');
  // prove it actually resumed via the out-of-box ticket, not a silent full-handshake fallback
  CheckTrue(LClient.IsResumed, 'the second handshake resumed off the auto-issued ticket');
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
  LServer := TTlsEngineFactory.CreateServerEngine(TTlsPresets.Hardened(Provider).Server
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
  LStore := TInMemorySessionStore.Create(Provider.Primitives.GetRandom);

  LClient := TTlsEngineFactory.CreateClientEngine(TTlsPresets.Strict(Provider).Client
    .WithTrustStore(ClientTrust).WithSessionCache(LCache).Build, ServerHost);
  LServer := TTlsEngineFactory.CreateServerEngine(TTlsPresets.Strict(Provider).Server
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
  LStore: ISessionStore;
  LClient, LServer: ITlsEngine;
begin
  // Strict is a mutable starting point: re-enabling resumption on it needs no ceremony
  LCache := TInMemorySessionCache.Create;
  LStore := TInMemorySessionStore.Create(Provider.Primitives.GetRandom);

  LClient := TTlsEngineFactory.CreateClientEngine(TTlsPresets.Strict(Provider).Client
    .WithResumption(True).WithTrustStore(ClientTrust).WithSessionCache(LCache).Build,
    ServerHost);
  LServer := TTlsEngineFactory.CreateServerEngine(TTlsPresets.Strict(Provider).Server
    .WithResumption(True).WithCredential(ServerCredential).WithSessionStore(LStore)
    .WithTicketCount(1).Build);
  PumpToCompletion(LClient, LServer);
  CheckEquals(1, LStore.Count, 're-enabled Strict stored a session');

  LClient := TTlsEngineFactory.CreateClientEngine(TTlsPresets.Strict(Provider).Client
    .WithResumption(True).WithTrustStore(ClientTrust).WithSessionCache(LCache).Build,
    ServerHost);
  LServer := TTlsEngineFactory.CreateServerEngine(TTlsPresets.Strict(Provider).Server
    .WithResumption(True).WithCredential(ServerCredential).WithSessionStore(LStore)
    .WithTicketCount(0).Build);
  PumpToCompletion(LClient, LServer);
  CheckFalse(LServer.IsTerminal, 're-enabled Strict resume did not fail');
  CheckEquals(0, LStore.Count, 're-enabled Strict resumed (store consumed)');
  CheckAppDataFlows(LClient, LServer);
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestConfigResumption);
{$ELSE}
  RegisterTest(TTestConfigResumption.Suite);
{$ENDIF FPC}

end.
