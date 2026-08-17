{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit Tls13ResumptionTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  TlpIClock,
  TlpClock,
  SysUtils,
  Classes,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  TlpArrayUtilities,
  TlpCryptoAlgorithms,
  TlpTlsAlert,
  TlpNamedGroups,
  TlpNegotiationTypes,
  TlpNegotiationPolicy,
  TlpCipherSuiteRegistry,
  TlpCoreExtensions,
  TlpISecretBuffer,
  TlpSecretBuffer,
  TlpITlsEngine,
  TlpTlsEngine,
  TlpIHandshakeMachine,
  TlpICertificateTrust,
  TlpCertificateVerifier,
  TlpTlsCredential,
  TlpCredentialResolvers,
  TlpISession,
  TlpSession,
  TlpDateTimeUtilities,
  TlpInMemorySessionCache,
  TlpInMemorySessionStore,
  TlpSessionTicketKeys,
  TlpAntiReplay,
  TlpTls13ClientStateMachine,
  TlpTls13ServerStateMachine,
  MockSessionStores,
  TlsLibTestBase;

type
  TTestTls13Resumption = class(TTlsLibAlgorithmTestCase)
  private
    const
      ServerHost = 'localhost';
    function Filled(AByte: Byte; ACount: Int32): TBytes;
    function TestRootCertificate: TBytes;
    function ServerCredential: TTlsCredential;
    function NewClient(const ACache: ISessionCache;
      AEarlyData: Boolean = False): ITlsEngine;
    // AWithCredential False makes the server unable to run a full handshake, so a
    // completed handshake proves the PSK was accepted (resumption).
    function BuildServer(const AStek: ISessionTicketKeyManager;
      const AStore: ISessionStore; AIssueTickets: Int32; ALifetimeSeconds: UInt32;
      AWithCredential: Boolean; AMaxEarlyData: UInt32 = 0;
      const AAntiReplay: IAntiReplayStrategy = nil): ITlsEngine;
    procedure PumpToCompletion(const AClient, AServer: ITlsEngine);
    function NewServer(const AStore: ISessionStore; AIssueTickets: Int32;
      ALifetimeSeconds: UInt32; AWithCredential: Boolean): ITlsEngine;
    function NewStekServer(const AStek: ISessionTicketKeyManager;
      AIssueTickets: Int32; ALifetimeSeconds: UInt32;
      AWithCredential: Boolean): ITlsEngine;
    function Drain(const AEngine: ITlsEngine): TBytes;
    procedure Feed(const AEngine: ITlsEngine; const AWire: TBytes);
    procedure Pump(const ASrc, ADst: ITlsEngine);
    procedure DriveHandshake(const AClient, AServer: ITlsEngine);
    function ReadAllApp(const AEngine: ITlsEngine): TBytes;
    procedure CheckAppDataFlows(const AClient, AServer: ITlsEngine);
    function MakeSession(const AIdentity: TBytes;
      const ASecret: ISecretBuffer; ALifetime: UInt32): IResumableSession;
    function MakeSessionForHost(const AIdentity: TBytes; const ASecret: ISecretBuffer;
      ALifetime: UInt32; const AHost: string): IResumableSession;
  published
    procedure TestResumptionCompletesPskDheKe;
    procedure TestSingleUseTicketReplayRejected;
    procedure TestMismatchedBinderAbortsDecryptError;
    procedure TestExpiredTicketNotAccepted;
    procedure TestCustomSessionCacheAndStoreAreUsed;
    procedure TestStatelessStekResumptionCompletes;
    procedure TestStekRetiredKeyNotAccepted;
    procedure TestStekInvalidTicketFallsBackToFullHandshake;
    procedure TestStoreUpgradesOverStek;
    procedure TestZeroRttAcceptedDeliversEarlyData;
    procedure TestZeroRttRejectedIsDiscardedNotReplayed;
    procedure TestZeroRttReplayCaughtByStrikeRegister;
    procedure TestEarlyDataOffByDefault;
    procedure TestMutualAuthResumptionCompletes;
    procedure TestTicketIssuedUnderDifferentSniFallsBackToFullHandshake;
  end;

implementation

{ TTestTls13Resumption }

function TTestTls13Resumption.Filled(AByte: Byte; ACount: Int32): TBytes;
begin
  Result := nil;
  SetLength(Result, ACount);
  if ACount > 0 then
    FillChar(Result[0], ACount, AByte);
end;

function TTestTls13Resumption.TestRootCertificate: TBytes;
var
  LCerts: TStringList;
begin
  LCerts := LoadVectorFields('Certs/EcP256Chain.txt');
  try
    Result := DecodeHex(LCerts.Values['root_cert']);
  finally
    LCerts.Free;
  end;
end;

function TTestTls13Resumption.ServerCredential: TTlsCredential;
var
  LCerts: TStringList;
begin
  LCerts := LoadVectorFields('Certs/EcP256Chain.txt');
  try
    Result.CertificateChain := TArray<TBytes>.Create(
      DecodeHex(LCerts.Values['leaf_cert']));
    Result.PrivateKey := Provider.ImportSigningKey(DecodeHex(LCerts.Values['leaf_key']));
  finally
    LCerts.Free;
  end;
end;

function TTestTls13Resumption.NewClient(const ACache: ISessionCache;
  AEarlyData: Boolean): ITlsEngine;
var
  LParams: TClientHandshakeParams;
begin
  LParams := Default(TClientHandshakeParams);
  LParams.Clock := TSystemClock.Create;
  LParams.Provider := Provider;
  LParams.Group := TNamedGroups.CreateX25519(Provider);
  LParams.GroupCode := TNamedGroupCatalog.X25519;
  LParams.CipherSuites := TCipherSuiteRegistry.CreateDefault(Provider);
  LParams.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  LParams.OfferedSuites := TArray<UInt16>.Create(TCipherSuites13.Aes128GcmSha256);
  LParams.OfferedSchemes := TArray<UInt16>.Create(TSignatureSchemes.EcdsaSecp256r1Sha256);
  LParams.ClientRandom := Provider.GetRandom.GenerateBytes(32);
  LParams.LegacySessionId := Filled($33, 32);
  LParams.CertificateVerifier := TCertificateVerifier.Create(Provider, TSystemClock.Create as ITlsClock,
    TTrustAnchorStore.Create(TArray<TBytes>.Create(TestRootCertificate))
    as ITrustAnchorStore, True) as ICertificateVerifier;
  LParams.ExpectedHostName := ServerHost;
  LParams.ServerName := ServerHost;
  LParams.SessionCache := ACache;
  LParams.EarlyDataEnabled := AEarlyData;

  Result := TTlsEngine.CreateConfigured(
    TTls13ClientStateMachine.Create(LParams) as IHandshakeMachine, Provider);
end;

function TTestTls13Resumption.BuildServer(const AStek: ISessionTicketKeyManager;
  const AStore: ISessionStore; AIssueTickets: Int32; ALifetimeSeconds: UInt32;
  AWithCredential: Boolean; AMaxEarlyData: UInt32;
  const AAntiReplay: IAntiReplayStrategy): ITlsEngine;
var
  LParams: TServerHandshakeParams;
begin
  LParams := Default(TServerHandshakeParams);
  LParams.Clock := TSystemClock.Create;
  LParams.Provider := Provider;
  LParams.Policy := TNegotiationPolicy.CreateDefault(Provider);
  LParams.CipherSuites := TCipherSuiteRegistry.CreateDefault(Provider);
  LParams.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  LParams.Group := TNamedGroups.CreateX25519(Provider);
  LParams.ServerRandom := Provider.GetRandom.GenerateBytes(32);
  if AWithCredential then
    LParams.CredentialResolver := TSniCredentialResolver.ForCredential(ServerCredential);
  LParams.SessionTicketKeys := AStek;
  LParams.SessionStore := AStore;
  LParams.IssueTicketCount := AIssueTickets;
  LParams.TicketLifetimeSeconds := ALifetimeSeconds;
  LParams.MaxEarlyData := AMaxEarlyData;
  LParams.AntiReplay := AAntiReplay;

  Result := TTlsEngine.CreateConfigured(
    TTls13ServerStateMachine.Create(LParams) as IHandshakeMachine, Provider);
end;

function TTestTls13Resumption.NewServer(const AStore: ISessionStore;
  AIssueTickets: Int32; ALifetimeSeconds: UInt32;
  AWithCredential: Boolean): ITlsEngine;
begin
  Result := BuildServer(nil, AStore, AIssueTickets, ALifetimeSeconds, AWithCredential);
end;

function TTestTls13Resumption.NewStekServer(const AStek: ISessionTicketKeyManager;
  AIssueTickets: Int32; ALifetimeSeconds: UInt32;
  AWithCredential: Boolean): ITlsEngine;
begin
  Result := BuildServer(AStek, nil, AIssueTickets, ALifetimeSeconds, AWithCredential);
end;

function TTestTls13Resumption.Drain(const AEngine: ITlsEngine): TBytes;
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

procedure TTestTls13Resumption.Feed(const AEngine: ITlsEngine; const AWire: TBytes);
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

procedure TTestTls13Resumption.Pump(const ASrc, ADst: ITlsEngine);
begin
  Feed(ADst, Drain(ASrc));
end;

procedure TTestTls13Resumption.PumpToCompletion(const AClient, AServer: ITlsEngine);
var
  LIterations: Int32;
begin
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

procedure TTestTls13Resumption.DriveHandshake(const AClient, AServer: ITlsEngine);
begin
  AClient.StartHandshake;
  PumpToCompletion(AClient, AServer);
end;

function TTestTls13Resumption.ReadAllApp(const AEngine: ITlsEngine): TBytes;
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

procedure TTestTls13Resumption.CheckAppDataFlows(const AClient, AServer: ITlsEngine);
var
  LFromClient, LFromServer: TBytes;
begin
  LFromClient := DecodeHex('68656c6c6f2066726f6d2074686520636c69656e74');
  AClient.Write(LFromClient, 0, System.Length(LFromClient));
  Pump(AClient, AServer);
  CheckEqualBytes('the server decrypts the client application data', LFromClient,
    ReadAllApp(AServer));
  LFromServer := DecodeHex('68656c6c6f2066726f6d2074686520736572766572');
  AServer.Write(LFromServer, 0, System.Length(LFromServer));
  Pump(AServer, AClient);
  CheckEqualBytes('the client decrypts the server application data', LFromServer,
    ReadAllApp(AClient));
end;

function TTestTls13Resumption.MakeSession(const AIdentity: TBytes;
  const ASecret: ISecretBuffer; ALifetime: UInt32): IResumableSession;
begin
  Result := MakeSessionForHost(AIdentity, ASecret, ALifetime, ServerHost);
end;

function TTestTls13Resumption.MakeSessionForHost(const AIdentity: TBytes;
  const ASecret: ISecretBuffer; ALifetime: UInt32; const AHost: string): IResumableSession;
begin
  Result := TResumableSession.CreateTls13(TCipherSuites13.Aes128GcmSha256,
    THashAlgorithm.SHA_256, ASecret, TNamedGroupCatalog.X25519, '', AHost, AIdentity,
    ALifetime, 0, UInt64(TDateTimeUtilities.CurrentUnixMs), 0);
end;

procedure TTestTls13Resumption.TestResumptionCompletesPskDheKe;
var
  LCache: ISessionCache;
  LStore: ISessionStore;
  LClient, LServer: ITlsEngine;
begin
  LCache := TInMemorySessionCache.Create;
  LStore := TInMemorySessionStore.Create(Provider.GetRandom);

  // first connection: a full handshake that issues one ticket
  LClient := NewClient(LCache);
  LServer := NewServer(LStore, 1, 7200, True);
  DriveHandshake(LClient, LServer);
  CheckFalse(LClient.IsHandshaking, 'the initial client handshake completed');
  CheckFalse(LServer.IsHandshaking, 'the initial server handshake completed');
  CheckFalse(LClient.IsResumed, 'the initial client handshake is not resumed');
  CheckFalse(LServer.IsResumed, 'the initial server handshake is not resumed');
  CheckEquals(1, LCache.Count, 'the client cached the issued ticket');
  CheckEquals(1, LStore.Count, 'the server stored the resumable session');

  // second connection: the server has NO credential, so it can only complete by
  // accepting the PSK (a full handshake would need a certificate)
  LClient := NewClient(LCache);
  LServer := NewServer(LStore, 0, 7200, False);
  DriveHandshake(LClient, LServer);
  CheckFalse(LClient.IsHandshaking, 'the resuming client completed');
  CheckFalse(LServer.IsHandshaking, 'the credential-less server completed via the PSK');
  CheckFalse(LClient.IsTerminal, 'the resuming client did not fail');
  CheckFalse(LServer.IsTerminal, 'the resuming server did not fail');
  CheckTrue(LClient.IsResumed, 'the resuming client reports a resumed handshake');
  CheckTrue(LServer.IsResumed, 'the resuming server reports a resumed handshake');
  CheckEquals(0, LStore.Count, 'the ticket was consumed (single-use)');
  CheckAppDataFlows(LClient, LServer);
end;

procedure TTestTls13Resumption.TestSingleUseTicketReplayRejected;
var
  LCache: ISessionCache;
  LStore: ISessionStore;
  LClient, LServer: ITlsEngine;
  LIdentity: TBytes;
  LSecret: ISecretBuffer;
begin
  // seed a matching client cache entry and server store entry (same identity+secret)
  LIdentity := Provider.GetRandom.GenerateBytes(32);
  LSecret := TSecretBuffer.From(Provider.GetRandom.GenerateBytes(32));
  LCache := TInMemorySessionCache.Create;
  LStore := TInMemorySessionStore.Create(Provider.GetRandom);
  LCache.Store(ServerHost, ServerHost, MakeSession(LIdentity, LSecret, 7200));
  LStore.PutWithId(LIdentity, MakeSession(LIdentity, LSecret, 7200));

  // first use resumes against a credential-less server: completion proves acceptance
  LClient := NewClient(LCache);
  LServer := NewServer(LStore, 0, 7200, False);
  DriveHandshake(LClient, LServer);
  CheckFalse(LServer.IsHandshaking, 'the first use resumed');
  CheckFalse(LServer.IsTerminal, 'the first use did not fail');
  CheckEquals(0, LStore.Count, 'the ticket was consumed');

  // replay the same ticket: the store no longer holds it, so a credential-less server
  // cannot resume and cannot run a full handshake - the replay is rejected
  LCache := TInMemorySessionCache.Create;
  LCache.Store(ServerHost, ServerHost, MakeSession(LIdentity, LSecret, 7200));
  LClient := NewClient(LCache);
  LServer := NewServer(LStore, 0, 7200, False);
  DriveHandshake(LClient, LServer);
  CheckFalse((not LServer.IsHandshaking) and (not LServer.IsTerminal),
    'a replayed single-use ticket is not silently accepted');
end;

procedure TTestTls13Resumption.TestMismatchedBinderAbortsDecryptError;
var
  LCache: ISessionCache;
  LStore: ISessionStore;
  LClient, LServer: ITlsEngine;
  LIdentity: TBytes;
begin
  // the client's cached secret differs from the server's stored secret for the same
  // identity, so the server opens the ticket but its binder does not validate
  LIdentity := Provider.GetRandom.GenerateBytes(32);
  LCache := TInMemorySessionCache.Create;
  LStore := TInMemorySessionStore.Create(Provider.GetRandom);
  LCache.Store(ServerHost, ServerHost, MakeSession(LIdentity,
    TSecretBuffer.From(Filled($AA, 32)), 7200));
  LStore.PutWithId(LIdentity, MakeSession(LIdentity,
    TSecretBuffer.From(Filled($BB, 32)), 7200));

  // a present binder that does not validate against an opened ticket is fatal: the server
  // aborts with decrypt_error rather than silently falling back to a full handshake
  // (RFC 8446 4.2.11.2)
  LClient := NewClient(LCache);
  LServer := NewServer(LStore, 0, 7200, True);
  DriveHandshake(LClient, LServer);
  CheckTrue(LServer.IsTerminal, 'the server aborted on the bad binder');
  CheckTrue(LServer.LastError.Alert.Description = TTlsAlertDescription.DecryptError,
    'the server sent decrypt_error');
end;

procedure TTestTls13Resumption.TestExpiredTicketNotAccepted;
var
  LCache: ISessionCache;
  LStore: ISessionStore;
  LClient, LServer: ITlsEngine;
  LIdentity: TBytes;
  LSecret: ISecretBuffer;
begin
  // an expired ticket (lifetime 0) against a credential-less server: the server must
  // reject the PSK on freshness and then cannot run a full handshake, so it does not
  // complete - proving the expired ticket was not accepted
  LIdentity := Provider.GetRandom.GenerateBytes(32);
  LSecret := TSecretBuffer.From(Provider.GetRandom.GenerateBytes(32));
  LCache := TInMemorySessionCache.Create;
  LStore := TInMemorySessionStore.Create(Provider.GetRandom);
  LCache.Store(ServerHost, ServerHost, MakeSession(LIdentity, LSecret, 0));
  LStore.PutWithId(LIdentity, MakeSession(LIdentity, LSecret, 0));

  LClient := NewClient(LCache);
  LServer := NewServer(LStore, 0, 0, False);
  DriveHandshake(LClient, LServer);
  CheckFalse((not LServer.IsHandshaking) and (not LServer.IsTerminal),
    'an expired ticket is not accepted');
end;

procedure TTestTls13Resumption.TestCustomSessionCacheAndStoreAreUsed;
var
  LCacheImpl: TMockSessionCache;
  LStoreImpl: TMockSessionStore;
  LCache: ISessionCache;
  LStore: ISessionStore;
  LClient, LServer: ITlsEngine;
begin
  // a user's own ISessionCache/ISessionStore implementations, injected the same way as
  // the shipped defaults; the interface references govern lifetime
  LCacheImpl := TMockSessionCache.Create;
  LCache := LCacheImpl;
  LStoreImpl := TMockSessionStore.Create;
  LStore := LStoreImpl;

  // first connection: a full handshake issues a ticket through the custom store/cache
  LClient := NewClient(LCache);
  LServer := NewServer(LStore, 1, 7200, True);
  DriveHandshake(LClient, LServer);
  CheckEquals(1, LCache.Count, 'the custom cache received the ticket');
  CheckEquals(1, LStore.Count, 'the custom store received the session');

  // second connection resumes: a credential-less server can only complete if the engine
  // actually consulted the custom store and cache
  LClient := NewClient(LCache);
  LServer := NewServer(LStore, 0, 7200, False);
  DriveHandshake(LClient, LServer);
  CheckFalse(LServer.IsHandshaking, 'the resume completed through the custom store');
  CheckFalse(LServer.IsTerminal, 'no failure resuming through the custom implementations');
  CheckTrue(LStoreImpl.TakeCount >= 1, 'the engine invoked the custom store Take');
  CheckTrue(LCacheImpl.TakeCount >= 1, 'the engine invoked the custom cache Take');
  CheckAppDataFlows(LClient, LServer);
end;

procedure TTestTls13Resumption.TestStatelessStekResumptionCompletes;
var
  LStek: ISessionTicketKeyManager;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
begin
  // the default (no store) strategy: AEAD-sealed tickets under a shared STEK, no
  // server-side storage
  LStek := TStekTicketKeyManager.Create(Provider.GetRandom);
  LCache := TInMemorySessionCache.Create;

  LClient := NewClient(LCache);
  LServer := NewStekServer(LStek, 1, 7200, True);
  DriveHandshake(LClient, LServer);
  CheckEquals(1, LCache.Count, 'the client cached the STEK ticket');

  // credential-less: completion proves the sealed ticket was opened and accepted
  LClient := NewClient(LCache);
  LServer := NewStekServer(LStek, 0, 7200, False);
  DriveHandshake(LClient, LServer);
  CheckFalse(LServer.IsHandshaking, 'the stateless STEK resume completed');
  CheckFalse(LServer.IsTerminal, 'no failure resuming under the STEK');
  CheckAppDataFlows(LClient, LServer);
end;

procedure TTestTls13Resumption.TestStekRetiredKeyNotAccepted;
var
  LStek: ISessionTicketKeyManager;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
  LI: Int32;
begin
  LStek := TStekTicketKeyManager.Create(Provider.GetRandom);
  LCache := TInMemorySessionCache.Create;

  // issue a real STEK ticket
  LClient := NewClient(LCache);
  LServer := NewStekServer(LStek, 1, 7200, True);
  DriveHandshake(LClient, LServer);
  CheckEquals(1, LCache.Count, 'a STEK ticket was issued');

  // rotate the STEK until the issuing key falls out of the decrypt window
  for LI := 0 to 5 do
    LStek.Rotate;

  // the sealed ticket's key is gone: a credential-less server cannot open it and cannot
  // run a full handshake, so it does not complete
  LClient := NewClient(LCache);
  LServer := NewStekServer(LStek, 0, 7200, False);
  DriveHandshake(LClient, LServer);
  CheckFalse((not LServer.IsHandshaking) and (not LServer.IsTerminal),
    'a ticket sealed under a retired STEK key is not accepted');
end;

procedure TTestTls13Resumption.TestStekInvalidTicketFallsBackToFullHandshake;
var
  LStek: ISessionTicketKeyManager;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
begin
  // a client offering a garbage "ticket" that is not a valid STEK seal
  LStek := TStekTicketKeyManager.Create(Provider.GetRandom);
  LCache := TInMemorySessionCache.Create;
  LCache.Store(ServerHost, ServerHost, MakeSession(
    Provider.GetRandom.GenerateBytes(48),
    TSecretBuffer.From(Provider.GetRandom.GenerateBytes(32)), 7200));

  // the server cannot open the bogus ticket and completes a full handshake instead
  LClient := NewClient(LCache);
  LServer := NewStekServer(LStek, 0, 7200, True);
  DriveHandshake(LClient, LServer);
  CheckFalse(LClient.IsHandshaking, 'the client completed a full handshake');
  CheckFalse(LServer.IsHandshaking, 'the server completed a full handshake');
  CheckFalse(LServer.IsTerminal, 'an unopenable ticket is not fatal');
  CheckAppDataFlows(LClient, LServer);
end;

procedure TTestTls13Resumption.TestStoreUpgradesOverStek;
var
  LStek: ISessionTicketKeyManager;
  LStore: ISessionStore;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
begin
  // configuring both a STEK and a store upgrades to the stateful single-use store
  LStek := TStekTicketKeyManager.Create(Provider.GetRandom);
  LStore := TInMemorySessionStore.Create(Provider.GetRandom);
  LCache := TInMemorySessionCache.Create;

  LClient := NewClient(LCache);
  LServer := BuildServer(LStek, LStore, 1, 7200, True);
  DriveHandshake(LClient, LServer);
  CheckEquals(1, LStore.Count, 'the store (not the STEK) issued the ticket');

  LClient := NewClient(LCache);
  LServer := BuildServer(LStek, LStore, 0, 7200, False);
  DriveHandshake(LClient, LServer);
  CheckFalse(LServer.IsHandshaking, 'the store-backed resume completed');
  CheckEquals(0, LStore.Count, 'the store ticket was consumed (single-use), proving the upgrade');
end;

procedure TTestTls13Resumption.TestZeroRttAcceptedDeliversEarlyData;
var
  LStek: ISessionTicketKeyManager;
  LAnti: IAntiReplayStrategy;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
  LEarly: TBytes;
begin
  LStek := TStekTicketKeyManager.Create(Provider.GetRandom);
  LAnti := TStrikeRegisterAntiReplay.Create;
  LCache := TInMemorySessionCache.Create;

  // first connection: a full handshake issues a ticket authorizing 0-RTT
  LClient := NewClient(LCache, False);
  LServer := BuildServer(LStek, nil, 1, 7200, True, 16384, LAnti);
  DriveHandshake(LClient, LServer);
  CheckEquals(1, LCache.Count, 'a 0-RTT-capable ticket was cached');

  // second connection: send 0-RTT early data. The server has no credential, so it can
  // only complete by accepting the PSK, and the early data must decrypt under the early keys
  LClient := NewClient(LCache, True);
  LServer := BuildServer(LStek, nil, 0, 7200, False, 16384, LAnti);
  LEarly := DecodeHex('30525454206561726c792064617461'); // "0RTT early data"
  LClient.StartHandshake;
  LClient.WriteEarlyData(LEarly, 0, System.Length(LEarly));
  PumpToCompletion(LClient, LServer);
  CheckFalse(LClient.IsHandshaking, 'the 0-RTT client completed');
  CheckFalse(LServer.IsHandshaking, 'the credential-less server completed via 0-RTT');
  CheckFalse(LServer.IsTerminal, 'no failure on 0-RTT');
  CheckEqualBytes('the server received the early data as 0-RTT', LEarly,
    ReadAllApp(LServer));
end;

procedure TTestTls13Resumption.TestZeroRttRejectedIsDiscardedNotReplayed;
var
  LStek: ISessionTicketKeyManager;
  LAnti: IAntiReplayStrategy;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
  LEarly: TBytes;
begin
  LStek := TStekTicketKeyManager.Create(Provider.GetRandom);
  LAnti := TStrikeRegisterAntiReplay.Create;
  LCache := TInMemorySessionCache.Create;

  // issue a 0-RTT-capable ticket
  LClient := NewClient(LCache, False);
  LServer := BuildServer(LStek, nil, 1, 7200, True, 16384, LAnti);
  DriveHandshake(LClient, LServer);

  // resume and send 0-RTT, but the server rejects early data (MaxEarlyData 0). The rejected
  // early data went out under the early keys and the server skips it; the engine does NOT
  // transparently replay it as 1-RTT (RFC 8446 2.3 leaves any resend to the application, as
  // rustls does), so nothing is delivered to the server for it.
  LClient := NewClient(LCache, True);
  LServer := BuildServer(LStek, nil, 0, 7200, False, 0, LAnti);
  LEarly := DecodeHex('7265706c617965642064617461'); // "replayed data"
  LClient.StartHandshake;
  LClient.WriteEarlyData(LEarly, 0, System.Length(LEarly));
  PumpToCompletion(LClient, LServer);
  CheckFalse(LServer.IsHandshaking, 'the resumption completed despite the 0-RTT reject');
  CheckFalse(LServer.IsTerminal, 'the reject is not fatal');
  CheckEquals(0, System.Length(ReadAllApp(LServer)),
    'the rejected early data is discarded, not auto-replayed as 1-RTT');
end;

procedure TTestTls13Resumption.TestZeroRttReplayCaughtByStrikeRegister;
var
  LStek: ISessionTicketKeyManager;
  LAnti: IAntiReplayStrategy;
  LCache: ISessionCache;
  LClient, LServerA, LServerB: ITlsEngine;
  LEarly, LFlight: TBytes;
begin
  LStek := TStekTicketKeyManager.Create(Provider.GetRandom);
  LAnti := TStrikeRegisterAntiReplay.Create;
  LCache := TInMemorySessionCache.Create;

  LClient := NewClient(LCache, False);
  LServerA := BuildServer(LStek, nil, 1, 7200, True, 16384, LAnti);
  DriveHandshake(LClient, LServerA);

  // capture the exact 0-RTT client flight (ClientHello + CCS + early records)
  LClient := NewClient(LCache, True);
  LServerA := BuildServer(LStek, nil, 0, 7200, False, 16384, LAnti);
  LEarly := DecodeHex('7265706c61792061747461636b'); // "replay attack"
  LClient.StartHandshake;
  LClient.WriteEarlyData(LEarly, 0, System.Length(LEarly));
  LFlight := Drain(LClient);

  // the first server accepts the early data (records the binder in the register)
  Feed(LServerA, LFlight);
  CheckEqualBytes('the first use delivers the early data', LEarly,
    ReadAllApp(LServerA));

  // replaying the identical flight to another server sharing the register: the binder is
  // a strike, so 0-RTT is rejected and the early data is skipped, not delivered
  LServerB := BuildServer(LStek, nil, 0, 7200, False, 16384, LAnti);
  Feed(LServerB, LFlight);
  CheckEquals(0, System.Length(ReadAllApp(LServerB)),
    'a replayed 0-RTT flight is caught by the strike register and skipped');
end;

procedure TTestTls13Resumption.TestEarlyDataOffByDefault;
var
  LStek: ISessionTicketKeyManager;
  LAnti: IAntiReplayStrategy;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
  LEarly: TBytes;
begin
  LStek := TStekTicketKeyManager.Create(Provider.GetRandom);
  LAnti := TStrikeRegisterAntiReplay.Create;
  LCache := TInMemorySessionCache.Create;

  // the issued ticket authorizes 0-RTT, but the client does not enable it
  LClient := NewClient(LCache, False);
  LServer := BuildServer(LStek, nil, 1, 7200, True, 16384, LAnti);
  DriveHandshake(LClient, LServer);

  LClient := NewClient(LCache, False); // early data NOT enabled, even though allowed
  LServer := BuildServer(LStek, nil, 0, 7200, False, 16384, LAnti);
  LEarly := DecodeHex('6e6f742073656e74'); // "not sent"
  LClient.StartHandshake;
  LClient.WriteEarlyData(LEarly, 0, System.Length(LEarly)); // a no-op: no early epoch
  PumpToCompletion(LClient, LServer);
  CheckFalse(LServer.IsHandshaking, 'the resumption completed without any early data');
  CheckEquals(0, System.Length(ReadAllApp(LServer)),
    'no early data was sent when 0-RTT was not enabled');
  CheckAppDataFlows(LClient, LServer);
end;

procedure TTestTls13Resumption.TestMutualAuthResumptionCompletes;
var
  LStek: ISessionTicketKeyManager;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;

  function BuildMtlsClient: ITlsEngine;
  var
    LP: TClientHandshakeParams;
  begin
    LP := Default(TClientHandshakeParams);
    LP.Clock := TSystemClock.Create;
    LP.Provider := Provider;
    LP.Group := TNamedGroups.CreateX25519(Provider);
    LP.GroupCode := TNamedGroupCatalog.X25519;
    LP.CipherSuites := TCipherSuiteRegistry.CreateDefault(Provider);
    LP.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
    LP.OfferedSuites := TArray<UInt16>.Create(TCipherSuites13.Aes128GcmSha256);
    LP.OfferedSchemes := TArray<UInt16>.Create(TSignatureSchemes.EcdsaSecp256r1Sha256);
    LP.ClientRandom := Provider.GetRandom.GenerateBytes(32);
    LP.LegacySessionId := Filled($33, 32);
    LP.CertificateVerifier := TCertificateVerifier.Create(Provider, TSystemClock.Create as ITlsClock,
      TTrustAnchorStore.Create(TArray<TBytes>.Create(TestRootCertificate))
      as ITrustAnchorStore, True) as ICertificateVerifier;
    LP.ExpectedHostName := ServerHost;
    LP.ServerName := ServerHost;
    LP.SessionCache := LCache;
    LP.ClientCredential := ServerCredential; // present the leaf as the client certificate
    Result := TTlsEngine.CreateConfigured(
      TTls13ClientStateMachine.Create(LP) as IHandshakeMachine, Provider);
  end;

  function BuildMtlsStekServer(AIssue: Int32; AWithCredential: Boolean): ITlsEngine;
  var
    LP: TServerHandshakeParams;
  begin
    LP := Default(TServerHandshakeParams);
    LP.Clock := TSystemClock.Create;
    LP.Provider := Provider;
    LP.Policy := TNegotiationPolicy.CreateDefault(Provider);
    LP.CipherSuites := TCipherSuiteRegistry.CreateDefault(Provider);
    LP.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
    LP.Group := TNamedGroups.CreateX25519(Provider);
    LP.ServerRandom := Provider.GetRandom.GenerateBytes(32);
    if AWithCredential then
      LP.CredentialResolver := TSniCredentialResolver.ForCredential(ServerCredential);
    LP.SessionTicketKeys := LStek;
    LP.IssueTicketCount := AIssue;
    LP.TicketLifetimeSeconds := 7200;
    // mutual TLS: require and verify the client certificate against the root
    LP.ClientAuth := TClientAuthMode.Required;
    LP.ClientAuthSignatureSchemes := TArray<UInt16>.Create(
      TSignatureSchemes.EcdsaSecp256r1Sha256);
    LP.ClientCertificateVerifier := TCertificateVerifier.Create(Provider, TSystemClock.Create as ITlsClock,
      TTrustAnchorStore.Create(TArray<TBytes>.Create(TestRootCertificate))
      as ITrustAnchorStore, False) as ICertificateVerifier;
    Result := TTlsEngine.CreateConfigured(
      TTls13ServerStateMachine.Create(LP) as IHandshakeMachine, Provider);
  end;

begin
  LStek := TStekTicketKeyManager.Create(Provider.GetRandom);
  LCache := TInMemorySessionCache.Create;

  // a full mutual-TLS handshake: the server verifies the client certificate and issues a ticket
  LClient := BuildMtlsClient;
  LServer := BuildMtlsStekServer(1, True);
  DriveHandshake(LClient, LServer);
  CheckFalse(LServer.IsHandshaking, 'the full mutual-TLS handshake completed');
  CheckEquals(1, LCache.Count, 'the client cached the ticket');

  // resume: client authentication is NOT re-done on a PSK resumption, so the server must not
  // wait for a client Certificate (regression: it used to park in WaitClientCertificate and
  // abort with unexpected_message when the client's Finished arrived). A credential-less
  // server proves completion came from the accepted PSK.
  LClient := BuildMtlsClient;
  LServer := BuildMtlsStekServer(0, False);
  DriveHandshake(LClient, LServer);
  CheckFalse(LServer.IsHandshaking, 'the mutual-TLS resumption completed');
  CheckFalse(LServer.IsTerminal, 'no failure resuming a mutual-TLS session');
  CheckAppDataFlows(LClient, LServer);
end;

procedure TTestTls13Resumption.TestTicketIssuedUnderDifferentSniFallsBackToFullHandshake;
var
  LCache: ISessionCache;
  LStore: ISessionStore;
  LClient, LServer: ITlsEngine;
  LIdentity: TBytes;
  LSecret: ISecretBuffer;
begin
  // the cross-host resumption guard: a ticket the server issued while serving one host must not
  // resume a connection that requests a different host (RFC 6066 3), even with a matching binder.
  // The client always requests ServerHost, so the server-stored session carries the issuing host
  LIdentity := Provider.GetRandom.GenerateBytes(32);
  LSecret := TSecretBuffer.From(Provider.GetRandom.GenerateBytes(32));

  // control: issued under the requested host -> resumes
  LCache := TInMemorySessionCache.Create;
  LStore := TInMemorySessionStore.Create(Provider.GetRandom);
  LCache.Store(ServerHost, ServerHost, MakeSession(LIdentity, LSecret, 7200));
  LStore.PutWithId(LIdentity, MakeSessionForHost(LIdentity, LSecret, 7200, ServerHost));
  LClient := NewClient(LCache);
  LServer := NewServer(LStore, 0, 7200, True);
  DriveHandshake(LClient, LServer);
  CheckTrue(LServer.IsResumed, 'a ticket issued under the requested host resumes');

  // guarded: issued under a different host -> the credentialed server ignores the PSK and runs a
  // full handshake instead of resuming under the wrong identity
  LCache := TInMemorySessionCache.Create;
  LStore := TInMemorySessionStore.Create(Provider.GetRandom);
  LCache.Store(ServerHost, ServerHost, MakeSession(LIdentity, LSecret, 7200));
  LStore.PutWithId(LIdentity, MakeSessionForHost(LIdentity, LSecret, 7200, 'other.example'));
  LClient := NewClient(LCache);
  LServer := NewServer(LStore, 0, 7200, True);
  DriveHandshake(LClient, LServer);
  CheckFalse(LServer.IsHandshaking, 'the guarded handshake completed');
  CheckFalse(LServer.IsTerminal, 'the guarded handshake did not fail');
  CheckFalse(LServer.IsResumed, 'a ticket issued under a different host does not resume');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestTls13Resumption);
{$ELSE}
  RegisterTest(TTestTls13Resumption.Suite);
{$ENDIF FPC}

end.
