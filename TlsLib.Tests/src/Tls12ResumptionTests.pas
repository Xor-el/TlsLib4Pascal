{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit Tls12ResumptionTests;

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
  TlpTlsVersion,
  TlpICryptoProvider,
  TlpISecretBuffer,
  TlpSecretBuffer,
  TlpCryptoAlgorithms,
  TlpNamedGroups,
  TlpNegotiationTypes,
  TlpCipherSuiteRegistry,
  TlpCoreExtensions,
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
  TlpTls12ClientStateMachine,
  TlpTls12ServerStateMachine,
  TlpTls13ClientStateMachine,
  TlpVersionDispatchMachine,
  TlsLibTestBase;

type
  TTestTls12Resumption = class(TTlsLibAlgorithmTestCase)
  private const
    TlsSuite = TCipherSuites12.EcdheEcdsaAes128GcmSha256;
    ServerHost = 'localhost';
  private
    function TestRootCertificate: TBytes;
    function ServerCredential: TTlsCredential;
    function NewClient(const ACache: ISessionCache; AOfferEms: Boolean): ITlsEngine;
    /// <summary>A dual-version client (offers TLS 1.3 and 1.2 in one ClientHello) drawing
    /// from and storing into ACache; against a 1.2-only server it negotiates 1.2 and can
    /// resume a cached 1.2 session.</summary>
    function NewDualVersionClient(const ACache: ISessionCache): ITlsEngine;
    /// <summary>A TLS 1.2 server: AStore drives session-id resumption, AStek stateless
    /// tickets; AWithCredential=False makes it credential-less (cannot run a full
    /// handshake).</summary>
    function NewServer(const AStore: ISessionStore;
      const AStek: ISessionTicketKeyManager; ALifetime: UInt32;
      AWithCredential: Boolean): ITlsEngine;
    function Drain(const AEngine: ITlsEngine): TBytes;
    procedure Feed(const AEngine: ITlsEngine; const AWire: TBytes);
    procedure Pump(const ASrc, ADst: ITlsEngine);
    procedure PumpToCompletion(const AClient, AServer: ITlsEngine);
    function ReadAllApp(const AEngine: ITlsEngine): TBytes;
    procedure CheckAppDataFlows(const AClient, AServer: ITlsEngine);
    /// <summary>Whether a plaintext handshake flight carries a Certificate (type 11): a
    /// full handshake does, an abbreviated (resumed) handshake does not.</summary>
    function FlightHasCertificate(const AWire: TBytes): Boolean;
    /// <summary>Runs the client and server to completion and reports whether the server's
    /// first response flight contained a Certificate (i.e. it ran a full handshake).</summary>
    function DriveObservingServerCert(const AClient, AServer: ITlsEngine): Boolean;
    function MakeTicketSession(const ATicket: TBytes;
      AExtendedMasterSecret: Boolean): IResumableSession;
    function MakeStoredSession(const AIdentity: TBytes; const ASecret: ISecretBuffer;
      const AHost: string): IResumableSession;
  published
    procedure TestSessionIdResumeIsAbbreviated;
    procedure TestTicketResumeIsAbbreviated;
    procedure TestResumePreservesExtendedMasterSecretOn;
    procedure TestResumePreservesExtendedMasterSecretOff;
    procedure TestExpiredTicketFallsBackToFullHandshake;
    procedure TestBogusTicketFallsBackToFullHandshake;
    procedure TestNoResumptionWithoutCache;
    procedure TestDualVersionClientResumesTls12;
    procedure TestSessionIssuedUnderDifferentSniFallsBackToFullHandshake;
  end;

implementation

{ TTestTls12Resumption }

function TTestTls12Resumption.TestRootCertificate: TBytes;
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

function TTestTls12Resumption.ServerCredential: TTlsCredential;
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

function TTestTls12Resumption.NewClient(const ACache: ISessionCache;
  AOfferEms: Boolean): ITlsEngine;
var
  LParams: TClient12HandshakeParams;
begin
  LParams := Default(TClient12HandshakeParams);
  LParams.Clock := TSystemClock.Create;
  LParams.Provider := Provider;
  LParams.GroupRegistry := TNamedGroups.CreateDefaultRegistry(Provider);
  LParams.CipherSuites := TCipherSuiteRegistry.CreateDualVersion(Provider);
  LParams.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  LParams.OfferedSuites := TArray<UInt16>.Create(TlsSuite);
  // TLS 1.2 supported_groups gates both the ECDHE key-exchange group and the ECDSA leaf's
  // curve (RFC 8422 5.1), so it lists X25519 and Secp256r1 (the P-256 certificate curve)
  LParams.OfferedGroups := TArray<UInt16>.Create(TNamedGroupCatalog.X25519,
    TNamedGroupCatalog.Secp256r1);
  LParams.OfferedSchemes := TArray<UInt16>.Create(
    TSignatureSchemes.EcdsaSecp256r1Sha256);
  LParams.OfferedVersions := TArray<UInt16>.Create(TlsWireVersionTls12);
  LParams.ClientRandom := Provider.GetRandom.GenerateBytes(32);
  LParams.OfferExtendedMasterSecret := AOfferEms;
  LParams.CertificateVerifier := TCertificateVerifier.Create(Provider, TSystemClock.Create as ITlsClock,
    TTrustAnchorStore.Create(TArray<TBytes>.Create(TestRootCertificate))
    as ITrustAnchorStore, True) as ICertificateVerifier;
  LParams.ExpectedHostName := ServerHost;
  LParams.ServerName := ServerHost;
  LParams.ServerIdentity := ServerHost + ':443';
  LParams.SessionCache := ACache;
  Result := TTlsEngine.CreateConfigured(
    TTls12ClientStateMachine.Create(LParams) as IHandshakeMachine, Provider);
end;

function TTestTls12Resumption.NewDualVersionClient(
  const ACache: ISessionCache): ITlsEngine;
var
  L13: TClientHandshakeParams;
  L12: TClient12HandshakeParams;
  LVerifier: ICertificateVerifier;
  LRandom, LSessionId: TBytes;
begin
  LVerifier := TCertificateVerifier.Create(Provider, TSystemClock.Create as ITlsClock,
    TTrustAnchorStore.Create(TArray<TBytes>.Create(TestRootCertificate))
    as ITrustAnchorStore, True) as ICertificateVerifier;
  // the dispatcher sends one unified ClientHello, so both sub-machines must share the same
  // client_random and legacy_session_id (the abbreviated Finished MAC binds them)
  LRandom := Provider.GetRandom.GenerateBytes(32);
  LSessionId := Provider.GetRandom.GenerateBytes(32);

  L13 := Default(TClientHandshakeParams);
  L13.Clock := TSystemClock.Create;
  L13.Provider := Provider;
  L13.Group := TNamedGroups.CreateX25519(Provider);
  L13.GroupCode := TNamedGroupCatalog.X25519;
  // the unified ClientHello carries the 1.3 machine's supported_groups, which for a 1.2
  // fallback with a P-256 ECDSA server certificate must also list Secp256r1 - TLS 1.2
  // gates the ECDSA leaf's curve on supported_groups (RFC 8422 5.4); the key_share stays
  // X25519-only
  L13.OfferedGroups := TArray<UInt16>.Create(TNamedGroupCatalog.X25519,
    TNamedGroupCatalog.Secp256r1);
  L13.GroupRegistry := TNamedGroups.CreateDefaultRegistry(Provider);
  L13.CipherSuites := TCipherSuiteRegistry.CreateDualVersion(Provider);
  L13.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  L13.OfferedSuites := TArray<UInt16>.Create(TCipherSuites13.Aes128GcmSha256, TlsSuite);
  L13.OfferedSchemes := TArray<UInt16>.Create(TSignatureSchemes.EcdsaSecp256r1Sha256);
  L13.ClientRandom := LRandom;
  L13.LegacySessionId := LSessionId;
  L13.ServerName := ServerHost;
  L13.CertificateVerifier := LVerifier;
  L13.ExpectedHostName := ServerHost;
  L13.ServerIdentity := ServerHost + ':443';
  L13.SessionCache := ACache;

  L12 := Default(TClient12HandshakeParams);
  L12.Clock := TSystemClock.Create;
  L12.Provider := Provider;
  L12.GroupRegistry := TNamedGroups.CreateDefaultRegistry(Provider);
  L12.CipherSuites := TCipherSuiteRegistry.CreateDualVersion(Provider);
  L12.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  L12.OfferedSuites := TArray<UInt16>.Create(TlsSuite);
  L12.OfferedGroups := TArray<UInt16>.Create(TNamedGroupCatalog.X25519,
    TNamedGroupCatalog.Secp256r1);
  L12.OfferedSchemes := TArray<UInt16>.Create(TSignatureSchemes.EcdsaSecp256r1Sha256);
  L12.OfferedVersions := TArray<UInt16>.Create(TlsWireVersionTls13, TlsWireVersionTls12);
  L12.ClientRandom := LRandom;
  L12.LegacySessionId := LSessionId;
  L12.ServerName := ServerHost;
  L12.OfferExtendedMasterSecret := True;
  L12.CertificateVerifier := LVerifier;
  L12.ExpectedHostName := ServerHost;
  L12.ServerIdentity := ServerHost + ':443';
  L12.SessionCache := ACache;

  Result := TTlsEngine.CreateConfigured(
    TClientVersionDispatchMachine.Create(L13, L12) as IHandshakeMachine, Provider);
end;

function TTestTls12Resumption.NewServer(const AStore: ISessionStore;
  const AStek: ISessionTicketKeyManager; ALifetime: UInt32;
  AWithCredential: Boolean): ITlsEngine;
var
  LParams: TServer12HandshakeParams;
begin
  LParams := Default(TServer12HandshakeParams);
  LParams.Clock := TSystemClock.Create;
  LParams.Provider := Provider;
  LParams.CipherSuites := TCipherSuiteRegistry.CreateDualVersion(Provider);
  LParams.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  LParams.Group := TNamedGroups.CreateX25519(Provider);
  LParams.ServerRandom := Provider.GetRandom.GenerateBytes(32);
  if AWithCredential then
    LParams.CredentialResolver := TSniCredentialResolver.ForCredential(ServerCredential);
  LParams.SessionStore := AStore;
  LParams.SessionTicketKeys := AStek;
  LParams.TicketLifetimeSeconds := ALifetime;
  Result := TTlsEngine.CreateConfigured(
    TTls12ServerStateMachine.Create(LParams) as IHandshakeMachine, Provider);
end;

function TTestTls12Resumption.Drain(const AEngine: ITlsEngine): TBytes;
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

procedure TTestTls12Resumption.Feed(const AEngine: ITlsEngine; const AWire: TBytes);
var
  LPos, LLen: Int32;
begin
  // one record at a time so an epoch installed while processing one record is active
  // for the next
  LPos := 0;
  while LPos + 5 <= System.Length(AWire) do
  begin
    LLen := (AWire[LPos + 3] shl 8) or AWire[LPos + 4];
    AEngine.ProcessInput(AWire, LPos, 5 + LLen);
    Inc(LPos, 5 + LLen);
  end;
end;

procedure TTestTls12Resumption.Pump(const ASrc, ADst: ITlsEngine);
begin
  Feed(ADst, Drain(ASrc));
end;

procedure TTestTls12Resumption.PumpToCompletion(const AClient, AServer: ITlsEngine);
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
end;

function TTestTls12Resumption.ReadAllApp(const AEngine: ITlsEngine): TBytes;
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

procedure TTestTls12Resumption.CheckAppDataFlows(const AClient, AServer: ITlsEngine);
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

function TTestTls12Resumption.FlightHasCertificate(const AWire: TBytes): Boolean;
var
  LPos, LRecLen, LInner, LMsgLen, LBodyEnd: Int32;
begin
  Result := False;
  LPos := 0;
  while LPos + 5 <= System.Length(AWire) do
  begin
    LRecLen := (AWire[LPos + 3] shl 8) or AWire[LPos + 4];
    // handshake records are plaintext only up to the ChangeCipherSpec; stop there so the
    // encrypted Finished that follows is not misread as plaintext handshake messages
    if AWire[LPos] = 20 then
      Exit;
    if AWire[LPos] = 22 then
    begin
      LInner := LPos + 5;
      while LInner + 4 <= LPos + 5 + LRecLen do
      begin
        LMsgLen := (AWire[LInner + 1] shl 16) or (AWire[LInner + 2] shl 8) or
          AWire[LInner + 3];
        LBodyEnd := LInner + 4 + LMsgLen;
        if AWire[LInner] = 11 then // Certificate
          Exit(True);
        LInner := LBodyEnd;
      end;
    end;
    Inc(LPos, 5 + LRecLen);
  end;
end;

function TTestTls12Resumption.DriveObservingServerCert(
  const AClient, AServer: ITlsEngine): Boolean;
var
  LFlight: TBytes;
  LIterations: Int32;
begin
  AClient.StartHandshake;
  // the server consumes the ClientHello and queues its first response flight
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

function TTestTls12Resumption.MakeTicketSession(const ATicket: TBytes;
  AExtendedMasterSecret: Boolean): IResumableSession;
begin
  Result := TResumableSession.CreateTls12(TlsSuite, THashAlgorithm.SHA_256,
    TSecretBuffer.From(Provider.GetRandom.GenerateBytes(48)), nil, ATicket,
    AExtendedMasterSecret, '', '', 7200, 0, UInt64(TDateTimeUtilities.CurrentUnixMs));
end;

function TTestTls12Resumption.MakeStoredSession(const AIdentity: TBytes;
  const ASecret: ISecretBuffer; const AHost: string): IResumableSession;
begin
  // a session-id session (RFC 5246 7.3): the id resumes via the store, AHost is the host it was
  // issued under and what the cross-host guard checks
  Result := TResumableSession.CreateTls12(TlsSuite, THashAlgorithm.SHA_256, ASecret, AIdentity,
    nil, True, '', AHost, 7200, 0, UInt64(TDateTimeUtilities.CurrentUnixMs));
end;

procedure TTestTls12Resumption.TestSessionIdResumeIsAbbreviated;
var
  LCache: ISessionCache;
  LStore: ISessionStore;
  LClient, LServer: ITlsEngine;
begin
  // a store (no STEK) drives session-id resumption (RFC 5246 7.3)
  LCache := TInMemorySessionCache.Create;
  LStore := TInMemorySessionStore.Create(Provider.GetRandom);

  LClient := NewClient(LCache, True);
  LServer := NewServer(LStore, nil, 7200, True);
  LClient.StartHandshake;
  PumpToCompletion(LClient, LServer);
  CheckFalse(LClient.IsHandshaking, 'the initial handshake completed');
  CheckEquals(1, LCache.Count, 'the client cached the session id');
  CheckEquals(1, LStore.Count, 'the server stored the session under its id');

  // resume: the credentialed server still resumes; the abbreviated flight omits the
  // Certificate, which proves it did not silently fall back to a full handshake
  LClient := NewClient(LCache, True);
  LServer := NewServer(LStore, nil, 7200, True);
  CheckFalse(DriveObservingServerCert(LClient, LServer),
    'session-id resumption is abbreviated (no Certificate)');
  CheckFalse(LClient.IsHandshaking, 'the resuming client completed');
  CheckFalse(LServer.IsHandshaking, 'the resuming server completed');
  CheckFalse(LClient.IsTerminal, 'the resuming client did not fail');
  CheckFalse(LServer.IsTerminal, 'the resuming server did not fail');
  CheckAppDataFlows(LClient, LServer);
end;

procedure TTestTls12Resumption.TestTicketResumeIsAbbreviated;
var
  LStek: ISessionTicketKeyManager;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
begin
  // a STEK (no store) drives stateless RFC 5077 ticket resumption
  LStek := TStekTicketKeyManager.Create(Provider.GetRandom);
  LCache := TInMemorySessionCache.Create;

  LClient := NewClient(LCache, True);
  LServer := NewServer(nil, LStek, 7200, True);
  LClient.StartHandshake;
  PumpToCompletion(LClient, LServer);
  CheckEquals(1, LCache.Count, 'the client cached the issued ticket');

  LClient := NewClient(LCache, True);
  LServer := NewServer(nil, LStek, 7200, True);
  CheckFalse(DriveObservingServerCert(LClient, LServer),
    'ticket resumption is abbreviated (no Certificate)');
  CheckFalse(LServer.IsHandshaking, 'the ticket resume completed');
  CheckFalse(LServer.IsTerminal, 'the ticket resume did not fail');
  // a fresh ticket is issued on the abbreviated handshake so the session stays resumable
  CheckEquals(1, LCache.Count, 'the client re-cached a renewed ticket');
  CheckAppDataFlows(LClient, LServer);
end;

procedure TTestTls12Resumption.TestResumePreservesExtendedMasterSecretOn;
var
  LStek: ISessionTicketKeyManager;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
begin
  // a session established with Extended Master Secret resumes only when the client
  // re-offers EMS; the abbreviated completion proves the EMS state round-tripped
  LStek := TStekTicketKeyManager.Create(Provider.GetRandom);
  LCache := TInMemorySessionCache.Create;

  LClient := NewClient(LCache, True);
  LServer := NewServer(nil, LStek, 7200, True);
  LClient.StartHandshake;
  PumpToCompletion(LClient, LServer);
  CheckEquals(1, LCache.Count, 'an EMS session was cached');

  LClient := NewClient(LCache, True);
  LServer := NewServer(nil, LStek, 7200, True);
  CheckFalse(DriveObservingServerCert(LClient, LServer),
    'an EMS session resumes abbreviated');
  CheckFalse(LServer.IsTerminal, 'the EMS resume did not fail');
  CheckAppDataFlows(LClient, LServer);
end;

procedure TTestTls12Resumption.TestResumePreservesExtendedMasterSecretOff;
var
  LStek: ISessionTicketKeyManager;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
begin
  // a session established WITHOUT EMS must resume without the client offering EMS on the
  // resumption ClientHello, or the server would decline (RFC 7627 5.3); an abbreviated
  // completion proves the client aligned its EMS offer to the cached session
  LStek := TStekTicketKeyManager.Create(Provider.GetRandom);
  LCache := TInMemorySessionCache.Create;

  LClient := NewClient(LCache, False);
  LServer := NewServer(nil, LStek, 7200, True);
  LClient.StartHandshake;
  PumpToCompletion(LClient, LServer);
  CheckEquals(1, LCache.Count, 'a non-EMS session was cached');

  LClient := NewClient(LCache, False);
  LServer := NewServer(nil, LStek, 7200, True);
  CheckFalse(DriveObservingServerCert(LClient, LServer),
    'a non-EMS session resumes abbreviated');
  CheckFalse(LServer.IsTerminal, 'the non-EMS resume did not fail');
  CheckAppDataFlows(LClient, LServer);
end;

procedure TTestTls12Resumption.TestExpiredTicketFallsBackToFullHandshake;
var
  LStek: ISessionTicketKeyManager;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
begin
  // a zero-lifetime ticket is expired the instant it is sealed; the resuming server must
  // reject it on freshness and complete a full handshake instead
  LStek := TStekTicketKeyManager.Create(Provider.GetRandom);
  LCache := TInMemorySessionCache.Create;

  LClient := NewClient(LCache, True);
  LServer := NewServer(nil, LStek, 0, True);
  LClient.StartHandshake;
  PumpToCompletion(LClient, LServer);
  CheckEquals(1, LCache.Count, 'the expired ticket was cached');

  LClient := NewClient(LCache, True);
  LServer := NewServer(nil, LStek, 0, True);
  CheckTrue(DriveObservingServerCert(LClient, LServer),
    'an expired ticket falls back to a full handshake (Certificate sent)');
  CheckFalse(LClient.IsHandshaking, 'the client completed the full handshake');
  CheckFalse(LServer.IsTerminal, 'an expired ticket is not fatal');
  CheckAppDataFlows(LClient, LServer);
end;

procedure TTestTls12Resumption.TestBogusTicketFallsBackToFullHandshake;
var
  LStek: ISessionTicketKeyManager;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
begin
  // the client presents a ticket that is not a valid STEK seal; the server cannot open it
  // and completes a full handshake
  LStek := TStekTicketKeyManager.Create(Provider.GetRandom);
  LCache := TInMemorySessionCache.Create;
  LCache.Store(ServerHost, ServerHost,
    MakeTicketSession(Provider.GetRandom.GenerateBytes(64), False));

  LClient := NewClient(LCache, True);
  LServer := NewServer(nil, LStek, 7200, True);
  CheckTrue(DriveObservingServerCert(LClient, LServer),
    'a bogus ticket falls back to a full handshake (Certificate sent)');
  CheckFalse(LClient.IsHandshaking, 'the client completed the full handshake');
  CheckFalse(LServer.IsTerminal, 'a bogus ticket is not fatal');
  CheckAppDataFlows(LClient, LServer);
end;

procedure TTestTls12Resumption.TestNoResumptionWithoutCache;
var
  LStore: ISessionStore;
  LClient, LServer: ITlsEngine;
begin
  // with no client cache the client never offers a session id or ticket, so even a
  // store-backed server runs a full handshake
  LStore := TInMemorySessionStore.Create(Provider.GetRandom);
  LClient := NewClient(nil, True);
  LServer := NewServer(LStore, nil, 7200, True);
  CheckTrue(DriveObservingServerCert(LClient, LServer),
    'without a cache the handshake is full (Certificate sent)');
  CheckFalse(LClient.IsHandshaking, 'the no-cache handshake completed');
  CheckFalse(LServer.IsTerminal, 'the no-cache handshake did not fail');
  CheckAppDataFlows(LClient, LServer);
end;

procedure TTestTls12Resumption.TestDualVersionClientResumesTls12;
var
  LCache: ISessionCache;
  LStek: ISessionTicketKeyManager;
  LClient, LServer: ITlsEngine;
begin
  LCache := TInMemorySessionCache.Create;
  LStek := TStekTicketKeyManager.Create(Provider.GetRandom);

  // connection 1: a dual-version client (offers 1.3 + 1.2) meets a 1.2-only server, so it
  // negotiates 1.2 in full and caches the issued 1.2 session
  LClient := NewDualVersionClient(LCache);
  LServer := NewServer(nil, LStek, 7200, True);
  CheckTrue(DriveObservingServerCert(LClient, LServer),
    'the first dual-version handshake is full (the server sends a Certificate)');
  CheckFalse(LClient.IsHandshaking, 'the first dual-version handshake completed');
  CheckEquals(1, LCache.Count, 'the dual-version client cached the 1.2 session');

  // connection 2: a fresh dual-version client sharing the cache offers the cached 1.2
  // session in its unified ClientHello; the 1.2 server resumes it (abbreviated, no
  // Certificate) rather than running another full handshake
  LClient := NewDualVersionClient(LCache);
  LServer := NewServer(nil, LStek, 7200, True);
  CheckFalse(DriveObservingServerCert(LClient, LServer),
    'the resumed dual-version handshake is abbreviated (no server Certificate)');
  CheckFalse(LClient.IsHandshaking, 'the resumed dual-version handshake completed');
  CheckFalse(LServer.IsTerminal, 'the resumed handshake did not fail');
  CheckAppDataFlows(LClient, LServer);
end;

procedure TTestTls12Resumption.TestSessionIssuedUnderDifferentSniFallsBackToFullHandshake;
var
  LCache: ISessionCache;
  LStore: ISessionStore;
  LClient, LServer: ITlsEngine;
  LIdentity: TBytes;
  LSecret: ISecretBuffer;
begin
  // the 1.2 cross-host resumption guard: a session issued while serving one host must not resume
  // a client that requests another (RFC 6066 3). The client always requests ServerHost, so the
  // server-stored session carries the issuing host the guard checks
  LIdentity := Provider.GetRandom.GenerateBytes(32);
  LSecret := TSecretBuffer.From(Provider.GetRandom.GenerateBytes(48));

  // control: issued under the requested host -> resumes (abbreviated, no Certificate)
  LCache := TInMemorySessionCache.Create;
  LStore := TInMemorySessionStore.Create(Provider.GetRandom);
  LCache.Store(ServerHost + ':443', ServerHost, MakeStoredSession(LIdentity, LSecret, ServerHost));
  LStore.PutWithId(LIdentity, MakeStoredSession(LIdentity, LSecret, ServerHost));
  LClient := NewClient(LCache, True);
  LServer := NewServer(LStore, nil, 7200, True);
  CheckFalse(DriveObservingServerCert(LClient, LServer),
    'a session issued under the requested host resumes');
  CheckTrue(LServer.IsResumed, 'the control 1.2 handshake resumed');

  // guarded: issued under a different host -> the credentialed server ignores the session id and
  // runs a full handshake (Certificate sent) instead of resuming under the wrong identity
  LCache := TInMemorySessionCache.Create;
  LStore := TInMemorySessionStore.Create(Provider.GetRandom);
  LCache.Store(ServerHost + ':443', ServerHost, MakeStoredSession(LIdentity, LSecret, ServerHost));
  LStore.PutWithId(LIdentity, MakeStoredSession(LIdentity, LSecret, 'other.example'));
  LClient := NewClient(LCache, True);
  LServer := NewServer(LStore, nil, 7200, True);
  CheckTrue(DriveObservingServerCert(LClient, LServer),
    'a session issued under a different host falls back to a full handshake');
  CheckFalse(LServer.IsResumed, 'a session issued under a different host does not resume');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestTls12Resumption);
{$ELSE}
  RegisterTest(TTestTls12Resumption.Suite);
{$ENDIF FPC}

end.
