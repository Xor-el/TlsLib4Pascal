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
  TlpTlsAlert,
  TlpICryptoProvider,
  TlpISecretBuffer,
  TlpSecretBuffer,
  TlpCryptoDomainTypes,
  TlpNamedGroups,
  TlpNegotiationTypes,
  TlpCipherSuiteRegistry,
  TlpCoreExtensions,
  TlpTlsConnectionInfo,
  TlpITlsEngine,
  TlpTlsEngine,
  TlpIHandshakeMachine,
  TlpICertificateTrust,
  TlpServerName,
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
  // a ticket-key manager that always declines to seal, so the strategy returns an empty ticket
  TDecliningTicketKeys = class sealed(TInterfacedObject, ISessionTicketKeyManager)
  public
    function CurrentKey(out AKeyName: TBytes; out AKey: ISecretBuffer): Boolean;
    function KeyByName(const AKeyName: TBytes; out AKey: ISecretBuffer): Boolean;
    procedure Rotate;
    function KeyNameLength: Int32;
  end;

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
      AWithCredential: Boolean; AEmitSentinel: Boolean = False): ITlsEngine;
    function Drain(const AEngine: ITlsEngine): TBytes;
    procedure Feed(const AEngine: ITlsEngine; const AWire: TBytes);
    procedure Pump(const ASrc, ADst: ITlsEngine);
    procedure PumpToCompletion(const AClient, AServer: ITlsEngine);
    function ReadAllApp(const AEngine: ITlsEngine): TBytes;
    procedure CheckAppDataFlows(const AClient, AServer: ITlsEngine);
    /// <summary>Whether a plaintext handshake flight carries a Certificate (type 11): a
    /// full handshake does, an abbreviated (resumed) handshake does not.</summary>
    function FlightHasCertificate(const AWire: TBytes): Boolean;
    /// <summary>Whether a plaintext handshake flight carries a NewSessionTicket (type 4).</summary>
    function FlightHasNewSessionTicket(const AWire: TBytes): Boolean;
    /// <summary>Runs the client and server to completion and reports whether the server's
    /// first response flight contained a Certificate (i.e. it ran a full handshake).</summary>
    function DriveObservingServerCert(const AClient, AServer: ITlsEngine): Boolean;
    function MakeTicketSession(const ATicket: TBytes;
      AExtendedMasterSecret: Boolean): IResumableSession;
    function MakeStoredSession(const AIdentity: TBytes; const ASecret: ISecretBuffer;
      const AHost: string): IResumableSession;
    // shared mTLS-resumption scaffolding parameterized by the resumption scope
    function LoadClientAuthCredential(out ARootCert: TBytes): TTlsCredential;
    function BuildMtlsClient(const ACache: ISessionCache;
      const ACredential: TTlsCredential): ITlsEngine;
    function BuildMtlsServer(const AStek: ISessionTicketKeyManager;
      AClientAuth: TClientAuthMode; const AClientRoot, AScope: TBytes): ITlsEngine;
  published
    procedure TestSessionIdResumeIsAbbreviated;
    procedure TestTicketResumeIsAbbreviated;
    procedure TestResumePreservesExtendedMasterSecretOn;
    procedure TestResumePreservesExtendedMasterSecretOff;
    procedure TestEmsSessionOfferedWithoutEmsAborts;
    procedure TestNonEmsSessionOfferedWithEmsFallsBackToFullHandshake;
    procedure TestResumptionScopeMismatchDeclinesTicket;
    procedure TestMutualAuthTicketReissueCarriesChain;
    procedure TestDecliningSealStillSendsZeroLengthTicket;
    procedure TestExpiredTicketFallsBackToFullHandshake;
    procedure TestBogusTicketFallsBackToFullHandshake;
    procedure TestNoResumptionWithoutCache;
    procedure TestDualVersionClientResumesTls12;
    procedure TestDualVersionClientAbortsStampedAbbreviatedResumption;
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
    Result.PrivateKey := Crypto.Signing.ImportSigningKey(DecodeHex(LCerts.Values['leaf_key']));
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
  LParams.Crypto := Crypto;
  LParams.Inspector := Pkix.Certificates;
  LParams.GroupRegistry := TNamedGroups.CreateDefaultRegistry(Crypto);
  LParams.CipherSuites := TCipherSuiteRegistry.CreateDualVersion(Crypto);
  LParams.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  LParams.OfferedSuites := TArray<UInt16>.Create(TlsSuite);
  // TLS 1.2 supported_groups gates both the ECDHE key-exchange group and the ECDSA leaf's
  // curve (RFC 8422 5.1), so it lists X25519 and Secp256r1 (the P-256 certificate curve)
  LParams.OfferedGroups := TArray<UInt16>.Create(TNamedGroupCatalog.X25519,
    TNamedGroupCatalog.Secp256r1);
  LParams.OfferedSchemes := TArray<UInt16>.Create(
    TSignatureSchemes.EcdsaSecp256r1Sha256);
  LParams.OfferedVersions := TArray<UInt16>.Create(TlsWireVersionTls12);
  LParams.ClientRandom := Crypto.Primitives.GetRandom.GenerateBytes(32);
  LParams.OfferExtendedMasterSecret := AOfferEms;
  LParams.CertificateVerifier := TCertificateVerifier.Create(Pkix, TSystemClock.Create as ITlsClock,
    TTrustAnchorStore.Create(TArray<TBytes>.Create(TestRootCertificate))
    as ITrustAnchorStore, True) as IServerCertificateVerifier;
  LParams.ExpectedServerName := TServerName.DnsName(ServerHost);
  LParams.ServerName := ServerHost;
  LParams.ServerIdentity := ServerHost + ':443';
  LParams.SessionCache := ACache;
  Result := TTlsEngine.CreateConfigured(
    TTls12ClientStateMachine.Create(LParams) as IHandshakeMachine, Crypto);
end;

function TTestTls12Resumption.NewDualVersionClient(
  const ACache: ISessionCache): ITlsEngine;
var
  L13: TClientHandshakeParams;
  L12: TClient12HandshakeParams;
  LVerifier: IServerCertificateVerifier;
  LRandom, LSessionId: TBytes;
begin
  LVerifier := TCertificateVerifier.Create(Pkix, TSystemClock.Create as ITlsClock,
    TTrustAnchorStore.Create(TArray<TBytes>.Create(TestRootCertificate))
    as ITrustAnchorStore, True) as IServerCertificateVerifier;
  // the dispatcher sends one unified ClientHello, so both sub-machines must share the same
  // client_random and legacy_session_id (the abbreviated Finished MAC binds them)
  LRandom := Crypto.Primitives.GetRandom.GenerateBytes(32);
  LSessionId := Crypto.Primitives.GetRandom.GenerateBytes(32);

  L13 := Default(TClientHandshakeParams);
  L13.Clock := TSystemClock.Create;
  L13.Crypto := Crypto;
  L13.Inspector := Pkix.Certificates;
  L13.Group := TNamedGroups.CreateX25519(Crypto);
  L13.GroupCode := TNamedGroupCatalog.X25519;
  // the unified ClientHello carries the 1.3 machine's supported_groups, which for a 1.2
  // fallback with a P-256 ECDSA server certificate must also list Secp256r1 - TLS 1.2
  // gates the ECDSA leaf's curve on supported_groups (RFC 8422 5.4); the key_share stays
  // X25519-only
  L13.OfferedGroups := TArray<UInt16>.Create(TNamedGroupCatalog.X25519,
    TNamedGroupCatalog.Secp256r1);
  L13.GroupRegistry := TNamedGroups.CreateDefaultRegistry(Crypto);
  L13.CipherSuites := TCipherSuiteRegistry.CreateDualVersion(Crypto);
  L13.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  L13.OfferedSuites := TArray<UInt16>.Create(TCipherSuites13.Aes128GcmSha256, TlsSuite);
  L13.OfferedSchemes := TArray<UInt16>.Create(TSignatureSchemes.EcdsaSecp256r1Sha256);
  L13.ClientRandom := LRandom;
  L13.LegacySessionId := LSessionId;
  L13.ServerName := ServerHost;
  L13.CertificateVerifier := LVerifier;
  L13.ExpectedServerName := TServerName.DnsName(ServerHost);
  L13.ServerIdentity := ServerHost + ':443';
  L13.SessionCache := ACache;

  L12 := Default(TClient12HandshakeParams);
  L12.Clock := TSystemClock.Create;
  L12.Crypto := Crypto;
  L12.Inspector := Pkix.Certificates;
  L12.GroupRegistry := TNamedGroups.CreateDefaultRegistry(Crypto);
  L12.CipherSuites := TCipherSuiteRegistry.CreateDualVersion(Crypto);
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
  L12.ExpectedServerName := TServerName.DnsName(ServerHost);
  L12.ServerIdentity := ServerHost + ':443';
  L12.SessionCache := ACache;

  Result := TTlsEngine.CreateConfigured(
    TClientVersionDispatchMachine.Create(L13, L12) as IHandshakeMachine, Crypto);
end;

function TTestTls12Resumption.NewServer(const AStore: ISessionStore;
  const AStek: ISessionTicketKeyManager; ALifetime: UInt32;
  AWithCredential: Boolean; AEmitSentinel: Boolean): ITlsEngine;
var
  LParams: TServer12HandshakeParams;
begin
  LParams := Default(TServer12HandshakeParams);
  LParams.Clock := TSystemClock.Create;
  LParams.Crypto := Crypto;
  LParams.Inspector := Pkix.Certificates;
  LParams.CipherSuites := TCipherSuiteRegistry.CreateDualVersion(Crypto);
  LParams.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  LParams.Group := TNamedGroups.CreateX25519(Crypto);
  LParams.ServerRandom := Crypto.Primitives.GetRandom.GenerateBytes(32);
  LParams.EmitDowngradeSentinel := AEmitSentinel;
  if AWithCredential then
    LParams.CredentialResolver := TSniCredentialResolver.ForCredential(ServerCredential);
  LParams.SessionStore := AStore;
  LParams.SessionTicketKeys := AStek;
  LParams.TicketLifetimeSeconds := ALifetime;
  Result := TTlsEngine.CreateConfigured(
    TTls12ServerStateMachine.Create(LParams) as IHandshakeMachine, Crypto);
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

function TDecliningTicketKeys.CurrentKey(out AKeyName: TBytes;
  out AKey: ISecretBuffer): Boolean;
begin
  AKeyName := nil;
  AKey := nil;
  Result := False;
end;

function TDecliningTicketKeys.KeyByName(const AKeyName: TBytes;
  out AKey: ISecretBuffer): Boolean;
begin
  AKey := nil;
  Result := False;
end;

procedure TDecliningTicketKeys.Rotate;
begin
end;

function TDecliningTicketKeys.KeyNameLength: Int32;
begin
  Result := 16;
end;

function TTestTls12Resumption.FlightHasNewSessionTicket(const AWire: TBytes): Boolean;
var
  LPos, LRecLen, LInner, LMsgLen: Int32;
begin
  Result := False;
  LPos := 0;
  while LPos + 5 <= System.Length(AWire) do
  begin
    LRecLen := (AWire[LPos + 3] shl 8) or AWire[LPos + 4];
    if AWire[LPos] = 20 then // stop at ChangeCipherSpec; the encrypted flight follows
      Exit;
    if AWire[LPos] = 22 then
    begin
      LInner := LPos + 5;
      while LInner + 4 <= LPos + 5 + LRecLen do
      begin
        LMsgLen := (AWire[LInner + 1] shl 16) or (AWire[LInner + 2] shl 8) or
          AWire[LInner + 3];
        if AWire[LInner] = 4 then // NewSessionTicket
          Exit(True);
        LInner := LInner + 4 + LMsgLen;
      end;
    end;
    Inc(LPos, 5 + LRecLen);
  end;
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
    TSecretBuffer.From(Crypto.Primitives.GetRandom.GenerateBytes(48)), nil, ATicket,
    AExtendedMasterSecret, '', '', 7200, 0, UInt64(TDateTimeUtilities.CurrentUnixMs), nil);
end;

function TTestTls12Resumption.MakeStoredSession(const AIdentity: TBytes;
  const ASecret: ISecretBuffer; const AHost: string): IResumableSession;
begin
  // a session-id session (RFC 5246 7.3): the id resumes via the store, AHost is the host it was
  // issued under and what the cross-host guard checks
  Result := TResumableSession.CreateTls12(TlsSuite, THashAlgorithm.SHA_256, ASecret, AIdentity,
    nil, True, '', AHost, 7200, 0, UInt64(TDateTimeUtilities.CurrentUnixMs), nil);
end;

procedure TTestTls12Resumption.TestSessionIdResumeIsAbbreviated;
var
  LCache: ISessionCache;
  LStore: ISessionStore;
  LClient, LServer: ITlsEngine;
  LInfo: TTlsConnectionInfo;
  LServerCred: TTlsCredential;
begin
  // a store (no STEK) drives session-id resumption (RFC 5246 7.3)
  LCache := TInMemorySessionCache.Create;
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);

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
  // the resumed client surfaces the stored server chain and, with no re-verification, validates no path
  LServerCred := ServerCredential;
  LInfo := LClient.ConnectionInfo;
  CheckTrue(LInfo.Resumed, 'the client reports a resumed handshake');
  CheckEquals(1, System.Length(LInfo.PeerCertificates),
    'the resumed client surfaces the stored server chain');
  CheckEqualBytes('the surfaced server leaf is the server credential leaf',
    LServerCred.CertificateChain[0], LInfo.PeerCertificates[0]);
  CheckEquals(0, System.Length(LInfo.ValidatedPath),
    'a non-reverify resumption validates no path on the client');
  CheckAppDataFlows(LClient, LServer);
end;

procedure TTestTls12Resumption.TestTicketResumeIsAbbreviated;
var
  LStek: ISessionTicketKeyManager;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
  LInfo: TTlsConnectionInfo;
  LServerCred: TTlsCredential;
begin
  // a STEK (no store) drives stateless RFC 5077 ticket resumption
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
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
  // the resumed client surfaces the stored server chain and, with no re-verification, validates no path
  LServerCred := ServerCredential;
  LInfo := LClient.ConnectionInfo;
  CheckTrue(LInfo.Resumed, 'the client reports a resumed handshake');
  CheckEquals(1, System.Length(LInfo.PeerCertificates),
    'the resumed client surfaces the stored server chain');
  CheckEqualBytes('the surfaced server leaf is the server credential leaf',
    LServerCred.CertificateChain[0], LInfo.PeerCertificates[0]);
  CheckEquals(0, System.Length(LInfo.ValidatedPath),
    'a non-reverify resumption validates no path on the client');
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
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
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
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
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

procedure TTestTls12Resumption.TestEmsSessionOfferedWithoutEmsAborts;
var
  LStek: ISessionTicketKeyManager;
  LCache1, LCache2: ISessionCache;
  LClient, LServer: ITlsEngine;
  LSession: IResumableSession;
  LTicket: TBytes;
begin
  // establish a real EMS session, then re-present its (EMS) ticket as a non-EMS cache entry so the
  // client offers the ticket without the extension; the server opening it as EMS must abort rather
  // than resume with an inconsistent master secret (RFC 7627 5.3)
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LCache1 := TInMemorySessionCache.Create;
  LClient := NewClient(LCache1, True);
  LServer := NewServer(nil, LStek, 7200, True);
  LClient.StartHandshake;
  PumpToCompletion(LClient, LServer);
  CheckTrue(LCache1.Take(ServerHost + ':443', ServerHost, LSession),
    'the EMS session was cached');
  LTicket := LSession.SessionTicket;

  LCache2 := TInMemorySessionCache.Create;
  LCache2.Store(ServerHost + ':443', ServerHost, MakeTicketSession(LTicket, False));
  LClient := NewClient(LCache2, False);
  LServer := NewServer(nil, LStek, 7200, True);
  LClient.StartHandshake;
  PumpToCompletion(LClient, LServer);
  CheckTrue(LServer.IsTerminal, 'an EMS session offered without EMS aborts');
  CheckEquals(Int64(Ord(TTlsAlertDescription.IllegalParameter)),
    Int64(Ord(LServer.LastError.Alert.Description)),
    'the abort is illegal_parameter (RFC 7627 5.3)');
  // the fatal alert reached the wire, not just the server's own state
  CheckTrue(LClient.IsTerminal, 'the client received the fatal alert');
  CheckEquals(Int64(Ord(TTlsAlertDescription.IllegalParameter)),
    Int64(Ord(LClient.LastError.Alert.Description)),
    'the client saw illegal_parameter');
end;

procedure TTestTls12Resumption.TestNonEmsSessionOfferedWithEmsFallsBackToFullHandshake;
var
  LStek: ISessionTicketKeyManager;
  LCache1, LCache2: ISessionCache;
  LClient, LServer: ITlsEngine;
  LSession: IResumableSession;
  LTicket: TBytes;
begin
  // the reverse direction: a non-EMS session re-presented as EMS so the client offers EMS; the
  // server opening a non-EMS ticket under an EMS offer declines to a full handshake, not an abort
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LCache1 := TInMemorySessionCache.Create;
  LClient := NewClient(LCache1, False);
  LServer := NewServer(nil, LStek, 7200, True);
  LClient.StartHandshake;
  PumpToCompletion(LClient, LServer);
  CheckTrue(LCache1.Take(ServerHost + ':443', ServerHost, LSession),
    'the non-EMS session was cached');
  LTicket := LSession.SessionTicket;

  LCache2 := TInMemorySessionCache.Create;
  LCache2.Store(ServerHost + ':443', ServerHost, MakeTicketSession(LTicket, True));
  LClient := NewClient(LCache2, True);
  LServer := NewServer(nil, LStek, 7200, True);
  CheckTrue(DriveObservingServerCert(LClient, LServer),
    'a non-EMS session offered with EMS falls back to a full handshake (Certificate sent)');
  CheckFalse(LServer.IsTerminal, 'the reverse EMS mismatch is not fatal');
end;

function TTestTls12Resumption.LoadClientAuthCredential(
  out ARootCert: TBytes): TTlsCredential;
var
  LV: TStringList;
begin
  LV := LoadVectorFields('Certs/ClientAuthChain.txt');
  try
    ARootCert := DecodeHex(LV.Values['root_cert']);
    Result.CertificateChain := TArray<TBytes>.Create(DecodeHex(LV.Values['leaf_cert']));
    Result.PrivateKey := Crypto.Signing.ImportSigningKey(DecodeHex(LV.Values['leaf_key']));
  finally
    LV.Free;
  end;
end;

function TTestTls12Resumption.BuildMtlsClient(const ACache: ISessionCache;
  const ACredential: TTlsCredential): ITlsEngine;
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
  LParams.OfferedSuites := TArray<UInt16>.Create(TlsSuite);
  LParams.OfferedGroups := TArray<UInt16>.Create(TNamedGroupCatalog.X25519,
    TNamedGroupCatalog.Secp256r1);
  LParams.OfferedSchemes := TArray<UInt16>.Create(TSignatureSchemes.EcdsaSecp256r1Sha256);
  LParams.OfferedVersions := TArray<UInt16>.Create(TlsWireVersionTls12);
  LParams.ClientRandom := Crypto.Primitives.GetRandom.GenerateBytes(32);
  LParams.OfferExtendedMasterSecret := True;
  LParams.CertificateVerifier := TCertificateVerifier.Create(Pkix,
    TSystemClock.Create as ITlsClock,
    TTrustAnchorStore.Create(TArray<TBytes>.Create(TestRootCertificate))
    as ITrustAnchorStore, True) as IServerCertificateVerifier;
  LParams.ExpectedServerName := TServerName.DnsName(ServerHost);
  LParams.ServerName := ServerHost;
  LParams.ServerIdentity := ServerHost + ':443';
  LParams.SessionCache := ACache;
  LParams.ClientCredential := ACredential;
  Result := TTlsEngine.CreateConfigured(
    TTls12ClientStateMachine.Create(LParams) as IHandshakeMachine, Crypto);
end;

function TTestTls12Resumption.BuildMtlsServer(const AStek: ISessionTicketKeyManager;
  AClientAuth: TClientAuthMode; const AClientRoot, AScope: TBytes): ITlsEngine;
var
  LParams: TServer12HandshakeParams;
begin
  LParams := Default(TServer12HandshakeParams);
  LParams.Clock := TSystemClock.Create;
  LParams.Crypto := Crypto;
  LParams.Inspector := Pkix.Certificates;
  LParams.CipherSuites := TCipherSuiteRegistry.CreateDualVersion(Crypto);
  LParams.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  LParams.Group := TNamedGroups.CreateX25519(Crypto);
  LParams.ServerRandom := Crypto.Primitives.GetRandom.GenerateBytes(32);
  LParams.CredentialResolver := TSniCredentialResolver.ForCredential(ServerCredential);
  LParams.SessionTicketKeys := AStek;
  LParams.ResumptionScope := AScope;
  LParams.TicketLifetimeSeconds := 7200;
  LParams.ClientAuth := AClientAuth;
  if AClientAuth <> TClientAuthMode.None then
  begin
    LParams.ClientAuthSignatureSchemes := TArray<UInt16>.Create(
      TSignatureSchemes.EcdsaSecp256r1Sha256);
    LParams.ClientCertificateVerifier := TCertificateVerifier.Create(Pkix,
      TSystemClock.Create as ITlsClock,
      TTrustAnchorStore.Create(TArray<TBytes>.Create(AClientRoot))
      as ITrustAnchorStore, False) as IClientCertificateVerifier;
  end;
  Result := TTlsEngine.CreateConfigured(
    TTls12ServerStateMachine.Create(LParams) as IHandshakeMachine, Crypto);
end;

procedure TTestTls12Resumption.TestResumptionScopeMismatchDeclinesTicket;
var
  LStek: ISessionTicketKeyManager;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
  LCred: TTlsCredential;
  LClientRoot: TBytes;
begin
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LCache := TInMemorySessionCache.Create;
  LCred := LoadClientAuthCredential(LClientRoot);

  // an issuer under scope A mints an mTLS ticket carrying the verified client chain
  LClient := BuildMtlsClient(LCache, LCred);
  LServer := BuildMtlsServer(LStek, TClientAuthMode.Required, LClientRoot,
    DecodeHex('a1a1a1a1a1a1a1a1'));
  LClient.StartHandshake;
  PumpToCompletion(LClient, LServer);
  CheckEquals(1, LCache.Count, 'the client cached the scope-A ticket');

  // a configuration sharing the STEK but under scope B declines the ticket (scope mismatch) and
  // completes a full handshake, verifying the client certificate under its own trust
  LClient := BuildMtlsClient(LCache, LCred);
  LServer := BuildMtlsServer(LStek, TClientAuthMode.Required, LClientRoot,
    DecodeHex('b2b2b2b2b2b2b2b2'));
  CheckTrue(DriveObservingServerCert(LClient, LServer),
    'a different-scope configuration runs a full handshake (Certificate sent), not a resume');
  CheckFalse(LServer.IsTerminal, 'the full handshake completed');
  CheckTrue(System.Length(LServer.ConnectionInfo.PeerCertificates) > 0,
    'the full handshake verified the client certificate itself');
end;

procedure TTestTls12Resumption.TestMutualAuthTicketReissueCarriesChain;
var
  LStek: ISessionTicketKeyManager;
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
  LCred: TTlsCredential;
  LClientRoot, LScope: TBytes;
  LServerInfo: TTlsConnectionInfo;
begin
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LCache := TInMemorySessionCache.Create;
  LCred := LoadClientAuthCredential(LClientRoot);
  LScope := DecodeHex('5c5c5c5c5c5c5c5c');

  // full mutual-TLS handshake -> ticket #1
  LClient := BuildMtlsClient(LCache, LCred);
  LServer := BuildMtlsServer(LStek, TClientAuthMode.Required, LClientRoot, LScope);
  LClient.StartHandshake;
  PumpToCompletion(LClient, LServer);
  CheckEquals(1, LCache.Count, 'ticket #1 was cached');

  // resume ticket #1 and re-issue ticket #2, which must carry the chain forward
  LClient := BuildMtlsClient(LCache, LCred);
  LServer := BuildMtlsServer(LStek, TClientAuthMode.Required, LClientRoot, LScope);
  LClient.StartHandshake;
  PumpToCompletion(LClient, LServer);
  CheckTrue(LServer.ConnectionInfo.Resumed, 'the first resumption resumed');
  CheckEquals(1, LCache.Count, 'the client holds a ticket for the next connection');

  // resume ticket #2: resumes only if it carried the chain (else Required declines to full)
  LClient := BuildMtlsClient(LCache, LCred);
  LServer := BuildMtlsServer(LStek, TClientAuthMode.Required, LClientRoot, LScope);
  LClient.StartHandshake;
  PumpToCompletion(LClient, LServer);
  LServerInfo := LServer.ConnectionInfo;
  CheckTrue(LServerInfo.Resumed, 'the re-issued ticket carried the chain, so it resumes again');
  CheckTrue(System.Length(LServerInfo.PeerCertificates) > 0,
    'and the resumed connection surfaces the client chain');
end;

procedure TTestTls12Resumption.TestDecliningSealStillSendsZeroLengthTicket;
var
  LCache: ISessionCache;
  LClient, LServer: ITlsEngine;
  LServerWire, LServerOut: TBytes;
  LIterations: Int32;
begin
  // a server that echoed the session_ticket extension MUST still send a NewSessionTicket, even
  // when the strategy declines to seal - a zero-length one - so the client is not left awaiting
  // it (RFC 5077 3.3)
  LCache := TInMemorySessionCache.Create;
  LClient := NewClient(LCache, True);
  LServer := NewServer(nil, TDecliningTicketKeys.Create, 7200, True);
  LClient.StartHandshake;
  LServerWire := nil;
  LIterations := 0;
  while (LClient.IsHandshaking or LServer.IsHandshaking) and (LIterations < 16) do
  begin
    Feed(LServer, Drain(LClient));
    LServerOut := Drain(LServer);
    LServerWire := ConcatBytes(LServerWire, LServerOut);
    Feed(LClient, LServerOut);
    Inc(LIterations);
  end;
  CheckFalse(LClient.IsHandshaking, 'the client completed despite the declined ticket');
  CheckFalse(LServer.IsHandshaking, 'the server completed');
  CheckTrue(FlightHasNewSessionTicket(LServerWire),
    'the server still sent a NewSessionTicket (zero-length)');
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
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
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
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);
  LCache := TInMemorySessionCache.Create;
  LCache.Store(ServerHost, ServerHost,
    MakeTicketSession(Crypto.Primitives.GetRandom.GenerateBytes(64), False));

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
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);
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
  LInfo: TTlsConnectionInfo;
  LServerCred: TTlsCredential;
begin
  LCache := TInMemorySessionCache.Create;
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);

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
  // through the 1.3->1.2 hand-off the resumed client surfaces the stored server chain and, with no
  // re-verification, validates no path
  LServerCred := ServerCredential;
  LInfo := LClient.ConnectionInfo;
  CheckTrue(LInfo.Resumed, 'the client reports a resumed handshake');
  CheckEquals(1, System.Length(LInfo.PeerCertificates),
    'the resumed client surfaces the stored server chain');
  CheckEqualBytes('the surfaced server leaf is the server credential leaf',
    LServerCred.CertificateChain[0], LInfo.PeerCertificates[0]);
  CheckEquals(0, System.Length(LInfo.ValidatedPath),
    'a non-reverify resumption validates no path on the client');
  CheckAppDataFlows(LClient, LServer);
end;

procedure TTestTls12Resumption.TestDualVersionClientAbortsStampedAbbreviatedResumption;
var
  LCache: ISessionCache;
  LStek: ISessionTicketKeyManager;
  LClient, LServer: ITlsEngine;
begin
  // a 1.3-capable client aborts a stamped downgrade even on an abbreviated (resumption)
  // ServerHello, not only on a full one (RFC 8446 4.1.3)
  LCache := TInMemorySessionCache.Create;
  LStek := TStekTicketKeyManager.Create(Crypto.Primitives.GetRandom);

  LClient := NewDualVersionClient(LCache);
  LServer := NewServer(nil, LStek, 7200, True);
  CheckTrue(DriveObservingServerCert(LClient, LServer),
    'the first dual-version handshake is full');
  CheckEquals(1, LCache.Count, 'the dual-version client cached the 1.2 session');

  // the resuming server stamps the downgrade sentinel on the abbreviated ServerHello
  LClient := NewDualVersionClient(LCache);
  LServer := NewServer(nil, LStek, 7200, True, True);
  LClient.StartHandshake;
  PumpToCompletion(LClient, LServer);
  CheckTrue(LClient.IsTerminal, 'the client aborts a stamped abbreviated ServerHello');
  CheckEquals(Int64(Ord(TTlsAlertDescription.IllegalParameter)),
    Int64(Ord(LClient.LastError.Alert.Description)),
    'the abort is illegal_parameter (RFC 8446 4.1.3)');
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
  LIdentity := Crypto.Primitives.GetRandom.GenerateBytes(32);
  LSecret := TSecretBuffer.From(Crypto.Primitives.GetRandom.GenerateBytes(48));

  // control: issued under the requested host -> resumes (abbreviated, no Certificate)
  LCache := TInMemorySessionCache.Create;
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);
  LCache.Store(ServerHost + ':443', ServerHost, MakeStoredSession(LIdentity, LSecret, ServerHost));
  LStore.PutWithId(LIdentity, MakeStoredSession(LIdentity, LSecret, ServerHost));
  LClient := NewClient(LCache, True);
  LServer := NewServer(LStore, nil, 7200, True);
  CheckFalse(DriveObservingServerCert(LClient, LServer),
    'a session issued under the requested host resumes');
  CheckTrue(LServer.ConnectionInfo.Resumed, 'the control 1.2 handshake resumed');

  // guarded: issued under a different host -> the credentialed server ignores the session id and
  // runs a full handshake (Certificate sent) instead of resuming under the wrong identity
  LCache := TInMemorySessionCache.Create;
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);
  LCache.Store(ServerHost + ':443', ServerHost, MakeStoredSession(LIdentity, LSecret, ServerHost));
  LStore.PutWithId(LIdentity, MakeStoredSession(LIdentity, LSecret, 'other.example'));
  LClient := NewClient(LCache, True);
  LServer := NewServer(LStore, nil, 7200, True);
  CheckTrue(DriveObservingServerCert(LClient, LServer),
    'a session issued under a different host falls back to a full handshake');
  CheckFalse(LServer.ConnectionInfo.Resumed, 'a session issued under a different host does not resume');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestTls12Resumption);
{$ELSE}
  RegisterTest(TTestTls12Resumption.Suite);
{$ENDIF FPC}

end.
