{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit Tls12DualVersionTests;

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
  TlpINamedGroup,
  TlpNamedGroups,
  TlpNegotiationTypes,
  TlpNegotiationPolicy,
  TlpCipherSuiteRegistry,
  TlpSignatureSchemeRegistry,
  TlpCoreExtensions,
  TlpHandshakeMessage,
  TlpHandshakeMessages,
  TlpHandshakeEffect,
  TlpISecretBuffer,
  TlpSecretBuffer,
  TlpITlsEngine,
  TlpTlsEngine,
  TlpTlsEngineFactory,
  TlpITlsConfig,
  TlpITlsConfigBuilder,
  TlpTlsPresets,
  TlpIHandshakeMachine,
  TlpICertificateTrust,
  TlpCertificateVerifier,
  TlpTlsCredential,
  TlpCredentialResolvers,
  TlpTls13ClientStateMachine,
  TlpTls13ServerStateMachine,
  TlpTls12ClientStateMachine,
  TlpTls12ServerStateMachine,
  TlpVersionDispatchMachine,
  TlsLibTestBase;

type
  TTestTls12DualVersion = class(TTlsLibAlgorithmTestCase)
  private
    function Filled(AByte: Byte; ACount: Int32): TBytes;
    function TestRootCertificate: TBytes;
    function ServerCredential: TTlsCredential;
    function DualSuites: TArray<UInt16>;
    function Client13Params: TClientHandshakeParams;
    function Client12Params: TClient12HandshakeParams;
    function Server13Params: TServerHandshakeParams;
    function Server12Params: TServer12HandshakeParams;
    function NewDualClient: ITlsEngine;
    function NewHybridOfferingDualClient: ITlsEngine;
    function NewServerDispatch(const AVersions: TArray<UInt16>): ITlsEngine;
    function NewDowngradeAttacker: ITlsEngine;
    function Drain(const AEngine: ITlsEngine): TBytes;
    procedure Feed(const AEngine: ITlsEngine; const AWire: TBytes);
    procedure Pump(const ASrc, ADst: ITlsEngine);
    function ReadAllApp(const AEngine: ITlsEngine): TBytes;
    procedure DriveToCompletion(const AClient, AServer: ITlsEngine);
    procedure CheckExchangesData(const AClient, AServer: ITlsEngine;
      const AMsg: string);
    /// <summary>Frames a ClientHello with the given cipher_suites and raw extensions
    /// block (a length-prefixed vector), parsed back into a handshake message.</summary>
    function MakeClientHello(const ACipherSuites: TArray<UInt16>;
      const AExtensions: TBytes): TTlsHandshakeMessage;
    function HasInappropriateFallback(
      const AEffects: TArray<THandshakeEffect>): Boolean;
  published
    procedure TestDualClientDualServerNegotiates13;
    procedure TestDualClientTls13OnlyServerNegotiates13;
    procedure TestDualClientTls12OnlyServerNegotiates12;
    procedure TestDualClientOfferingHybridExcludesItOnTls12;
    procedure TestForcedDowngradeIsDetectedAndAborts;
    procedure TestGarbageFirstRecordAbortsWithoutRaising;
    procedure TestScsvFromLowerClientAborts;
    procedure TestScsvFromCurrentClientDoesNotAbort;
    procedure TestScsvToLegacyOnlyServerDoesNotAbort;
    procedure TestCompatiblePresetEngineLoopback;
    procedure TestCompatiblePresetMutualTlsCompletes;
  end;

implementation

{ TTestTls12DualVersion }

function TTestTls12DualVersion.Filled(AByte: Byte; ACount: Int32): TBytes;
var
  LI: Int32;
begin
  Result := nil;
  SetLength(Result, ACount);
  for LI := 0 to ACount - 1 do
    Result[LI] := AByte;
end;

function TTestTls12DualVersion.TestRootCertificate: TBytes;
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

function TTestTls12DualVersion.ServerCredential: TTlsCredential;
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

function TTestTls12DualVersion.DualSuites: TArray<UInt16>;
begin
  // one 1.3 suite and one ECDHE-ECDSA 1.2 suite: the negotiated version alone decides
  Result := TArray<UInt16>.Create(TCipherSuites13.Aes128GcmSha256,
    TCipherSuites12.EcdheEcdsaAes128GcmSha256);
end;

function TTestTls12DualVersion.Client13Params: TClientHandshakeParams;
begin
  Result := Default(TClientHandshakeParams);
  Result.Clock := TSystemClock.Create;
  Result.Provider := Provider;
  Result.Group := TNamedGroups.CreateX25519(Provider);
  Result.GroupCode := TNamedGroupCatalog.X25519;
  // the unified ClientHello carries these supported_groups; a 1.2 fallback with a P-256
  // ECDSA server certificate needs Secp256r1 listed too, since TLS 1.2 gates the ECDSA
  // leaf's curve on supported_groups (RFC 8422 5.4). The key_share stays X25519-only
  Result.OfferedGroups := TArray<UInt16>.Create(TNamedGroupCatalog.X25519,
    TNamedGroupCatalog.Secp256r1);
  Result.GroupRegistry := TNamedGroups.CreateDefaultRegistry(Provider);
  Result.CipherSuites := TCipherSuiteRegistry.CreateDualVersion(Provider);
  Result.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  Result.OfferedSuites := DualSuites;
  Result.OfferedSchemes := TArray<UInt16>.Create(
    TSignatureSchemes.EcdsaSecp256r1Sha256);
  Result.Grease := False;
  Result.ClientRandom := Filled($11, 32);
  Result.LegacySessionId := Filled($33, 32);
  Result.CertificateVerifier := TCertificateVerifier.Create(Provider, TSystemClock.Create as ITlsClock,
    TTrustAnchorStore.Create(TArray<TBytes>.Create(TestRootCertificate))
    as ITrustAnchorStore, True) as ICertificateVerifier;
  Result.ExpectedHostName := 'localhost';
end;

function TTestTls12DualVersion.Client12Params: TClient12HandshakeParams;
begin
  Result := Default(TClient12HandshakeParams);
  Result.Clock := TSystemClock.Create;
  Result.Provider := Provider;
  Result.GroupRegistry := TNamedGroups.CreateDefaultRegistry(Provider);
  Result.CipherSuites := TCipherSuiteRegistry.CreateDualVersion(Provider);
  Result.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  Result.OfferedSuites := DualSuites;
  // TLS 1.2 supported_groups gates both the ECDHE key-exchange group and the ECDSA leaf's
  // curve (RFC 8422 5.1), so it lists X25519 and Secp256r1 (the P-256 certificate curve)
  Result.OfferedGroups := TArray<UInt16>.Create(TNamedGroupCatalog.X25519,
    TNamedGroupCatalog.Secp256r1);
  Result.OfferedSchemes := TArray<UInt16>.Create(
    TSignatureSchemes.EcdsaSecp256r1Sha256);
  Result.OfferedVersions := TArray<UInt16>.Create(TlsWireVersionTls13,
    TlsWireVersionTls12);
  // the client random matches Client13Params so a 1.2 hand-off stays consistent
  Result.ClientRandom := Filled($11, 32);
  Result.LegacySessionId := Filled($33, 32);
  Result.OfferExtendedMasterSecret := True;
  Result.CertificateVerifier := TCertificateVerifier.Create(Provider, TSystemClock.Create as ITlsClock,
    TTrustAnchorStore.Create(TArray<TBytes>.Create(TestRootCertificate))
    as ITrustAnchorStore, True) as ICertificateVerifier;
  Result.ExpectedHostName := 'localhost';
end;

function TTestTls12DualVersion.Server13Params: TServerHandshakeParams;
begin
  Result := Default(TServerHandshakeParams);
  Result.Clock := TSystemClock.Create;
  Result.Provider := Provider;
  Result.Policy := TNegotiationPolicy.Create(Provider,
    TCipherSuiteRegistry.CreateDualVersion(Provider),
    TNamedGroups.CreateDefaultRegistry(Provider),
    TSignatureSchemeRegistry.CreateDefault,
    TArray<UInt16>.Create(TNamedGroupCatalog.X25519),
    TArray<UInt16>.Create(TlsWireVersionTls13, TlsWireVersionTls12), TServerCipherPreference.ServerOrder);
  Result.CipherSuites := TCipherSuiteRegistry.CreateDualVersion(Provider);
  Result.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  Result.Group := TNamedGroups.CreateX25519(Provider);
  Result.ServerRandom := Filled($22, 32);
  Result.CookieSecret := TSecretBuffer.From(Provider.GetRandom.GenerateBytes(32));
  Result.CredentialResolver := TSniCredentialResolver.ForCredential(ServerCredential);
end;

function TTestTls12DualVersion.Server12Params: TServer12HandshakeParams;
begin
  Result := Default(TServer12HandshakeParams);
  Result.Clock := TSystemClock.Create;
  Result.Provider := Provider;
  Result.CipherSuites := TCipherSuiteRegistry.CreateDualVersion(Provider);
  Result.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  Result.Group := TNamedGroups.CreateX25519(Provider);
  Result.ServerRandom := Filled($22, 32);
  Result.CredentialResolver := TSniCredentialResolver.ForCredential(ServerCredential);
end;

function TTestTls12DualVersion.NewDualClient: ITlsEngine;
begin
  Result := TTlsEngine.CreateConfigured(TClientVersionDispatchMachine.Create(
    Client13Params, Client12Params) as IHandshakeMachine, Provider);
end;

function TTestTls12DualVersion.NewHybridOfferingDualClient: ITlsEngine;
var
  L13: TClientHandshakeParams;
  L12: TClient12HandshakeParams;
begin
  L13 := Client13Params;
  L12 := Client12Params;
  // additionally advertise the X25519MLKEM768 hybrid in supported_groups (hybrid first);
  // the key_share stays classical X25519, so a 1.2 handshake must ignore the hybrid
  L13.OfferedGroups := TArray<UInt16>.Create(TNamedGroupCatalog.X25519MlKem768,
    TNamedGroupCatalog.X25519, TNamedGroupCatalog.Secp256r1);
  L12.OfferedGroups := L13.OfferedGroups;
  Result := TTlsEngine.CreateConfigured(TClientVersionDispatchMachine.Create(
    L13, L12) as IHandshakeMachine, Provider);
end;

function TTestTls12DualVersion.NewServerDispatch(
  const AVersions: TArray<UInt16>): ITlsEngine;
begin
  Result := TTlsEngine.CreateConfigured(TServerVersionDispatchMachine.Create(
    Server13Params, Server12Params, AVersions) as IHandshakeMachine, Provider);
end;

function TTestTls12DualVersion.NewDowngradeAttacker: ITlsEngine;
var
  LParams: TServer12HandshakeParams;
begin
  // a 1.3-capable server that (maliciously) answers a 1.3+1.2 client with 1.2 and
  // stamps the RFC 8446 downgrade sentinel
  LParams := Server12Params;
  LParams.EmitDowngradeSentinel := True;
  Result := TTlsEngine.CreateConfigured(
    TTls12ServerStateMachine.Create(LParams) as IHandshakeMachine, Provider);
end;

function TTestTls12DualVersion.Drain(const AEngine: ITlsEngine): TBytes;
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

procedure TTestTls12DualVersion.Feed(const AEngine: ITlsEngine; const AWire: TBytes);
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

procedure TTestTls12DualVersion.Pump(const ASrc, ADst: ITlsEngine);
begin
  Feed(ADst, Drain(ASrc));
end;

function TTestTls12DualVersion.ReadAllApp(const AEngine: ITlsEngine): TBytes;
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

procedure TTestTls12DualVersion.DriveToCompletion(const AClient, AServer: ITlsEngine);
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
end;

procedure TTestTls12DualVersion.CheckExchangesData(const AClient, AServer: ITlsEngine;
  const AMsg: string);
var
  LFromClient, LFromServer: TBytes;
begin
  CheckFalse(AClient.IsHandshaking, AMsg + ': client completed');
  CheckFalse(AServer.IsHandshaking, AMsg + ': server completed');
  CheckFalse(AClient.IsTerminal, AMsg + ': client did not fail');
  CheckFalse(AServer.IsTerminal, AMsg + ': server did not fail');

  LFromClient := DecodeHex('68656c6c6f2066726f6d2074686520636c69656e74');
  AClient.Write(LFromClient, 0, System.Length(LFromClient));
  Pump(AClient, AServer);
  CheckEqualBytes(AMsg + ': server reads client data', LFromClient,
    ReadAllApp(AServer));

  LFromServer := DecodeHex('68656c6c6f2066726f6d2074686520736572766572');
  AServer.Write(LFromServer, 0, System.Length(LFromServer));
  Pump(AServer, AClient);
  CheckEqualBytes(AMsg + ': client reads server data', LFromServer,
    ReadAllApp(AClient));
end;

procedure TTestTls12DualVersion.TestDualClientDualServerNegotiates13;
var
  LClient, LServer: ITlsEngine;
begin
  LClient := NewDualClient;
  LServer := NewServerDispatch(TArray<UInt16>.Create(TlsWireVersionTls13,
    TlsWireVersionTls12));
  DriveToCompletion(LClient, LServer);
  CheckExchangesData(LClient, LServer, 'dual client + dual server');
end;

procedure TTestTls12DualVersion.TestDualClientTls13OnlyServerNegotiates13;
var
  LClient, LServer: ITlsEngine;
begin
  LClient := NewDualClient;
  LServer := NewServerDispatch(TArray<UInt16>.Create(TlsWireVersionTls13));
  DriveToCompletion(LClient, LServer);
  CheckExchangesData(LClient, LServer, 'dual client + 1.3-only server');
end;

procedure TTestTls12DualVersion.TestDualClientTls12OnlyServerNegotiates12;
var
  LClient, LServer: ITlsEngine;
begin
  // the server supports only 1.2, so the client's dispatcher must hand off to its 1.2
  // machine; a 1.2-only server never stamps the downgrade sentinel
  LClient := NewDualClient;
  LServer := NewServerDispatch(TArray<UInt16>.Create(TlsWireVersionTls12));
  DriveToCompletion(LClient, LServer);
  CheckExchangesData(LClient, LServer, 'dual client + 1.2-only server');
end;

procedure TTestTls12DualVersion.TestDualClientOfferingHybridExcludesItOnTls12;
var
  LClient, LServer: ITlsEngine;
begin
  // the dual client lists X25519MLKEM768 in supported_groups, but a 1.2-only server must
  // negotiate a classical ECDHE group - a KEM hybrid is never selected on TLS 1.2 (RFC 8446)
  LClient := NewHybridOfferingDualClient;
  LServer := NewServerDispatch(TArray<UInt16>.Create(TlsWireVersionTls12));
  DriveToCompletion(LClient, LServer);
  CheckExchangesData(LClient, LServer, 'dual client offering hybrid + 1.2-only server');
  CheckEquals(Integer(TlsWireVersionTls12), Integer(LClient.NegotiatedVersion.WireValue),
    'the connection negotiated TLS 1.2');
  CheckEquals(Integer(TNamedGroupCatalog.X25519), Integer(LClient.NegotiatedGroup),
    'a classical group (not the X25519MLKEM768 hybrid) was selected on 1.2');
end;

procedure TTestTls12DualVersion.TestForcedDowngradeIsDetectedAndAborts;
var
  LClient, LServer: ITlsEngine;
begin
  LClient := NewDualClient;
  LServer := NewDowngradeAttacker;
  DriveToCompletion(LClient, LServer);
  CheckTrue(LClient.IsTerminal,
    'the client aborts a 1.2 downgrade that carries the 1.3-capable sentinel');
end;

procedure TTestTls12DualVersion.TestCompatiblePresetEngineLoopback;
var
  LClient, LServer: ITlsEngine;
begin
  // the whole public stack: the Compatible preset (dual-version) + the engine factory
  LServer := TTlsEngineFactory.CreateServerEngine(TTlsPresets.Compatible(Provider)
    .Server.WithCredential(ServerCredential).Build);
  LClient := TTlsEngineFactory.CreateClientEngine(TTlsPresets.Compatible(Provider)
    .Client.WithTrustStore(TTrustAnchorStore.Create(
    TArray<TBytes>.Create(TestRootCertificate))
    as ITrustAnchorStore).Build, 'localhost');
  DriveToCompletion(LClient, LServer);
  CheckExchangesData(LClient, LServer, 'Compatible preset engine');
end;

procedure TTestTls12DualVersion.TestCompatiblePresetMutualTlsCompletes;
var
  LClient, LServer: ITlsEngine;
begin
  // mutual TLS through the preset/config surface: the server requires and trusts the
  // client certificate, the client presents its credential
  LServer := TTlsEngineFactory.CreateServerEngine(TTlsPresets.Compatible(Provider)
    .Server.WithCredential(ServerCredential)
    .WithPeerAuth(TClientAuthMode.Required)
    .WithTrustStore(TTrustAnchorStore.Create(TArray<TBytes>.Create(TestRootCertificate))
    as ITrustAnchorStore).Build);
  LClient := TTlsEngineFactory.CreateClientEngine(TTlsPresets.Compatible(Provider)
    .Client.WithCredential(ServerCredential)
    .WithTrustStore(TTrustAnchorStore.Create(TArray<TBytes>.Create(TestRootCertificate))
    as ITrustAnchorStore).Build, 'localhost');
  DriveToCompletion(LClient, LServer);
  CheckExchangesData(LClient, LServer, 'Compatible preset mutual TLS');
end;

procedure TTestTls12DualVersion.TestGarbageFirstRecordAbortsWithoutRaising;
var
  LServer: ITlsEngine;
begin
  // a malformed first ClientHello on the dual-version path must surface as a fatal alert
  // from the dispatch machine, never as an unhandled exception out of ProcessInput. The
  // record frames a complete but truncated client_hello (a 3-byte body over-reads)
  LServer := NewServerDispatch(TArray<UInt16>.Create(TlsWireVersionTls13,
    TlsWireVersionTls12));
  Feed(LServer, DecodeHex('160303000701000003AABBCC'));
  CheckTrue(LServer.IsTerminal, 'a garbage ClientHello aborts the dual-version server');
  CheckFalse(LServer.IsHandshaking, 'the server did not stay handshaking');
end;

function TTestTls12DualVersion.MakeClientHello(const ACipherSuites: TArray<UInt16>;
  const AExtensions: TBytes): TTlsHandshakeMessage;
var
  LHello: TTlsClientHello;
  LFramed: TBytes;
  LReader: THandshakeMessageReader;
begin
  LHello.Random := Filled($11, 32);
  LHello.LegacySessionId := nil;
  LHello.CipherSuites := ACipherSuites;
  LHello.Extensions := AExtensions;
  LFramed := THandshakeFraming.Frame(TTlsHandshakeType.ClientHello,
    THandshakeMessages.EncodeClientHello(LHello));
  LReader := THandshakeMessageReader.Create;
  try
    LReader.Append(LFramed, 0, System.Length(LFramed));
    LReader.NextMessage(Result);
  finally
    LReader.Free;
  end;
end;

function TTestTls12DualVersion.HasInappropriateFallback(
  const AEffects: TArray<THandshakeEffect>): Boolean;
var
  LEffect: THandshakeEffect;
begin
  Result := False;
  for LEffect in AEffects do
    if (LEffect.Kind = THandshakeEffectKind.Fail) and
      (LEffect.Alert = TTlsAlertDescription.InappropriateFallback) then
      Result := True;
end;

procedure TTestTls12DualVersion.TestScsvFromLowerClientAborts;
var
  LServer: IHandshakeMachine;
begin
  // a client that fell back to 1.2 (no supported_versions, so it tops out at 1.2) yet
  // signals TLS_FALLBACK_SCSV, reaching a 1.3-capable server, is an inappropriate
  // fallback: the server could have done 1.3 (RFC 7507)
  LServer := TServerVersionDispatchMachine.Create(Server13Params, Server12Params,
    TArray<UInt16>.Create(TlsWireVersionTls13, TlsWireVersionTls12)) as IHandshakeMachine;
  CheckTrue(HasInappropriateFallback(LServer.ProcessMessage(MakeClientHello(
    TArray<UInt16>.Create(TlsFallbackScsv, TCipherSuites12.EcdheEcdsaAes128GcmSha256),
    DecodeHex('0000')))),
    'SCSV from a fallen-back client to a 1.3-capable server aborts inappropriate_fallback');
end;

procedure TTestTls12DualVersion.TestScsvFromCurrentClientDoesNotAbort;
var
  LServer: IHandshakeMachine;
begin
  // a normal 1.3 client lists 1.3 in supported_versions and may still carry SCSV;
  // server_max = client_max, so it is not a fallback and must not fire. Extensions =
  // supported_versions [1.3, 1.2]
  LServer := TServerVersionDispatchMachine.Create(Server13Params, Server12Params,
    TArray<UInt16>.Create(TlsWireVersionTls13, TlsWireVersionTls12)) as IHandshakeMachine;
  CheckFalse(HasInappropriateFallback(LServer.ProcessMessage(MakeClientHello(
    TArray<UInt16>.Create(TlsFallbackScsv, TCipherSuites13.Aes128GcmSha256),
    DecodeHex('0009002B00050403040303')))),
    'SCSV with a current 1.3 offer is not a fallback');
end;

procedure TTestTls12DualVersion.TestScsvToLegacyOnlyServerDoesNotAbort;
var
  LServer: IHandshakeMachine;
begin
  // a 1.2-only server (1.3 not in its supported set) reached by a 1.2 client that carries
  // SCSV: server_max = client_max = 1.2, a legitimate 1.2 handshake, not a fallback
  LServer := TServerVersionDispatchMachine.Create(Server13Params, Server12Params,
    TArray<UInt16>.Create(TlsWireVersionTls12)) as IHandshakeMachine;
  CheckFalse(HasInappropriateFallback(LServer.ProcessMessage(MakeClientHello(
    TArray<UInt16>.Create(TlsFallbackScsv, TCipherSuites12.EcdheEcdsaAes128GcmSha256),
    DecodeHex('0000')))),
    'SCSV to a 1.2-only server is not a fallback');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestTls12DualVersion);
{$ELSE}
  RegisterTest(TTestTls12DualVersion.Suite);
{$ENDIF FPC}

end.
