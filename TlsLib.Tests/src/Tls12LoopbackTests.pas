{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit Tls12LoopbackTests;

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
  TlpRecordHeader,
  TlpTlsLibExceptions,
  TlpNamedGroups,
  TlpNegotiationTypes,
  TlpNegotiationPolicy,
  TlpCipherSuiteRegistry,
  TlpCoreExtensions,
  TlpICryptoProvider,
  TlpITlsEngine,
  TlpTlsEngine,
  TlpIHandshakeMachine,
  TlpHandshakeEffect,
  TlpHandshakeStage,
  TlpHandshakeMessage,
  TlpHandshakeMessages,
  TlpExtensionVector,
  TlpICertificateTrust,
  TlpITrustAnchorStore,
  TlpTrustAnchorStore,
  TlpServerName,
  TlpCertificateVerifier,
  TlpTrustPolicy,
  TlpTrustTypes,
  TlpTlsCredential,
  TlpCredentialResolvers,
  TlpTls12ClientStateMachine,
  TlpTls12ServerStateMachine,
  MockCryptoProvider,
  TlsLibTestBase;

type
  TTestTls12Loopback = class(TTlsLibAlgorithmTestCase)
  private
    function Filled(AByte: Byte; ACount: Int32): TBytes;
    function TestRootCertificate: TBytes;
    function ServerCredential: TTlsCredential;
    function NewClient(ASuite: UInt16; AOfferEms: Boolean): ITlsEngine;
    function NewServer(ARequireEms: Boolean): ITlsEngine;
    function ServerCredentialEd448: TTlsCredential;
    function NewClientEd448: ITlsEngine;
    function NewServerEd448: ITlsEngine;
    function ServerCredentialEd25519: TTlsCredential;
    function NewClientEd25519: ITlsEngine;
    function NewServerEd25519: ITlsEngine;
    function Drain(const AEngine: ITlsEngine): TBytes;
    procedure Feed(const AEngine: ITlsEngine; const AWire: TBytes);
    procedure Pump(const ASrc, ADst: ITlsEngine);
    function ReadAllApp(const AEngine: ITlsEngine): TBytes;
    procedure RunHandshakeAndExchange(ASuite: UInt16; AOfferEms, ARequireEms: Boolean;
      const AMsg: string);
    /// <summary>Flips the last byte of the first handshake message of AMsgType found in
    /// the plaintext handshake records of AWire (test-only wire mutation).</summary>
    function TamperHandshakeMessage(var AWire: TBytes; AMsgType: Byte): Boolean;
    // AWire's first record alone, with AExtra appended to its body (the length is rewritten).
    function FirstRecordWith(const AWire, AExtra: TBytes): TBytes;
    /// <summary>Flips a payload byte of the last record in AWire (the encrypted Finished
    /// on a second flight); returns False when AWire holds no record.</summary>
    function TamperLastRecordPayload(var AWire: TBytes): Boolean;
    function ClientMachine(ASuite: UInt16; AOfferEms: Boolean): IHandshakeMachine;
    function ServerMachine(ARequireEms: Boolean): IHandshakeMachine;
    function OcspField(const AName: string): TBytes;
    function NewStaplingServer(const AStaple: TBytes): ITlsEngine;
    function NewHardRevocationClient: ITlsEngine;
    /// <summary>The framed bytes of each SendHandshake effect, in order (the record-layer
    /// effects a machine emits - keys, change_cipher_spec - are dropped).</summary>
    function SendMessages(const AEffects: TArray<THandshakeEffect>): TArray<TBytes>;
    /// <summary>Delivers each framed handshake message to ADst and returns every effect
    /// it produced, so two bare state machines can be driven without a record layer.</summary>
    function DeliverFlight(const ADst: IHandshakeMachine;
      const AMsgs: TArray<TBytes>): TArray<THandshakeEffect>;
    function HasFailAlert(const AEffects: TArray<THandshakeEffect>;
      AAlert: TTlsAlertDescription): Boolean;
    function HasEffect(const AEffects: TArray<THandshakeEffect>;
      AKind: THandshakeEffectKind): Boolean;
    function DecodeServerFlightHello(const AFlight: TArray<TBytes>): TTlsServerHello;
    // splits a server flight into its individual framed handshake messages
    function AllServerMessages(const AFlight: TArray<TBytes>): TArray<TBytes>;
    // a bare 1.2 server that echoes status_request and staples, so the client enters
    // WaitCertificateStatus and its flight carries a CertificateStatus before the ServerKeyExchange
    function StaplingServerMachine(const AStaple: TBytes): IHandshakeMachine;
    // a bare 1.2 client that offers status_request and defers its peer-certificate verdict to the
    // host (HostDecision), so a verified chain parks rather than completing inline
    function ParkingStaplingClientMachine: IHandshakeMachine;
  published
    procedure TestParkedClientDefersServerKeyExchangeAfterOmittedCertificateStatus;
    procedure TestParkedClientDefersAnOutOfOrderMessageUntilResume;
    procedure TestClientRejectsServerHelloLegacyVersionBelowTls12;
    procedure TestClientRejectsSupportedVersionsInTls12ServerHello;
    procedure TestPlaintextFinishedPackedWithKeyExchangeIsExcessData;
    procedure TestEcdheEd448CredentialHandshake;
    procedure TestEcdheEd25519CredentialHandshake;
    procedure TestEcdheEcdsaAesGcmWithExtendedMasterSecret;
    procedure TestEcdheEcdsaChaCha20WithExtendedMasterSecret;
    procedure TestClientWriteBeforeServerFinishedIsRefused;
    procedure TestServerWithoutAPolicyIsRefused;
    procedure TestWriteAfterInboundCloseNotifyClosesWrite;
    procedure TestWriteAtUsageLimitClosesWhenNoRekey;
    procedure TestPlainMasterSecretWhenEmsNotOffered;
    procedure TestRequiredEmsAbortsWhenClientDoesNotOfferIt;
    procedure TestTamperedServerKeyExchangeSignatureAborts;
    procedure TestTamperedClientFinishedAborts;
    procedure TestServerRejectsClientFinishedWithWrongVerifyData;
    procedure TestClientAnswersHelloRequestWithWarningThenAborts;
    procedure TestNonEmptyHelloRequestIsDecodeError;
    procedure TestStapledGoodOcspCompletesUnderHardPosture;
    procedure TestMissingStapleAbortsUnderHardPosture;
  end;

implementation

{ TTestTls12Loopback }

function TTestTls12Loopback.Filled(AByte: Byte; ACount: Int32): TBytes;
var
  LI: Int32;
begin
  Result := nil;
  SetLength(Result, ACount);
  for LI := 0 to ACount - 1 do
    Result[LI] := AByte;
end;

function TTestTls12Loopback.TestRootCertificate: TBytes;
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

function TTestTls12Loopback.ServerCredential: TTlsCredential;
var
  LCerts: TStringList;
begin
  LCerts := LoadVectorFields('Certs/EcP256Chain.txt');
  try
    Result.CertificateChain := TArray<TBytes>.Create(
      DecodeHex(LCerts.Values['leaf_cert']));
    Result.PrivateKey := Crypto.Signing.ImportSigningKey(DecodeHex(LCerts.Values['leaf_key']), nil);
  finally
    LCerts.Free;
  end;
end;

function TTestTls12Loopback.ClientMachine(ASuite: UInt16;
  AOfferEms: Boolean): IHandshakeMachine;
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
  LParams.OfferedSuites := TArray<UInt16>.Create(ASuite);
  // TLS 1.2 supported_groups gates both the ECDHE key-exchange group and the ECDSA leaf's
  // curve (RFC 8422 5.3), so it lists X25519 and Secp256r1 (the P-256 certificate curve)
  LParams.OfferedGroups := TArray<UInt16>.Create(TNamedGroupCatalog.X25519,
    TNamedGroupCatalog.Secp256r1);
  LParams.OfferedSchemes := TArray<UInt16>.Create(
    TSignatureSchemes.EcdsaSecp256r1Sha256);
  LParams.OfferedVersions := TArray<UInt16>.Create(TlsWireVersionTls12);
  LParams.ClientRandom := Filled($11, 32);
  LParams.LegacySessionId := nil;
  LParams.OfferExtendedMasterSecret := AOfferEms;
  LParams.CertificateVerifier := TCertificateVerifier.Create(Pkix, TSystemClock.Create as ITlsClock,
    TTrustAnchorStore.Create(TArray<TBytes>.Create(TestRootCertificate))
    as ITrustAnchorStore, True) as IServerCertificateVerifier;
  LParams.ExpectedServerName := TServerName.DnsName('localhost');
  Result := TTls12ClientStateMachine.Create(LParams) as IHandshakeMachine;
end;

function TTestTls12Loopback.NewClient(ASuite: UInt16;
  AOfferEms: Boolean): ITlsEngine;
begin
  Result := TTlsEngine.CreateConfigured(ClientMachine(ASuite, AOfferEms), Crypto);
end;

function TTestTls12Loopback.ServerMachine(ARequireEms: Boolean): IHandshakeMachine;
var
  LParams: TServer12HandshakeParams;
begin
  LParams := Default(TServer12HandshakeParams);
  LParams.Policy := TNegotiationPolicy.CreateDefault(Crypto);
  LParams.Clock := TSystemClock.Create;
  LParams.Crypto := Crypto;
  LParams.Inspector := Pkix.Certificates;
  LParams.CipherSuites := TCipherSuiteRegistry.CreateDualVersion(Crypto);
  LParams.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  LParams.Group := TNamedGroups.CreateX25519(Crypto);
  LParams.ServerRandom := Filled($22, 32);
  LParams.CredentialResolver := TSniCredentialResolver.ForCredential(ServerCredential);
  LParams.RequireExtendedMasterSecret := ARequireEms;
  Result := TTls12ServerStateMachine.Create(LParams) as IHandshakeMachine;
end;

function TTestTls12Loopback.ServerCredentialEd448: TTlsCredential;
var
  LCerts: TStringList;
begin
  LCerts := LoadVectorFields('Certs/Ed448Chain.txt');
  try
    Result.CertificateChain := TArray<TBytes>.Create(
      DecodeHex(LCerts.Values['leaf_cert']));
    Result.PrivateKey := Crypto.Signing.ImportSigningKey(
      DecodeHex(LCerts.Values['leaf_key']), nil);
  finally
    LCerts.Free;
  end;
end;

function TTestTls12Loopback.NewClientEd448: ITlsEngine;
var
  LParams: TClient12HandshakeParams;
  LCerts: TStringList;
  LRoot: TBytes;
begin
  LCerts := LoadVectorFields('Certs/Ed448Chain.txt');
  try
    LRoot := DecodeHex(LCerts.Values['root_cert']);
  finally
    LCerts.Free;
  end;
  LParams := Default(TClient12HandshakeParams);
  LParams.Clock := TSystemClock.Create;
  LParams.Crypto := Crypto;
  LParams.Inspector := Pkix.Certificates;
  LParams.GroupRegistry := TNamedGroups.CreateDefaultRegistry(Crypto);
  LParams.CipherSuites := TCipherSuiteRegistry.CreateDualVersion(Crypto);
  LParams.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  // an ECDHE_ECDSA suite carries an Ed448 credential (RFC 8422 2.1 / 5.3: an EdDSA-capable key)
  LParams.OfferedSuites := TArray<UInt16>.Create(TCipherSuites12.EcdheEcdsaAes128GcmSha256);
  LParams.OfferedGroups := TArray<UInt16>.Create(TNamedGroupCatalog.X25519,
    TNamedGroupCatalog.Secp256r1);
  LParams.OfferedSchemes := TArray<UInt16>.Create(TSignatureSchemes.Ed448);
  LParams.OfferedVersions := TArray<UInt16>.Create(TlsWireVersionTls12);
  LParams.ClientRandom := Filled($11, 32);
  LParams.LegacySessionId := nil;
  LParams.OfferExtendedMasterSecret := True;
  LParams.CertificateVerifier := TCertificateVerifier.Create(Pkix,
    TSystemClock.Create as ITlsClock,
    TTrustAnchorStore.Create(TArray<TBytes>.Create(LRoot)) as ITrustAnchorStore, True)
    as IServerCertificateVerifier;
  LParams.ExpectedServerName := TServerName.DnsName('localhost');
  Result := TTlsEngine.CreateConfigured(
    TTls12ClientStateMachine.Create(LParams) as IHandshakeMachine, Crypto);
end;

function TTestTls12Loopback.NewServerEd448: ITlsEngine;
var
  LParams: TServer12HandshakeParams;
begin
  LParams := Default(TServer12HandshakeParams);
  LParams.Policy := TNegotiationPolicy.CreateDefault(Crypto);
  LParams.Clock := TSystemClock.Create;
  LParams.Crypto := Crypto;
  LParams.Inspector := Pkix.Certificates;
  LParams.CipherSuites := TCipherSuiteRegistry.CreateDualVersion(Crypto);
  LParams.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  LParams.Group := TNamedGroups.CreateX25519(Crypto);
  LParams.ServerRandom := Filled($22, 32);
  LParams.CredentialResolver := TSniCredentialResolver.ForCredential(ServerCredentialEd448);
  LParams.RequireExtendedMasterSecret := False;
  Result := TTlsEngine.CreateConfigured(
    TTls12ServerStateMachine.Create(LParams) as IHandshakeMachine, Crypto);
end;

function TTestTls12Loopback.ServerCredentialEd25519: TTlsCredential;
var
  LCerts: TStringList;
begin
  LCerts := LoadVectorFields('Certs/Ed25519Chain.txt');
  try
    Result.CertificateChain := TArray<TBytes>.Create(
      DecodeHex(LCerts.Values['leaf_cert']));
    Result.PrivateKey := Crypto.Signing.ImportSigningKey(
      DecodeHex(LCerts.Values['leaf_key']), nil);
  finally
    LCerts.Free;
  end;
end;

function TTestTls12Loopback.NewClientEd25519: ITlsEngine;
var
  LParams: TClient12HandshakeParams;
  LCerts: TStringList;
  LRoot: TBytes;
begin
  LCerts := LoadVectorFields('Certs/Ed25519Chain.txt');
  try
    LRoot := DecodeHex(LCerts.Values['root_cert']);
  finally
    LCerts.Free;
  end;
  LParams := Default(TClient12HandshakeParams);
  LParams.Clock := TSystemClock.Create;
  LParams.Crypto := Crypto;
  LParams.Inspector := Pkix.Certificates;
  LParams.GroupRegistry := TNamedGroups.CreateDefaultRegistry(Crypto);
  LParams.CipherSuites := TCipherSuiteRegistry.CreateDualVersion(Crypto);
  LParams.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  LParams.OfferedSuites := TArray<UInt16>.Create(TCipherSuites12.EcdheEcdsaAes128GcmSha256);
  LParams.OfferedGroups := TArray<UInt16>.Create(TNamedGroupCatalog.X25519,
    TNamedGroupCatalog.Secp256r1);
  LParams.OfferedSchemes := TArray<UInt16>.Create(TSignatureSchemes.Ed25519);
  LParams.OfferedVersions := TArray<UInt16>.Create(TlsWireVersionTls12);
  LParams.ClientRandom := Filled($11, 32);
  LParams.LegacySessionId := nil;
  LParams.OfferExtendedMasterSecret := True;
  LParams.CertificateVerifier := TCertificateVerifier.Create(Pkix,
    TSystemClock.Create as ITlsClock,
    TTrustAnchorStore.Create(TArray<TBytes>.Create(LRoot)) as ITrustAnchorStore, True)
    as IServerCertificateVerifier;
  LParams.ExpectedServerName := TServerName.DnsName('localhost');
  Result := TTlsEngine.CreateConfigured(
    TTls12ClientStateMachine.Create(LParams) as IHandshakeMachine, Crypto);
end;

function TTestTls12Loopback.NewServerEd25519: ITlsEngine;
var
  LParams: TServer12HandshakeParams;
begin
  LParams := Default(TServer12HandshakeParams);
  LParams.Policy := TNegotiationPolicy.CreateDefault(Crypto);
  LParams.Clock := TSystemClock.Create;
  LParams.Crypto := Crypto;
  LParams.Inspector := Pkix.Certificates;
  LParams.CipherSuites := TCipherSuiteRegistry.CreateDualVersion(Crypto);
  LParams.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  LParams.Group := TNamedGroups.CreateX25519(Crypto);
  LParams.ServerRandom := Filled($22, 32);
  LParams.CredentialResolver := TSniCredentialResolver.ForCredential(ServerCredentialEd25519);
  LParams.RequireExtendedMasterSecret := False;
  Result := TTlsEngine.CreateConfigured(
    TTls12ServerStateMachine.Create(LParams) as IHandshakeMachine, Crypto);
end;

function TTestTls12Loopback.OcspField(const AName: string): TBytes;
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

function TTestTls12Loopback.NewStaplingServer(const AStaple: TBytes): ITlsEngine;
begin
  Result := TTlsEngine.CreateConfigured(StaplingServerMachine(AStaple), Crypto);
end;

function TTestTls12Loopback.NewHardRevocationClient: ITlsEngine;
var
  LParams: TClient12HandshakeParams;
  LOptions: TCertificateVerifierOptions;
begin
  LParams := Default(TClient12HandshakeParams);
  LParams.Clock := TSystemClock.Create;
  LParams.Crypto := Crypto;
  LParams.Inspector := Pkix.Certificates;
  LParams.GroupRegistry := TNamedGroups.CreateDefaultRegistry(Crypto);
  LParams.CipherSuites := TCipherSuiteRegistry.CreateDualVersion(Crypto);
  LParams.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  LParams.OfferedSuites := TArray<UInt16>.Create(
    TCipherSuites12.EcdheEcdsaAes128GcmSha256);
  // TLS 1.2 supported_groups gates both the ECDHE key-exchange group and the ECDSA leaf's
  // curve (RFC 8422 5.3), so it lists X25519 and Secp256r1 (the P-256 certificate curve)
  LParams.OfferedGroups := TArray<UInt16>.Create(TNamedGroupCatalog.X25519,
    TNamedGroupCatalog.Secp256r1);
  LParams.OfferedSchemes := TArray<UInt16>.Create(
    TSignatureSchemes.EcdsaSecp256r1Sha256);
  LParams.OfferedVersions := TArray<UInt16>.Create(TlsWireVersionTls12);
  LParams.ClientRandom := Filled($11, 32);
  LParams.LegacySessionId := nil;
  LParams.OfferExtendedMasterSecret := True;
  // hard-fail revocation: the leaf must come with a current Good stapled OCSP response,
  // delivered here in a CertificateStatus message (RFC 6066 8), so the client offers
  // status_request to solicit the staple
  LParams.RequestOcspStapling := True;
  LOptions.RevocationPosture := TRevocationPosture.Hard;
  LParams.CertificateVerifier := TCertificateVerifier.Create(Pkix, TSystemClock.Create as ITlsClock,
    TTrustAnchorStore.Create(TArray<TBytes>.Create(OcspField('root_cert')))
    as ITrustAnchorStore, True, LOptions) as IServerCertificateVerifier;
  LParams.ExpectedServerName := TServerName.DnsName('localhost');
  Result := TTlsEngine.CreateConfigured(
    TTls12ClientStateMachine.Create(LParams) as IHandshakeMachine, Crypto);
end;

function TTestTls12Loopback.NewServer(ARequireEms: Boolean): ITlsEngine;
begin
  Result := TTlsEngine.CreateConfigured(ServerMachine(ARequireEms), Crypto);
end;

function TTestTls12Loopback.Drain(const AEngine: ITlsEngine): TBytes;
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

procedure TTestTls12Loopback.Feed(const AEngine: ITlsEngine; const AWire: TBytes);
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

procedure TTestTls12Loopback.Pump(const ASrc, ADst: ITlsEngine);
begin
  Feed(ADst, Drain(ASrc));
end;

function TTestTls12Loopback.ReadAllApp(const AEngine: ITlsEngine): TBytes;
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

procedure TTestTls12Loopback.TestWriteAfterInboundCloseNotifyClosesWrite;
var
  LClient, LServer: ITlsEngine;
  LIterations: Int32;
  LRaised: Boolean;
begin
  LClient := NewClient(TCipherSuites12.EcdheEcdsaAes128GcmSha256, True);
  LServer := NewServer(False);
  LClient.StartHandshake;
  LIterations := 0;
  while (LClient.IsHandshaking or LServer.IsHandshaking) and (LIterations < 16) do
  begin
    Pump(LClient, LServer);
    Pump(LServer, LClient);
    Inc(LIterations);
  end;
  CheckFalse(LClient.IsHandshaking, 'the handshake completed');

  // under TLS 1.2 an inbound close_notify closes the write side too (RFC 5246 7.2.1)
  LServer.SendClose;
  Pump(LServer, LClient);
  CheckTrue(LClient.IsInboundClosed, 'the client saw the inbound close_notify');
  CheckFalse(LClient.IsTerminal, 'a close after the handshake is not a failure');
  CheckTrue(LClient.WriteClosed, 'TLS 1.2 closes the write side on an inbound close_notify');
  LRaised := False;
  try
    LClient.Write(DecodeHex('00'), 0, 1);
  except
    on EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a TLS 1.2 write after an inbound close_notify raises');
end;

procedure TTestTls12Loopback.TestWriteAtUsageLimitClosesWhenNoRekey;
var
  LClient, LServer: ITlsEngine;
  LCapped: ICryptoProvider;
  LIterations: Int32;
  LRaised: Boolean;
begin
  // a capped AEAD whose usage limit is one past the rekey lead (17 = lead 16 + 1) puts the write
  // epoch at its soft threshold on the very first application record (the Finished consumed
  // sequence 0), so a single write reaches the limit path without sealing millions of records
  LCapped := TCappedAeadProvider.Create(Crypto, 17) as ICryptoProvider;
  LClient := TTlsEngine.CreateConfigured(
    ClientMachine(TCipherSuites12.EcdheEcdsaAes128GcmSha256, True), LCapped);
  LServer := TTlsEngine.CreateConfigured(ServerMachine(False), LCapped);
  LClient.StartHandshake;
  LIterations := 0;
  while (LClient.IsHandshaking or LServer.IsHandshaking) and (LIterations < 16) do
  begin
    Pump(LClient, LServer);
    Pump(LServer, LClient);
    Inc(LIterations);
  end;
  CheckFalse(LClient.IsHandshaking, 'the handshake completed');

  // TLS 1.2 has no KeyUpdate; at the AEAD usage limit the write epoch cannot be rekeyed, so a
  // write closes the connection and refuses rather than exceed the AEAD safety bound (RFC 8446
  // 5.5 applies the same record limits to the 1.2 AEAD suites). The close_notify still seals
  // under the current, still-valid epoch.
  LRaised := False;
  try
    LClient.Write(DecodeHex('00'), 0, 1);
  except
    on ERecordLimitTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a TLS 1.2 write at the usage limit raises ERecordLimitTlsLibException');
  CheckTrue(LClient.WriteClosed, 'the connection is closed for writing after the limit');
  Pump(LClient, LServer);
  CheckTrue(LServer.IsInboundClosed, 'the peer received the close_notify emitted at the limit');
end;

procedure TTestTls12Loopback.RunHandshakeAndExchange(ASuite: UInt16;
  AOfferEms, ARequireEms: Boolean; const AMsg: string);
var
  LClient, LServer: ITlsEngine;
  LIterations: Int32;
  LFromClient, LFromServer: TBytes;
begin
  LClient := NewClient(ASuite, AOfferEms);
  LServer := NewServer(ARequireEms);

  LClient.StartHandshake;
  LIterations := 0;
  while (LClient.IsHandshaking or LServer.IsHandshaking) and (LIterations < 16) do
  begin
    Pump(LClient, LServer);
    Pump(LServer, LClient);
    Inc(LIterations);
  end;

  CheckFalse(LClient.IsHandshaking, AMsg + ': the client completed the handshake');
  CheckFalse(LServer.IsHandshaking, AMsg + ': the server completed the handshake');
  CheckFalse(LClient.IsTerminal, AMsg + ': the client did not fail');
  CheckFalse(LServer.IsTerminal, AMsg + ': the server did not fail');

  // the session uses Extended Master Secret exactly when the client offered it, and only then is a
  // keying-material exporter available (RFC 7627 5.4)
  CheckEquals(AOfferEms, LClient.ConnectionInfo.ExtendedMasterSecret,
    AMsg + ': the client reports whether EMS was used');
  CheckEquals(AOfferEms, LServer.ConnectionInfo.ExtendedMasterSecret,
    AMsg + ': the server reports whether EMS was used');
  LFromClient := LClient.ExportKeyingMaterial('EXPORTER-test', 32);
  LFromServer := LServer.ExportKeyingMaterial('EXPORTER-test', 32);
  if AOfferEms then
  begin
    CheckEquals(32, System.Length(LFromClient), AMsg + ': the client exports with EMS');
    CheckEqualBytes(AMsg + ': both peers export the same material', LFromClient, LFromServer);
  end
  else
  begin
    CheckEquals(0, System.Length(LFromClient), AMsg + ': the client exports nothing without EMS');
    CheckEquals(0, System.Length(LFromServer), AMsg + ': the server exports nothing without EMS');
  end;

  // real application data flows both ways over the negotiated AEAD keys
  LFromClient := DecodeHex('68656c6c6f2066726f6d2074686520636c69656e74');
  LClient.Write(LFromClient, 0, System.Length(LFromClient));
  Pump(LClient, LServer);
  CheckEqualBytes(AMsg + ': the server decrypts the client application data',
    LFromClient, ReadAllApp(LServer));

  LFromServer := DecodeHex('68656c6c6f2066726f6d2074686520736572766572');
  LServer.Write(LFromServer, 0, System.Length(LFromServer));
  Pump(LServer, LClient);
  CheckEqualBytes(AMsg + ': the client decrypts the server application data',
    LFromServer, ReadAllApp(LClient));
end;

procedure TTestTls12Loopback.TestEcdheEcdsaAesGcmWithExtendedMasterSecret;
begin
  RunHandshakeAndExchange(TCipherSuites12.EcdheEcdsaAes128GcmSha256, True, False,
    'ECDHE-ECDSA-AES128-GCM + EMS');
end;

procedure TTestTls12Loopback.TestServerWithoutAPolicyIsRefused;
var
  LParams: TServer12HandshakeParams;
  LMachine: IHandshakeMachine;
  LRaised: Boolean;
begin
  // the negotiation policy selects a 1.2 server's suite and group, so a server built without one
  // is refused at construction rather than failing on its first ClientHello
  LParams := Default(TServer12HandshakeParams);
  LParams.Clock := TSystemClock.Create;
  LParams.Crypto := Crypto;
  LParams.Inspector := Pkix.Certificates;
  LParams.CipherSuites := TCipherSuiteRegistry.CreateDualVersion(Crypto);
  LParams.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  LParams.ServerRandom := Filled($22, 32);
  LParams.CredentialResolver := TSniCredentialResolver.ForCredential(ServerCredential);
  LRaised := False;
  try
    LMachine := TTls12ServerStateMachine.Create(LParams) as IHandshakeMachine;
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a 1.2 server without a negotiation policy is refused');
end;

procedure TTestTls12Loopback.TestClientWriteBeforeServerFinishedIsRefused;
var
  LClient, LServer: ITlsEngine;
  LData: TBytes;
  LRaised: Boolean;
begin
  // TLS 1.2 installs the client application write epoch when the client sends its Finished, but
  // the handshake is not complete until the server Finished verifies. A Write in between must be
  // refused - the library does not offer False-Start (RFC 7918)
  LClient := NewClient(TCipherSuites12.EcdheEcdsaAes128GcmSha256, True);
  LServer := NewServer(True);
  LClient.StartHandshake;
  Pump(LClient, LServer); // ClientHello -> server
  Pump(LServer, LClient); // ServerHello..ServerHelloDone -> client; client queues its Finished flight
  CheckTrue(LClient.IsHandshaking, 'the client still awaits the server Finished');
  LData := DecodeHex('6e6f7065'); // "nope"
  LRaised := False;
  try
    LClient.Write(LData, 0, System.Length(LData));
  except
    on EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'no TLS 1.2 False-Start: the write is refused before the server Finished');
  // complete the handshake; the same write then succeeds
  Pump(LClient, LServer); // client CKE/CCS/Finished -> server; server completes
  Pump(LServer, LClient); // server CCS/Finished -> client; client completes
  CheckFalse(LClient.IsHandshaking, 'the client completed the handshake');
  LClient.Write(LData, 0, System.Length(LData));
  Pump(LClient, LServer);
  CheckEqualBytes('the client application data reaches the server', LData,
    ReadAllApp(LServer));
end;

procedure TTestTls12Loopback.TestEcdheEcdsaChaCha20WithExtendedMasterSecret;
begin
  RunHandshakeAndExchange(TCipherSuites12.EcdheEcdsaChaCha20Poly1305Sha256, True,
    False, 'ECDHE-ECDSA-ChaCha20 + EMS');
end;

procedure TTestTls12Loopback.TestPlainMasterSecretWhenEmsNotOffered;
begin
  // neither side requires EMS and the client does not offer it: the plain master
  // secret path (RFC 5246) still completes and carries application data
  RunHandshakeAndExchange(TCipherSuites12.EcdheEcdsaAes256GcmSha384, False, False,
    'ECDHE-ECDSA-AES256-GCM without EMS');
end;

procedure TTestTls12Loopback.TestRequiredEmsAbortsWhenClientDoesNotOfferIt;
var
  LClient, LServer: ITlsEngine;
  LIterations: Int32;
begin
  // the server requires extended_master_secret but the client did not offer it, so
  // the server aborts rather than falling back to a plain master secret
  LClient := NewClient(TCipherSuites12.EcdheEcdsaAes128GcmSha256, False);
  LServer := NewServer(True);

  LClient.StartHandshake;
  LIterations := 0;
  while (LClient.IsHandshaking or LServer.IsHandshaking) and (LIterations < 16) do
  begin
    Pump(LClient, LServer);
    Pump(LServer, LClient);
    Inc(LIterations);
  end;

  CheckTrue(LServer.IsTerminal, 'the server aborted when required EMS was absent');
end;

function TTestTls12Loopback.FirstRecordWith(const AWire, AExtra: TBytes): TBytes;
var
  LLen: Int32;
begin
  LLen := (AWire[3] shl 8) or AWire[4];
  Result := ConcatBytes(System.Copy(AWire, 0, TRecordLimits.HeaderLength + LLen), AExtra);
  Inc(LLen, System.Length(AExtra));
  Result[3] := Byte(LLen shr 8);
  Result[4] := Byte(LLen);
end;

function TTestTls12Loopback.TamperHandshakeMessage(var AWire: TBytes;
  AMsgType: Byte): Boolean;
var
  LPos, LRecLen, LInner, LMsgLen, LBodyEnd: Int32;
begin
  Result := False;
  LPos := 0;
  while LPos + 5 <= System.Length(AWire) do
  begin
    LRecLen := (AWire[LPos + 3] shl 8) or AWire[LPos + 4];
    // handshake records are plaintext before the ChangeCipherSpec, so their messages
    // can be walked by type; a coalesced record may carry several messages
    if AWire[LPos] = 22 then
    begin
      LInner := LPos + 5;
      while LInner + 4 <= LPos + 5 + LRecLen do
      begin
        LMsgLen := (AWire[LInner + 1] shl 16) or (AWire[LInner + 2] shl 8) or
          AWire[LInner + 3];
        LBodyEnd := LInner + 4 + LMsgLen;
        if (AWire[LInner] = AMsgType) and (LBodyEnd <= System.Length(AWire)) then
        begin
          AWire[LBodyEnd - 1] := AWire[LBodyEnd - 1] xor $01;
          Exit(True);
        end;
        LInner := LBodyEnd;
      end;
    end;
    Inc(LPos, 5 + LRecLen);
  end;
end;

function TTestTls12Loopback.TamperLastRecordPayload(var AWire: TBytes): Boolean;
var
  LPos, LRecLen, LLastPayload: Int32;
begin
  Result := False;
  LPos := 0;
  LLastPayload := -1;
  while LPos + 5 <= System.Length(AWire) do
  begin
    LRecLen := (AWire[LPos + 3] shl 8) or AWire[LPos + 4];
    if LRecLen > 0 then
      LLastPayload := LPos + 5;
    Inc(LPos, 5 + LRecLen);
  end;
  if LLastPayload >= 0 then
  begin
    AWire[LLastPayload] := AWire[LLastPayload] xor $01;
    Result := True;
  end;
end;

procedure TTestTls12Loopback.TestTamperedServerKeyExchangeSignatureAborts;
var
  LClient, LServer: ITlsEngine;
  LWire: TBytes;
begin
  // a corrupted ServerKeyExchange signature must fail the client's signature check,
  // never complete the handshake - guards the 1.2 SKE signature verification
  LClient := NewClient(TCipherSuites12.EcdheEcdsaAes128GcmSha256, True);
  LServer := NewServer(False);
  LClient.StartHandshake;
  Pump(LClient, LServer); // the server consumes the ClientHello and emits its first flight
  LWire := Drain(LServer);
  CheckTrue(TamperHandshakeMessage(LWire, 12),
    'the ServerKeyExchange (handshake type 12) is present to tamper');
  Feed(LClient, LWire);

  CheckTrue(LClient.IsTerminal, 'a corrupted ServerKeyExchange signature fails the client');
  CheckFalse(LClient.IsHandshaking, 'the client did not stay handshaking');
  CheckEquals(Ord(TTlsAlertDescription.DecryptError),
    Ord(LClient.LastError.Alert.Description), 'the client aborts with decrypt_error');
  CheckEquals(0, System.Length(ReadAllApp(LClient)),
    'no application data is produced after the abort');
end;

procedure TTestTls12Loopback.TestTamperedClientFinishedAborts;
var
  LClient, LServer: ITlsEngine;
  LWire: TBytes;
begin
  // a corrupted client Finished record must fail the server, never complete the
  // handshake - guards the 1.2 Finished path (the record decrypts under the AEAD keys)
  LClient := NewClient(TCipherSuites12.EcdheEcdsaAes128GcmSha256, True);
  LServer := NewServer(False);
  LClient.StartHandshake;
  Pump(LClient, LServer); // server: ServerHello..ServerHelloDone
  Pump(LServer, LClient); // client: ClientKeyExchange, ChangeCipherSpec, (encrypted) Finished
  LWire := Drain(LClient);
  CheckTrue(TamperLastRecordPayload(LWire),
    'the client emitted a Finished record to tamper');
  Feed(LServer, LWire);

  CheckTrue(LServer.IsTerminal, 'a corrupted client Finished fails the server');
  CheckFalse(LServer.IsHandshaking, 'the server did not stay handshaking');
  CheckEquals(0, System.Length(ReadAllApp(LServer)),
    'no application data is produced after the abort');
end;

function TTestTls12Loopback.SendMessages(
  const AEffects: TArray<THandshakeEffect>): TArray<TBytes>;
var
  LEffect: THandshakeEffect;
begin
  Result := nil;
  for LEffect in AEffects do
    if LEffect.Kind = THandshakeEffectKind.SendHandshake then
    begin
      SetLength(Result, System.Length(Result) + 1);
      Result[System.High(Result)] := LEffect.Bytes;
    end;
end;

function TTestTls12Loopback.DeliverFlight(const ADst: IHandshakeMachine;
  const AMsgs: TArray<TBytes>): TArray<THandshakeEffect>;
var
  LFramed: TBytes;
  LReader: THandshakeMessageReader;
  LMsg: TTlsHandshakeMessage;
  LEffect: THandshakeEffect;
begin
  Result := nil;
  for LFramed in AMsgs do
  begin
    LReader := THandshakeMessageReader.Create;
    try
      LReader.Append(LFramed, 0, System.Length(LFramed));
      while LReader.NextMessage(LMsg) do
        for LEffect in ADst.ProcessMessage(LMsg) do
        begin
          SetLength(Result, System.Length(Result) + 1);
          Result[System.High(Result)] := LEffect;
        end;
    finally
      LReader.Free;
    end;
  end;
end;

function TTestTls12Loopback.HasFailAlert(
  const AEffects: TArray<THandshakeEffect>; AAlert: TTlsAlertDescription): Boolean;
var
  LEffect: THandshakeEffect;
begin
  Result := False;
  for LEffect in AEffects do
    if (LEffect.Kind = THandshakeEffectKind.Fail) and (LEffect.Alert = AAlert) then
      Result := True;
end;

function TTestTls12Loopback.DecodeServerFlightHello(
  const AFlight: TArray<TBytes>): TTlsServerHello;
var
  LReader: THandshakeMessageReader;
  LMsg: TTlsHandshakeMessage;
begin
  Result := Default(TTlsServerHello);
  LReader := THandshakeMessageReader.Create;
  try
    LReader.Append(AFlight[0], 0, System.Length(AFlight[0]));
    if LReader.NextMessage(LMsg) then
      Result := THandshakeMessages.DecodeServerHello(LMsg.Body);
  finally
    LReader.Free;
  end;
end;

function TTestTls12Loopback.HasEffect(const AEffects: TArray<THandshakeEffect>;
  AKind: THandshakeEffectKind): Boolean;
var
  LEffect: THandshakeEffect;
begin
  Result := False;
  for LEffect in AEffects do
    if LEffect.Kind = AKind then
      Exit(True);
end;

function TTestTls12Loopback.AllServerMessages(
  const AFlight: TArray<TBytes>): TArray<TBytes>;
var
  LFramed: TBytes;
  LReader: THandshakeMessageReader;
  LMsg: TTlsHandshakeMessage;
begin
  Result := nil;
  for LFramed in AFlight do
  begin
    LReader := THandshakeMessageReader.Create;
    try
      LReader.Append(LFramed, 0, System.Length(LFramed));
      while LReader.NextMessage(LMsg) do
      begin
        SetLength(Result, System.Length(Result) + 1);
        Result[System.High(Result)] := LMsg.Raw;
      end;
    finally
      LReader.Free;
    end;
  end;
end;

function TTestTls12Loopback.StaplingServerMachine(
  const AStaple: TBytes): IHandshakeMachine;
var
  LParams: TServer12HandshakeParams;
  LCred: TTlsCredential;
begin
  LParams := Default(TServer12HandshakeParams);
  LParams.Policy := TNegotiationPolicy.CreateDefault(Crypto);
  LParams.Clock := TSystemClock.Create;
  LParams.Crypto := Crypto;
  LParams.Inspector := Pkix.Certificates;
  LParams.CipherSuites := TCipherSuiteRegistry.CreateDualVersion(Crypto);
  LParams.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  LParams.Group := TNamedGroups.CreateX25519(Crypto);
  LParams.ServerRandom := Filled($22, 32);
  // the leaf's issuer travels in the chain so the client can authenticate the staple
  LCred := Default(TTlsCredential);
  LCred.CertificateChain := TArray<TBytes>.Create(
    OcspField('leaf_cert'), OcspField('issuer_cert'));
  LCred.PrivateKey := Crypto.Signing.ImportSigningKey(OcspField('leaf_key'), nil);
  LCred.OcspStaple := AStaple;
  LParams.CredentialResolver := TSniCredentialResolver.ForCredential(LCred);
  Result := TTls12ServerStateMachine.Create(LParams) as IHandshakeMachine;
end;

function TTestTls12Loopback.ParkingStaplingClientMachine: IHandshakeMachine;
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
  LParams.OfferedSuites := TArray<UInt16>.Create(
    TCipherSuites12.EcdheEcdsaAes128GcmSha256);
  LParams.OfferedGroups := TArray<UInt16>.Create(TNamedGroupCatalog.X25519,
    TNamedGroupCatalog.Secp256r1);
  LParams.OfferedSchemes := TArray<UInt16>.Create(
    TSignatureSchemes.EcdsaSecp256r1Sha256);
  LParams.OfferedVersions := TArray<UInt16>.Create(TlsWireVersionTls12);
  LParams.ClientRandom := Filled($11, 32);
  LParams.LegacySessionId := nil;
  LParams.OfferExtendedMasterSecret := True;
  // solicit the staple (so the client waits for a CertificateStatus) and hand the peer-certificate
  // verdict to the host, so a verified chain parks instead of completing inline
  LParams.RequestOcspStapling := True;
  LParams.Deferral := TVerdictDeferral.HostDecision;
  LParams.CertificateVerifier := TCertificateVerifier.Create(Pkix,
    TSystemClock.Create as ITlsClock,
    TTrustAnchorStore.Create(TArray<TBytes>.Create(OcspField('root_cert')))
    as ITrustAnchorStore, True) as IServerCertificateVerifier;
  LParams.ExpectedServerName := TServerName.DnsName('localhost');
  Result := TTls12ClientStateMachine.Create(LParams) as IHandshakeMachine;
end;

procedure TTestTls12Loopback.TestParkedClientDefersServerKeyExchangeAfterOmittedCertificateStatus;
var
  LClient, LServer: IHandshakeMachine;
  LMsgs: TArray<TBytes>;
  LEffects: TArray<THandshakeEffect>;
begin
  // the server echoes status_request and staples, so a client that offered status_request waits for a
  // CertificateStatus. Deliver ServerHello+Certificate, then the ServerKeyExchange while omitting the
  // CertificateStatus: the client verifies the chain (no staple) and, because the verdict is deferred
  // to the host, PARKS - and must DEFER the coalesced ServerKeyExchange rather than advance the park
  LClient := ParkingStaplingClientMachine;
  LServer := StaplingServerMachine(OcspField('ocsp_good'));
  LMsgs := AllServerMessages(SendMessages(DeliverFlight(LServer, SendMessages(LClient.Start))));
  // [ServerHello, Certificate, CertificateStatus, ServerKeyExchange, ServerHelloDone]
  CheckEquals(5, System.Length(LMsgs), 'the server produced the expected stapled 1.2 flight');

  DeliverFlight(LClient, TArray<TBytes>.Create(LMsgs[0], LMsgs[1]));
  LEffects := DeliverFlight(LClient, TArray<TBytes>.Create(LMsgs[3]));
  CheckTrue(LClient.Stage = THandshakeStage.ParkedForVerdict,
    'the client parks for the host verdict after verifying without a staple');
  CheckTrue(HasEffect(LEffects, THandshakeEffectKind.AwaitCertificateVerdict),
    'the park surfaces AwaitCertificateVerdict');
  CheckTrue(HasEffect(LEffects, THandshakeEffectKind.PeerCertificateChain),
    'and the peer certificate chain');
  CheckFalse(HasEffect(LEffects, THandshakeEffectKind.SendHandshake),
    'the deferred ServerKeyExchange did not advance the parked handshake');
  CheckFalse(HasEffect(LEffects, THandshakeEffectKind.Fail), 'and did not fail');

  LEffects := LClient.ResumeAfterVerdict;
  CheckTrue(LClient.Stage = THandshakeStage.Handshaking, 'resuming clears the park');
  CheckFalse(HasEffect(LEffects, THandshakeEffectKind.Fail),
    'the deferred ServerKeyExchange re-dispatches cleanly on resume');

  LEffects := DeliverFlight(LClient, TArray<TBytes>.Create(LMsgs[4]));
  CheckTrue(HasEffect(LEffects, THandshakeEffectKind.SendHandshake),
    'the client emits its flight once ServerHelloDone arrives, proving the deferred SKE was consumed');
  CheckFalse(HasEffect(LEffects, THandshakeEffectKind.Fail), 'the handshake proceeds without failing');
end;

procedure TTestTls12Loopback.TestParkedClientDefersAnOutOfOrderMessageUntilResume;
var
  LClient, LServer: IHandshakeMachine;
  LMsgs: TArray<TBytes>;
  LEffects: TArray<THandshakeEffect>;
begin
  // the deferred message must be acted on ONLY after resume, never in place while parked. Deliver a
  // ServerHelloDone (out of order for the awaited ServerKeyExchange) as the message following the
  // omitted CertificateStatus: with the park honoured its protocol error surfaces on resume; a parked
  // machine that processed it in place would raise the Fail during the park instead
  LClient := ParkingStaplingClientMachine;
  LServer := StaplingServerMachine(OcspField('ocsp_good'));
  LMsgs := AllServerMessages(SendMessages(DeliverFlight(LServer, SendMessages(LClient.Start))));
  CheckEquals(5, System.Length(LMsgs), 'the server produced the expected stapled 1.2 flight');

  DeliverFlight(LClient, TArray<TBytes>.Create(LMsgs[0], LMsgs[1]));
  LEffects := DeliverFlight(LClient, TArray<TBytes>.Create(LMsgs[4]));
  CheckTrue(LClient.Stage = THandshakeStage.ParkedForVerdict, 'the client parks for the host verdict');
  CheckFalse(HasEffect(LEffects, THandshakeEffectKind.Fail),
    'the out-of-order message is deferred, not acted on while parked');

  LEffects := LClient.ResumeAfterVerdict;
  CheckTrue(HasFailAlert(LEffects, TTlsAlertDescription.UnexpectedMessage),
    'the deferred message''s protocol error surfaces on resume, proving it was not processed in the park');
end;

procedure TTestTls12Loopback.TestClientRejectsServerHelloLegacyVersionBelowTls12;
var
  LClient, LServer: IHandshakeMachine;
  LFlight: TArray<TBytes>;
  LFramed: TBytes;
begin
  // a single-version 1.2 client (built directly, not via the version dispatcher) rejects a
  // ServerHello whose legacy_version is below TLS 1.2 (RFC 5246 / RFC 8446 4.1.3): protocol_version.
  // the conformant encoder always writes 0x0303, so patch the low byte of legacy_version directly
  LClient := ClientMachine(TCipherSuites12.EcdheEcdsaAes128GcmSha256, True);
  LServer := ServerMachine(False);
  LFlight := SendMessages(DeliverFlight(LServer, SendMessages(LClient.Start)));
  CheckTrue(System.Length(LFlight) > 0, 'the server produced a flight');
  LFramed := THandshakeFraming.Frame(TTlsHandshakeType.ServerHello,
    THandshakeMessages.EncodeServerHello(DecodeServerFlightHello(LFlight)));
  LFramed[5] := $02; // 0x0303 -> 0x0302 (TLS 1.1)
  CheckTrue(HasFailAlert(DeliverFlight(LClient, TArray<TBytes>.Create(LFramed)),
    TTlsAlertDescription.ProtocolVersion),
    'a sub-1.2 legacy_version in the ServerHello aborts with protocol_version');
end;

procedure TTestTls12Loopback.TestClientRejectsSupportedVersionsInTls12ServerHello;
var
  LClient, LServer: IHandshakeMachine;
  LFlight: TArray<TBytes>;
  LSh: TTlsServerHello;
  LVec: TExtensionVector;
begin
  // a 1.2 ServerHello must not echo supported_versions (that selects 1.3); the single-version 1.2
  // client rejects the echo of an extension it offered with unsupported_extension
  LClient := ClientMachine(TCipherSuites12.EcdheEcdsaAes128GcmSha256, True);
  LServer := ServerMachine(False);
  LFlight := SendMessages(DeliverFlight(LServer, SendMessages(LClient.Start)));
  CheckTrue(System.Length(LFlight) > 0, 'the server produced a flight');
  LSh := DecodeServerFlightHello(LFlight);
  LVec := TExtensionVector.Parse(LSh.Extensions);
  // the ServerHello selection form of supported_versions is the single chosen version
  LVec.Append(TExtensionEntry.Create(TExtensionTypes.SupportedVersions, TBytes.Create($03, $04)));
  LSh.Extensions := LVec.Encode;
  CheckTrue(HasFailAlert(DeliverFlight(LClient, TArray<TBytes>.Create(
    THandshakeFraming.Frame(TTlsHandshakeType.ServerHello,
    THandshakeMessages.EncodeServerHello(LSh)))), TTlsAlertDescription.UnsupportedExtension),
    'a supported_versions extension in a 1.2 ServerHello aborts with unsupported_extension');
end;

procedure TTestTls12Loopback.TestServerRejectsClientFinishedWithWrongVerifyData;
var
  LClient, LServer: IHandshakeMachine;
  LClientFlight: TArray<TBytes>;
  LFinished: TBytes;
  LEffect: THandshakeEffect;
  LI: Int32;
  LRejected: Boolean;
begin
  // white-box: two bare 1.2 machines (no record layer, so the Finished is a plaintext
  // message) driven to the client's second flight; corrupting one verify_data byte while
  // the framing stays valid must make the SERVER state machine reject it. This guards the
  // ProcessClientFinished enforcement specifically - the AEAD-level tamper test would stay
  // green even if that check were removed, because the record MAC catches its flip first
  LClient := ClientMachine(TCipherSuites12.EcdheEcdsaAes128GcmSha256, True);
  LServer := ServerMachine(False);

  // ClientHello -> the server flight -> the client's ClientKeyExchange + Finished
  LClientFlight := SendMessages(DeliverFlight(LClient,
    SendMessages(DeliverFlight(LServer, SendMessages(LClient.Start)))));
  CheckTrue(System.Length(LClientFlight) >= 2,
    'the client emitted a ClientKeyExchange and a Finished');

  // deliver every message but the Finished: the ClientKeyExchange derives the keys and
  // moves the server to WaitClientFinished
  for LI := 0 to System.High(LClientFlight) - 1 do
    DeliverFlight(LServer, TArray<TBytes>.Create(LClientFlight[LI]));

  // flip the last verify_data byte (msg_type + 3-byte length are left intact)
  LFinished := System.Copy(LClientFlight[System.High(LClientFlight)]);
  LFinished[System.High(LFinished)] := Byte(LFinished[System.High(LFinished)] xor $01);

  LRejected := False;
  for LEffect in DeliverFlight(LServer, TArray<TBytes>.Create(LFinished)) do
    if (LEffect.Kind = THandshakeEffectKind.Fail) and
      (LEffect.Alert = TTlsAlertDescription.DecryptError) then
      LRejected := True;
  CheckTrue(LRejected,
    'the server rejects a client Finished with wrong verify_data (decrypt_error)');
end;

procedure TTestTls12Loopback.TestClientAnswersHelloRequestWithWarningThenAborts;
var
  LClient, LServer: IHandshakeMachine;
  LEffects: TArray<THandshakeEffect>;
  LEffect: THandshakeEffect;
  LWarnings, LFails: Int32;
begin
  // white-box: two bare 1.2 machines driven to Connected. This client does not renegotiate,
  // so a post-handshake HelloRequest is answered with a warning no_renegotiation and the
  // connection continues; a second one is fatal (RFC 5246 7.2.2, RFC 5746 4.2)
  LClient := ClientMachine(TCipherSuites12.EcdheEcdsaAes128GcmSha256, True);
  LServer := ServerMachine(False);
  // ClientHello -> server flight -> client ClientKeyExchange+Finished -> server Finished -> client
  DeliverFlight(LClient, SendMessages(DeliverFlight(LServer,
    SendMessages(DeliverFlight(LClient, SendMessages(DeliverFlight(LServer,
    SendMessages(LClient.Start))))))));

  // a HelloRequest is type 0 with an empty body
  LWarnings := 0;
  for LEffect in DeliverFlight(LClient, TArray<TBytes>.Create(DecodeHex('00000000'))) do
    if (LEffect.Kind = THandshakeEffectKind.SendWarningAlert) and
      (LEffect.Alert = TTlsAlertDescription.NoRenegotiation) then
      Inc(LWarnings);
  CheckEquals(1, LWarnings, 'the first HelloRequest yields one warning no_renegotiation');

  LFails := 0;
  LEffects := DeliverFlight(LClient, TArray<TBytes>.Create(DecodeHex('00000000')));
  for LEffect in LEffects do
    if (LEffect.Kind = THandshakeEffectKind.Fail) and
      (LEffect.Alert = TTlsAlertDescription.IllegalParameter) then
      Inc(LFails);
  CheckEquals(1, LFails, 'a second HelloRequest is fatal illegal_parameter');
end;

procedure TTestTls12Loopback.TestNonEmptyHelloRequestIsDecodeError;
var
  LClient, LServer: IHandshakeMachine;
  LEffect: THandshakeEffect;
  LFails: Int32;
begin
  // a HelloRequest carries an empty body (RFC 5246 7.4.1.1); a non-empty one is a decode_error
  LClient := ClientMachine(TCipherSuites12.EcdheEcdsaAes128GcmSha256, True);
  LServer := ServerMachine(False);
  DeliverFlight(LClient, SendMessages(DeliverFlight(LServer,
    SendMessages(DeliverFlight(LClient, SendMessages(DeliverFlight(LServer,
    SendMessages(LClient.Start))))))));

  LFails := 0;
  // type 0, length 1, one body byte
  for LEffect in DeliverFlight(LClient, TArray<TBytes>.Create(DecodeHex('00000001FF'))) do
    if (LEffect.Kind = THandshakeEffectKind.Fail) and
      (LEffect.Alert = TTlsAlertDescription.DecodeError) then
      Inc(LFails);
  CheckEquals(1, LFails, 'a HelloRequest with a non-empty body is decode_error');
end;

procedure TTestTls12Loopback.TestStapledGoodOcspCompletesUnderHardPosture;
var
  LClient, LServer: ITlsEngine;
  LIterations: Int32;
begin
  // the server sends a CertificateStatus carrying a current Good OCSP response, which a
  // hard-fail client requires (RFC 6066 8)
  LClient := NewHardRevocationClient;
  LServer := NewStaplingServer(OcspField('ocsp_good'));
  LClient.StartHandshake;

  LIterations := 0;
  while (LClient.IsHandshaking or LServer.IsHandshaking) and (LIterations < 16) do
  begin
    Pump(LClient, LServer);
    Pump(LServer, LClient);
    Inc(LIterations);
  end;

  CheckFalse(LClient.IsHandshaking, 'the client completed the handshake');
  CheckFalse(LClient.IsTerminal, 'the client accepted the stapled Good response');
  CheckFalse(LServer.IsTerminal, 'the server completed the handshake');
end;

procedure TTestTls12Loopback.TestMissingStapleAbortsUnderHardPosture;
var
  LClient, LServer: ITlsEngine;
  LIterations: Int32;
begin
  // the same client, but the server sends no CertificateStatus: hard-fail rejects the leaf
  LClient := NewHardRevocationClient;
  LServer := NewStaplingServer(nil);
  LClient.StartHandshake;

  LIterations := 0;
  while (LClient.IsHandshaking or LServer.IsHandshaking) and (LIterations < 16) do
  begin
    Pump(LClient, LServer);
    Pump(LServer, LClient);
    Inc(LIterations);
  end;

  CheckTrue(LClient.IsTerminal,
    'the client aborted the handshake for a missing staple under hard-fail');
end;

procedure TTestTls12Loopback.TestPlaintextFinishedPackedWithKeyExchangeIsExcessData;
var
  LClient, LServer: ITlsEngine;
  LFlight, LMerged: TBytes;
  LOutcome: TTlsOutcome;
begin
  LClient := NewClient(TCipherSuites12.EcdheEcdsaAes128GcmSha256, True);
  LServer := NewServer(False);
  LClient.StartHandshake;
  Pump(LClient, LServer);
  Pump(LServer, LClient);
  LFlight := Drain(LClient);
  // a plaintext Finished packed behind the ClientKeyExchange would complete the handshake with
  // the read cipher never switched (RFC 5246 7.4.9: Finished follows the change_cipher_spec)
  LMerged := FirstRecordWith(LFlight, DecodeHex('14 00 00 0c 000000000000000000000000'));
  LOutcome := LServer.ProcessInput(LMerged, 0, System.Length(LMerged));
  CheckEquals(Ord(TTlsOutcome.Fatal), Ord(LOutcome), 'a Finished packed behind the key exchange is fatal');
  CheckTrue(LServer.LastError.Alert.Description = TTlsAlertDescription.UnexpectedMessage,
    'it aborts with unexpected_message');
end;

procedure TTestTls12Loopback.TestEcdheEd448CredentialHandshake;
var
  LClient, LServer: ITlsEngine;
  LIterations: Int32;
  LMsg: TBytes;
begin
  LClient := NewClientEd448;
  LServer := NewServerEd448;
  LClient.StartHandshake;
  LIterations := 0;
  while (LClient.IsHandshaking or LServer.IsHandshaking) and (LIterations < 16) do
  begin
    Pump(LClient, LServer);
    Pump(LServer, LClient);
    Inc(LIterations);
  end;
  // the 1.2 server selected the ECDHE_ECDSA suite for its Ed448 credential (the auth-method
  // allowlist admits EdDSA), signed the ServerKeyExchange with ed448, and the client verified it
  CheckFalse(LClient.IsHandshaking, 'the client completed the 1.2 Ed448 handshake');
  CheckFalse(LServer.IsHandshaking, 'the server completed the 1.2 Ed448 handshake');
  CheckFalse(LClient.IsTerminal, 'the client did not fail');
  CheckFalse(LServer.IsTerminal, 'the server did not fail');
  LMsg := DecodeHex('656434343820312e32'); // "ed448 1.2"
  LClient.Write(LMsg, 0, System.Length(LMsg));
  Pump(LClient, LServer);
  CheckEqualBytes('app data flows over the 1.2 Ed448-authenticated channel', LMsg,
    ReadAllApp(LServer));
end;

procedure TTestTls12Loopback.TestEcdheEd25519CredentialHandshake;
var
  LClient, LServer: ITlsEngine;
  LIterations: Int32;
  LMsg: TBytes;
begin
  LClient := NewClientEd25519;
  LServer := NewServerEd25519;
  LClient.StartHandshake;
  LIterations := 0;
  while (LClient.IsHandshaking or LServer.IsHandshaking) and (LIterations < 16) do
  begin
    Pump(LClient, LServer);
    Pump(LServer, LClient);
    Inc(LIterations);
  end;
  CheckFalse(LClient.IsHandshaking, 'the client completed the 1.2 Ed25519 handshake');
  CheckFalse(LServer.IsHandshaking, 'the server completed the 1.2 Ed25519 handshake');
  CheckFalse(LClient.IsTerminal, 'the client did not fail');
  CheckFalse(LServer.IsTerminal, 'the server did not fail');
  LMsg := DecodeHex('65643235353139'); // "ed25519"
  LClient.Write(LMsg, 0, System.Length(LMsg));
  Pump(LClient, LServer);
  CheckEqualBytes('app data flows over the 1.2 Ed25519-authenticated channel', LMsg,
    ReadAllApp(LServer));
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestTls12Loopback);
{$ELSE}
  RegisterTest(TTestTls12Loopback.Suite);
{$ENDIF FPC}

end.
