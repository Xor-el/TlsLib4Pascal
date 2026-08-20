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
  TlpNamedGroups,
  TlpNegotiationTypes,
  TlpCipherSuiteRegistry,
  TlpCoreExtensions,
  TlpITlsEngine,
  TlpTlsEngine,
  TlpIHandshakeMachine,
  TlpHandshakeEffect,
  TlpHandshakeMessage,
  TlpICertificateTrust,
  TlpCertificateVerifier,
  TlpCertificateLimits,
  TlpTrustPolicy,
  TlpTlsCredential,
  TlpCredentialResolvers,
  TlpTls12ClientStateMachine,
  TlpTls12ServerStateMachine,
  TlsLibTestBase;

type
  TTestTls12Loopback = class(TTlsLibAlgorithmTestCase)
  private
    function Filled(AByte: Byte; ACount: Int32): TBytes;
    function TestRootCertificate: TBytes;
    function ServerCredential: TTlsCredential;
    function NewClient(ASuite: UInt16; AOfferEms: Boolean): ITlsEngine;
    function NewServer(ARequireEms: Boolean): ITlsEngine;
    function Drain(const AEngine: ITlsEngine): TBytes;
    procedure Feed(const AEngine: ITlsEngine; const AWire: TBytes);
    procedure Pump(const ASrc, ADst: ITlsEngine);
    function ReadAllApp(const AEngine: ITlsEngine): TBytes;
    procedure RunHandshakeAndExchange(ASuite: UInt16; AOfferEms, ARequireEms: Boolean;
      const AMsg: string);
    /// <summary>Flips the last byte of the first handshake message of AMsgType found in
    /// the plaintext handshake records of AWire (test-only wire mutation).</summary>
    function TamperHandshakeMessage(var AWire: TBytes; AMsgType: Byte): Boolean;
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
  published
    procedure TestEcdheEcdsaAesGcmWithExtendedMasterSecret;
    procedure TestEcdheEcdsaChaCha20WithExtendedMasterSecret;
    procedure TestPlainMasterSecretWhenEmsNotOffered;
    procedure TestRequiredEmsAbortsWhenClientDoesNotOfferIt;
    procedure TestTamperedServerKeyExchangeSignatureAborts;
    procedure TestTamperedClientFinishedAborts;
    procedure TestServerRejectsClientFinishedWithWrongVerifyData;
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
    Result.PrivateKey := Provider.ImportSigningKey(DecodeHex(LCerts.Values['leaf_key']));
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
  LParams.Provider := Provider;
  LParams.GroupRegistry := TNamedGroups.CreateDefaultRegistry(Provider);
  LParams.CipherSuites := TCipherSuiteRegistry.CreateDualVersion(Provider);
  LParams.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  LParams.OfferedSuites := TArray<UInt16>.Create(ASuite);
  // TLS 1.2 supported_groups gates both the ECDHE key-exchange group and the ECDSA leaf's
  // curve (RFC 8422 5.1), so it lists X25519 and Secp256r1 (the P-256 certificate curve)
  LParams.OfferedGroups := TArray<UInt16>.Create(TNamedGroupCatalog.X25519,
    TNamedGroupCatalog.Secp256r1);
  LParams.OfferedSchemes := TArray<UInt16>.Create(
    TSignatureSchemes.EcdsaSecp256r1Sha256);
  LParams.OfferedVersions := TArray<UInt16>.Create(TlsWireVersionTls12);
  LParams.ClientRandom := Filled($11, 32);
  LParams.LegacySessionId := nil;
  LParams.OfferExtendedMasterSecret := AOfferEms;
  LParams.CertificateVerifier := TCertificateVerifier.Create(Provider, TSystemClock.Create as ITlsClock,
    TTrustAnchorStore.Create(TArray<TBytes>.Create(TestRootCertificate))
    as ITrustAnchorStore, True) as ICertificateVerifier;
  LParams.ExpectedHostName := 'localhost';
  Result := TTls12ClientStateMachine.Create(LParams) as IHandshakeMachine;
end;

function TTestTls12Loopback.NewClient(ASuite: UInt16;
  AOfferEms: Boolean): ITlsEngine;
begin
  Result := TTlsEngine.CreateConfigured(ClientMachine(ASuite, AOfferEms), Provider);
end;

function TTestTls12Loopback.ServerMachine(ARequireEms: Boolean): IHandshakeMachine;
var
  LParams: TServer12HandshakeParams;
begin
  LParams := Default(TServer12HandshakeParams);
  LParams.Clock := TSystemClock.Create;
  LParams.Provider := Provider;
  LParams.CipherSuites := TCipherSuiteRegistry.CreateDualVersion(Provider);
  LParams.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  LParams.Group := TNamedGroups.CreateX25519(Provider);
  LParams.ServerRandom := Filled($22, 32);
  LParams.CredentialResolver := TSniCredentialResolver.ForCredential(ServerCredential);
  LParams.RequireExtendedMasterSecret := ARequireEms;
  Result := TTls12ServerStateMachine.Create(LParams) as IHandshakeMachine;
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
var
  LParams: TServer12HandshakeParams;
  LCred: TTlsCredential;
begin
  LParams := Default(TServer12HandshakeParams);
  LParams.Clock := TSystemClock.Create;
  LParams.Provider := Provider;
  LParams.CipherSuites := TCipherSuiteRegistry.CreateDualVersion(Provider);
  LParams.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  LParams.Group := TNamedGroups.CreateX25519(Provider);
  LParams.ServerRandom := Filled($22, 32);
  // the leaf's issuer travels in the chain so the client can authenticate the staple
  LCred := Default(TTlsCredential);
  LCred.CertificateChain := TArray<TBytes>.Create(
    OcspField('leaf_cert'), OcspField('issuer_cert'));
  LCred.PrivateKey := Provider.ImportSigningKey(OcspField('leaf_key'));
  LCred.OcspStaple := AStaple;
  LParams.CredentialResolver := TSniCredentialResolver.ForCredential(LCred);
  Result := TTlsEngine.CreateConfigured(
    TTls12ServerStateMachine.Create(LParams) as IHandshakeMachine, Provider);
end;

function TTestTls12Loopback.NewHardRevocationClient: ITlsEngine;
var
  LParams: TClient12HandshakeParams;
begin
  LParams := Default(TClient12HandshakeParams);
  LParams.Clock := TSystemClock.Create;
  LParams.Provider := Provider;
  LParams.GroupRegistry := TNamedGroups.CreateDefaultRegistry(Provider);
  LParams.CipherSuites := TCipherSuiteRegistry.CreateDualVersion(Provider);
  LParams.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  LParams.OfferedSuites := TArray<UInt16>.Create(
    TCipherSuites12.EcdheEcdsaAes128GcmSha256);
  // TLS 1.2 supported_groups gates both the ECDHE key-exchange group and the ECDSA leaf's
  // curve (RFC 8422 5.1), so it lists X25519 and Secp256r1 (the P-256 certificate curve)
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
  LParams.CertificateVerifier := TCertificateVerifier.Create(Provider, TSystemClock.Create as ITlsClock,
    TTrustAnchorStore.Create(TArray<TBytes>.Create(OcspField('root_cert')))
    as ITrustAnchorStore, True, TCertificateChainLimits.Defaults,
    TRevocationPosture.Hard) as ICertificateVerifier;
  LParams.ExpectedHostName := 'localhost';
  Result := TTlsEngine.CreateConfigured(
    TTls12ClientStateMachine.Create(LParams) as IHandshakeMachine, Provider);
end;

function TTestTls12Loopback.NewServer(ARequireEms: Boolean): ITlsEngine;
begin
  Result := TTlsEngine.CreateConfigured(ServerMachine(ARequireEms), Provider);
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

initialization

{$IFDEF FPC}
  RegisterTest(TTestTls12Loopback);
{$ELSE}
  RegisterTest(TTestTls12Loopback.Suite);
{$ENDIF FPC}

end.
