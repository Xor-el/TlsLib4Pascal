{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit Tls13ClientReplayTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  TlpClock,
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
  TlpISecretBuffer,
  TlpSecretBuffer,
  TlpCryptoAlgorithms,
  TlpINamedGroup,
  TlpIRecordProtection,
  TlpNegotiationTypes,
  TlpCipherSuiteRegistry,
  TlpCoreExtensions,
  TlpExtensionContext,
  TlpITlsExtension,
  TlpExtensionBlockCodec,
  TlpRecordLayer,
  TlpITlsEngine,
  TlpHandshakeMessage,
  TlpHandshakeMessages,
  TlpIHandshakeChannel,
  TlpHandshakeChannel,
  TlpIHandshakeMachine,
  TlpHandshakeEffect,
  TlpHandshakeDriver,
  TlpICertificateTrust,
  TlpTls13ClientStateMachine,
  TlsLibTestBase;

type
  /// <summary>A verifier that trusts any chain (for tests not exercising trust).</summary>
  TAcceptAllVerifier = class(TInterfacedObject, ICertificateVerifier)
  public
    function Verify(const AChain: TArray<TBytes>; const AHostName: string;
      const AOcspStaple: TBytes; out AAlert: TTlsAlertDescription): Boolean;
  end;

  /// <summary>A named group that yields a fixed shared secret (for RFC replay).</summary>
  TReplayGroup = class(TInterfacedObject, INamedGroup)
  strict private
    FShared: TBytes;
  public
    constructor Create(const AShared: TBytes);
    function Code: UInt16;
    function Name: string;
    function Kind: TNamedGroupKind;
    procedure GenerateKeyPair(out APriv: ISecretBuffer; out APubShare: TBytes);
    procedure Encapsulate(const APeerPub: TBytes; out ACiphertext: TBytes;
      out ASharedSecret: ISecretBuffer);
    procedure Decapsulate(const APriv: ISecretBuffer; const ACiphertext: TBytes;
      out ASharedSecret: ISecretBuffer);
    function ValidatePeerShare(const AShare: TBytes): Boolean;
  end;

  /// <summary>Installs record protection straight onto a record layer (test seam).</summary>
  TRecordLayerInstaller = class(TInterfacedObject, IRecordEpochInstaller)
  strict private
    FLayer: TRecordLayer;
  public
    constructor Create(const ALayer: TRecordLayer);
    procedure InstallReadProtection(const AProtection: IRecordProtection);
    procedure InstallWriteProtection(const AProtection: IRecordProtection);
    procedure RevertWriteToPlaintext;
    procedure SetRecordSizeLimit(AOutboundPlaintext, AInboundPlaintext: Int32);
    procedure SetEarlyDataSkip(AMaxBytes: Int32);
    procedure SetEarlyDataLimit(AMaxBytes: Int32);
    procedure SetEarlyReadEpoch(AActive: Boolean);
  end;

  TSilentSink = class(TInterfacedObject, IHandshakeSink)
  public
    procedure OnHandshakeEvent(AEvent: TTlsEventKind);
    procedure OnAlpnSelected(const AProtocol: string);
    procedure OnOcspStapleReceived(const AStaple: TBytes);
    procedure OnHandshakeEstablished;
    procedure OnHandshakeFailed(AAlert: TTlsAlertDescription);
  end;

  TTestTls13ClientReplay = class(TTlsLibAlgorithmTestCase)
  private
    FHs, FSched, FRec: TStringList;
    FLayer: TRecordLayer;
    FDriver: THandshakeDriver;
    FSm: IHandshakeMachine;
    function Msg(const AName: string): TTlsHandshakeMessage;
    function FindSendHandshake(const AEffects: TArray<THandshakeEffect>): TBytes;
    /// <summary>The alert of the first Fail effect in AEffects, or False if none.</summary>
    function FailAlertOf(const AEffects: TArray<THandshakeEffect>;
      out AAlert: TTlsAlertDescription): Boolean;
    function Filled(AByte: Byte; ACount: Int32): TBytes;
    procedure StartClient;
    procedure ArrangeThroughCertificate;
    procedure ArrangeThroughCertificateVerify;
    /// <summary>Synthesizes a framed ServerHello with the given fields (for hostile-input tests).</summary>
    function BuildServerHello(const ARandom, ASessionIdEcho: TBytes;
      ASuite, ASelectedVersion, AGroup: UInt16;
      const AKeyExchange: TBytes): TTlsHandshakeMessage;
    /// <summary>Feeds AMessage to a freshly-started client and returns the fatal alert, or False.</summary>
    function ServerHelloAlert(const AMessage: TTlsHandshakeMessage;
      out AAlert: TTlsAlertDescription): Boolean;
    /// <summary>A minimal well-formed NewSessionTicket message (RFC 8446 4.6.1).</summary>
    function BuildNewSessionTicket: TTlsHandshakeMessage;
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestRfc8448ClientReplayByteExact;
    procedure TestBadCertificateVerifyFailsClosed;
    procedure TestBadServerFinishedFailsClosed;
    procedure TestServerHelloUnofferedSuiteRejected;
    procedure TestServerHelloBadSessionIdEchoRejected;
    procedure TestServerHelloWrongVersionRejected;
    procedure TestServerHelloUnofferedGroupRejected;
    procedure TestServerHelloDowngradeSentinelRejected;
    procedure TestPostHandshakeNewSessionTicketTolerated;
  end;

implementation

{ TAcceptAllVerifier }

function TAcceptAllVerifier.Verify(const AChain: TArray<TBytes>;
  const AHostName: string; const AOcspStaple: TBytes;
  out AAlert: TTlsAlertDescription): Boolean;
begin
  AAlert := TTlsAlertDescription.BadCertificate;
  Result := True;
end;

{ TReplayGroup }

constructor TReplayGroup.Create(const AShared: TBytes);
begin
  inherited Create;
  FShared := AShared;
end;

function TReplayGroup.Code: UInt16;
begin
  Result := TNamedGroupCatalog.X25519;
end;

function TReplayGroup.Name: string;
begin
  Result := 'X25519';
end;

function TReplayGroup.Kind: TNamedGroupKind;
begin
  Result := TNamedGroupKind.Ecdhe;
end;

procedure TReplayGroup.GenerateKeyPair(out APriv: ISecretBuffer;
  out APubShare: TBytes);
begin
  APriv := TSecretBuffer.Allocate(32);
  APubShare := nil;
  SetLength(APubShare, 32);
end;

procedure TReplayGroup.Encapsulate(const APeerPub: TBytes; out ACiphertext: TBytes;
  out ASharedSecret: ISecretBuffer);
begin
  ACiphertext := nil;
  ASharedSecret := TSecretBuffer.From(FShared);
end;

procedure TReplayGroup.Decapsulate(const APriv: ISecretBuffer;
  const ACiphertext: TBytes; out ASharedSecret: ISecretBuffer);
begin
  ASharedSecret := TSecretBuffer.From(FShared);
end;

function TReplayGroup.ValidatePeerShare(const AShare: TBytes): Boolean;
begin
  Result := True;
end;

{ TRecordLayerInstaller }

constructor TRecordLayerInstaller.Create(const ALayer: TRecordLayer);
begin
  inherited Create;
  FLayer := ALayer;
end;

procedure TRecordLayerInstaller.InstallReadProtection(
  const AProtection: IRecordProtection);
begin
  FLayer.SetReadProtection(AProtection);
end;

procedure TRecordLayerInstaller.InstallWriteProtection(
  const AProtection: IRecordProtection);
begin
  FLayer.SetWriteProtection(AProtection);
end;

procedure TRecordLayerInstaller.RevertWriteToPlaintext;
begin
  FLayer.RevertWriteToPlaintext;
end;

procedure TRecordLayerInstaller.SetEarlyReadEpoch(AActive: Boolean);
begin
  FLayer.SetEarlyReadAccepted(AActive);
end;

procedure TRecordLayerInstaller.SetRecordSizeLimit(AOutboundPlaintext,
  AInboundPlaintext: Int32);
begin
  FLayer.SetRecordSizeLimit(AOutboundPlaintext, AInboundPlaintext);
end;

procedure TRecordLayerInstaller.SetEarlyDataSkip(AMaxBytes: Int32);
begin
  FLayer.SetEarlyDataSkip(AMaxBytes);
end;

procedure TRecordLayerInstaller.SetEarlyDataLimit(AMaxBytes: Int32);
begin
  // outbound 0-RTT capping is an engine concern; this record-layer seam ignores it
end;

{ TSilentSink }

procedure TSilentSink.OnHandshakeEvent(AEvent: TTlsEventKind);
begin
end;

procedure TSilentSink.OnOcspStapleReceived(const AStaple: TBytes);
begin
end;

procedure TSilentSink.OnAlpnSelected(const AProtocol: string);
begin
end;

procedure TSilentSink.OnHandshakeEstablished;
begin
end;

procedure TSilentSink.OnHandshakeFailed(AAlert: TTlsAlertDescription);
begin
end;

{ TTestTls13ClientReplay }

procedure TTestTls13ClientReplay.SetUp;
begin
  inherited SetUp;
  FHs := LoadVectorFields('Rfc8448/HandshakeMessages.txt');
  FSched := LoadVectorFields('Rfc8448/Tls13KeySchedule.txt');
  FRec := LoadVectorFields('Rfc8448/Tls13RecordFinished.txt');
  FLayer := TRecordLayer.Create;
end;

procedure TTestTls13ClientReplay.TearDown;
begin
  FDriver.Free;
  FLayer.Free;
  FHs.Free;
  FSched.Free;
  FRec.Free;
  inherited TearDown;
end;

function TTestTls13ClientReplay.Msg(const AName: string): TTlsHandshakeMessage;
var
  LReader: THandshakeMessageReader;
  LWhole: TBytes;
begin
  LWhole := DecodeHex(FHs.Values[AName]);
  LReader := THandshakeMessageReader.Create;
  try
    LReader.Append(LWhole, 0, System.Length(LWhole));
    LReader.NextMessage(Result);
  finally
    LReader.Free;
  end;
end;

function TTestTls13ClientReplay.FindSendHandshake(
  const AEffects: TArray<THandshakeEffect>): TBytes;
var
  LEffect: THandshakeEffect;
begin
  Result := nil;
  for LEffect in AEffects do
    if LEffect.Kind = THandshakeEffectKind.SendHandshake then
      Exit(LEffect.Bytes);
end;

function TTestTls13ClientReplay.FailAlertOf(
  const AEffects: TArray<THandshakeEffect>;
  out AAlert: TTlsAlertDescription): Boolean;
var
  LEffect: THandshakeEffect;
begin
  Result := False;
  AAlert := TTlsAlertDescription.CloseNotify;
  for LEffect in AEffects do
    if LEffect.Kind = THandshakeEffectKind.Fail then
    begin
      AAlert := LEffect.Alert;
      Exit(True);
    end;
end;

procedure TTestTls13ClientReplay.StartClient;
var
  LParams: TClientHandshakeParams;
begin
  LParams := Default(TClientHandshakeParams);
  LParams.Clock := TSystemClock.Create;
  LParams.Provider := Provider;
  LParams.Group := TReplayGroup.Create(DecodeHex(FSched.Values['shared_secret']));
  LParams.GroupCode := TNamedGroupCatalog.X25519;
  LParams.CipherSuites := TCipherSuiteRegistry.CreateDefault(Provider);
  LParams.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  LParams.OfferedSuites := TArray<UInt16>.Create(TCipherSuites13.Aes128GcmSha256);
  // the RFC 8448 server signs its CertificateVerify with rsa_pss_rsae_sha256, so the
  // client must have offered it for the verification to be accepted (the ClientHello
  // is overridden, so this does not affect the byte-exact replay)
  LParams.OfferedSchemes := TArray<UInt16>.Create(
    TSignatureSchemes.EcdsaSecp256r1Sha256, TSignatureSchemes.RsaPssRsaeSha256);
  // the RFC 8448 leaf is not part of any test trust store; this replay exercises
  // the message flow, not trust, so accept any chain
  LParams.CertificateVerifier := TAcceptAllVerifier.Create;
  LParams.ClientHelloOverride := DecodeHex(FHs.Values['client_hello']);
  FSm := TTls13ClientStateMachine.Create(LParams);

  FDriver := THandshakeDriver.Create(
    THandshakeChannel.Create(FLayer) as IHandshakeChannel,
    TRecordLayerInstaller.Create(FLayer) as IRecordEpochInstaller, Provider,
    TSilentSink.Create as IHandshakeSink);

  FDriver.ApplyAll(FSm.Start);
  FLayer.TakeOutgoing; // discard the plaintext ClientHello
end;

procedure TTestTls13ClientReplay.ArrangeThroughCertificate;
begin
  StartClient;
  FDriver.ApplyAll(FSm.ProcessMessage(Msg('server_hello')));
  // the middlebox change_cipher_spec goes out on the ServerHello, before the client's
  // encrypted flight (RFC 8446 D.4); discard it so the flight capture stays byte-exact
  FLayer.TakeOutgoing;
  FDriver.ApplyAll(FSm.ProcessMessage(Msg('encrypted_ext')));
  FDriver.ApplyAll(FSm.ProcessMessage(Msg('certificate')));
end;

function TTestTls13ClientReplay.BuildServerHello(const ARandom, ASessionIdEcho: TBytes;
  ASuite, ASelectedVersion, AGroup: UInt16;
  const AKeyExchange: TBytes): TTlsHandshakeMessage;
var
  LCodec: IExtensionBlockCodec;
  LContext: TExtensionContext;
  LHello: TTlsServerHello;
  LFramed: TBytes;
  LReader: THandshakeMessageReader;
begin
  LCodec := TExtensionBlockCodec.Create(TCoreExtensions.CreateDefaultRegistry)
    as IExtensionBlockCodec;
  LContext := TExtensionContext.Create;
  try
    // SelectedVersion = 0 omits supported_versions; a non-empty key exchange emits key_share
    LContext.SelectedVersion := ASelectedVersion;
    LContext.SelectedKeyShare.Group := AGroup;
    LContext.SelectedKeyShare.KeyExchange := AKeyExchange;
    LHello.Random := ARandom;
    LHello.LegacySessionIdEcho := ASessionIdEcho;
    LHello.CipherSuite := ASuite;
    LHello.Extensions := LCodec.ProduceBlock(LContext,
      TTlsExtensionContextKind.ServerHello);
  finally
    LContext.Free;
  end;
  LFramed := THandshakeFraming.Frame(TTlsHandshakeType.ServerHello,
    THandshakeMessages.EncodeServerHello(LHello));
  LReader := THandshakeMessageReader.Create;
  try
    LReader.Append(LFramed, 0, System.Length(LFramed));
    LReader.NextMessage(Result);
  finally
    LReader.Free;
  end;
end;

function TTestTls13ClientReplay.ServerHelloAlert(const AMessage: TTlsHandshakeMessage;
  out AAlert: TTlsAlertDescription): Boolean;
begin
  StartClient;
  // an in-band failure now surfaces as a Fail effect, not a raised exception
  Result := FailAlertOf(FSm.ProcessMessage(AMessage), AAlert);
end;

procedure TTestTls13ClientReplay.ArrangeThroughCertificateVerify;
begin
  ArrangeThroughCertificate;
  // the client verifies the genuine RFC 8448 server CertificateVerify here
  FDriver.ApplyAll(FSm.ProcessMessage(Msg('cert_verify')));
end;

procedure TTestTls13ClientReplay.TestBadCertificateVerifyFailsClosed;
var
  LTampered: TBytes;
  LMessage: TTlsHandshakeMessage;
  LReader: THandshakeMessageReader;
  LAlert: TTlsAlertDescription;
begin
  ArrangeThroughCertificate;

  // flip a byte of the CertificateVerify signature
  LTampered := DecodeHex(FHs.Values['cert_verify']);
  LTampered[System.Length(LTampered) - 1] :=
    Byte(LTampered[System.Length(LTampered) - 1] xor $01);
  LReader := THandshakeMessageReader.Create;
  try
    LReader.Append(LTampered, 0, System.Length(LTampered));
    LReader.NextMessage(LMessage);
  finally
    LReader.Free;
  end;

  CheckTrue(FailAlertOf(FSm.ProcessMessage(LMessage), LAlert),
    'a bad CertificateVerify aborts');
  CheckTrue(LAlert = TTlsAlertDescription.DecryptError,
    'a bad CertificateVerify is decrypt_error');
end;

procedure TTestTls13ClientReplay.TestRfc8448ClientReplayByteExact;
var
  LEffects: TArray<THandshakeEffect>;
  LExpectedFinished: TBytes;
begin
  ArrangeThroughCertificateVerify;

  // the server Finished verifies (no exception) and the client emits its Finished
  LEffects := FSm.ProcessMessage(Msg('server_finished'));
  LExpectedFinished := ConcatBytes(DecodeHex('14000020'),
    DecodeHex(FSched.Values['client_verify_data']));
  CheckEqualBytes('client Finished verify_data matches RFC 8448',
    LExpectedFinished, FindSendHandshake(LEffects));

  FDriver.ApplyAll(LEffects);
  // the emitted encrypted client Finished record is byte-exact vs RFC 8448
  CheckEqualBytes('the client emits the RFC 8448 client Finished record byte-exact',
    DecodeHex(FRec.Values['record']), FLayer.TakeOutgoing);
end;

procedure TTestTls13ClientReplay.TestBadServerFinishedFailsClosed;
var
  LTampered: TBytes;
  LMessage: TTlsHandshakeMessage;
  LReader: THandshakeMessageReader;
  LAlert: TTlsAlertDescription;
begin
  ArrangeThroughCertificateVerify;

  // flip a byte of the server Finished verify_data
  LTampered := DecodeHex(FHs.Values['server_finished']);
  LTampered[System.Length(LTampered) - 1] :=
    Byte(LTampered[System.Length(LTampered) - 1] xor $01);
  LReader := THandshakeMessageReader.Create;
  try
    LReader.Append(LTampered, 0, System.Length(LTampered));
    LReader.NextMessage(LMessage);
  finally
    LReader.Free;
  end;

  CheckTrue(FailAlertOf(FSm.ProcessMessage(LMessage), LAlert),
    'a bad server Finished aborts');
  CheckTrue(LAlert = TTlsAlertDescription.DecryptError,
    'a bad server Finished is decrypt_error');
end;

function TTestTls13ClientReplay.Filled(AByte: Byte; ACount: Int32): TBytes;
begin
  Result := nil;
  SetLength(Result, ACount);
  if ACount > 0 then
    FillChar(Result[0], ACount, AByte);
end;

procedure TTestTls13ClientReplay.TestServerHelloUnofferedSuiteRejected;
var
  LAlert: TTlsAlertDescription;
begin
  // the server steers to a registered but not-offered suite (the client offered AES-128-GCM only)
  CheckTrue(ServerHelloAlert(BuildServerHello(Filled($01, 32), nil,
    TCipherSuites13.ChaCha20Poly1305Sha256, TlsWireVersionTls13,
    TNamedGroupCatalog.X25519, Filled($02, 32)), LAlert),
    'an unoffered cipher suite aborts the handshake');
  CheckTrue(LAlert = TTlsAlertDescription.IllegalParameter,
    'an unoffered cipher suite is illegal_parameter');
end;

procedure TTestTls13ClientReplay.TestServerHelloBadSessionIdEchoRejected;
var
  LAlert: TTlsAlertDescription;
begin
  // the client offered an empty legacy_session_id; the echo must match it
  CheckTrue(ServerHelloAlert(BuildServerHello(Filled($01, 32), Filled($AA, 32),
    TCipherSuites13.Aes128GcmSha256, TlsWireVersionTls13,
    TNamedGroupCatalog.X25519, Filled($02, 32)), LAlert),
    'a mismatched legacy_session_id_echo aborts the handshake');
  CheckTrue(LAlert = TTlsAlertDescription.IllegalParameter,
    'a mismatched session id echo is illegal_parameter');
end;

procedure TTestTls13ClientReplay.TestServerHelloWrongVersionRejected;
var
  LAlert: TTlsAlertDescription;
begin
  // supported_versions selects 1.2, not 1.3 (no downgrade sentinel present)
  CheckTrue(ServerHelloAlert(BuildServerHello(Filled($01, 32), nil,
    TCipherSuites13.Aes128GcmSha256, TlsWireVersionTls12,
    TNamedGroupCatalog.X25519, Filled($02, 32)), LAlert),
    'a non-1.3 selected version aborts the handshake');
  CheckTrue(LAlert = TTlsAlertDescription.ProtocolVersion,
    'a non-1.3 selected version is protocol_version');
end;

procedure TTestTls13ClientReplay.TestServerHelloUnofferedGroupRejected;
var
  LAlert: TTlsAlertDescription;
begin
  // the selected key_share group differs from the one offered (X25519)
  CheckTrue(ServerHelloAlert(BuildServerHello(Filled($01, 32), nil,
    TCipherSuites13.Aes128GcmSha256, TlsWireVersionTls13,
    TNamedGroupCatalog.Secp256r1, Filled($02, 32)), LAlert),
    'an unoffered key_share group aborts the handshake');
  CheckTrue(LAlert = TTlsAlertDescription.IllegalParameter,
    'an unoffered key_share group is illegal_parameter');
end;

procedure TTestTls13ClientReplay.TestServerHelloDowngradeSentinelRejected;
var
  LAlert: TTlsAlertDescription;
  LRandom: TBytes;
begin
  // a genuine-1.3 server steered to 1.2 stamps the sentinel in the last 8 random bytes;
  // supported_versions is omitted so the effective negotiated version is 1.2
  LRandom := Filled($01, 32);
  Move(Tls12DowngradeSentinel[0], LRandom[24], 8);
  CheckTrue(ServerHelloAlert(BuildServerHello(LRandom, nil,
    TCipherSuites13.Aes128GcmSha256, 0, TNamedGroupCatalog.X25519,
    Filled($02, 32)), LAlert), 'a downgrade sentinel aborts the handshake');
  CheckTrue(LAlert = TTlsAlertDescription.IllegalParameter,
    'a downgrade sentinel is illegal_parameter');
end;

function TTestTls13ClientReplay.BuildNewSessionTicket: TTlsHandshakeMessage;
var
  LBody, LFramed: TBytes;
  LReader: THandshakeMessageReader;
begin
  // ticket_lifetime(4) + ticket_age_add(4) + ticket_nonce<0..255> +
  // ticket<1..2^16-1> + extensions<0..2^16-2>
  LBody := DecodeHex('00001c20' + '00000000' + '00' + '0008' +
    '0102030405060708' + '0000');
  LFramed := THandshakeFraming.Frame(TTlsHandshakeType.NewSessionTicket, LBody);
  LReader := THandshakeMessageReader.Create;
  try
    LReader.Append(LFramed, 0, System.Length(LFramed));
    LReader.NextMessage(Result);
  finally
    LReader.Free;
  end;
end;

procedure TTestTls13ClientReplay.TestPostHandshakeNewSessionTicketTolerated;
var
  LAlert: TTlsAlertDescription;
begin
  ArrangeThroughCertificateVerify;
  // the server Finished completes the handshake; the client is now Connected
  FDriver.ApplyAll(FSm.ProcessMessage(Msg('server_finished')));

  // a post-handshake NewSessionTicket must be dropped, not aborted (interop with any
  // real 1.3 server, which sends tickets by default)
  CheckFalse(FailAlertOf(FSm.ProcessMessage(BuildNewSessionTicket), LAlert),
    'a post-handshake NewSessionTicket does not abort the connection');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestTls13ClientReplay);
{$ELSE}
  RegisterTest(TTestTls13ClientReplay.Suite);
{$ENDIF FPC}

end.
