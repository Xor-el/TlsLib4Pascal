{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit Tls13ServerReplayTests;

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
  TlpICryptoProvider,
  TlpINamedGroup,
  TlpNegotiationTypes,
  TlpNegotiationPolicy,
  TlpCipherSuiteRegistry,
  TlpCoreExtensions,
  TlpExtensionContext,
  TlpITlsExtension,
  TlpExtensionBlockCodec,
  TlpRecordLayer,
  TlpHandshakeMessage,
  TlpHandshakeMessages,
  TlpIHandshakeChannel,
  TlpHandshakeChannel,
  TlpIHandshakeMachine,
  TlpHandshakeEffect,
  TlpHandshakeDriver,
  TlpTls13ServerStateMachine,
  TlpTlsCredential,
  TlpCredentialResolvers,
  MockCryptoProvider,
  MockNamedGroups,
  MockSink,
  MockRecordInstaller,
  TlsLibHandshakeTestBase;

type
  TTestTls13ServerReplay = class(TTlsLibHandshakeTestCase)
  private
    FHs, FSched, FKeys: TStringList;
    FLayer: TRecordLayer;
    FDriver: THandshakeDriver;
    FSm: IHandshakeMachine;
    function Msg(const AName: string): TTlsHandshakeMessage;
    /// <summary>Rebuilds FDriver over ACryptoProvider, releasing any driver from a prior
    /// arrange first so a re-arranged test never leaks the previous graph.</summary>
    procedure BuildDriver(const ACryptoProvider: ICryptoProvider);
    /// <summary>Arranges a server whose RSA credential can sign any rsa_pss_rsae_*
    /// variant (schemes listed [sha384, sha256, sha512]); it really signs, no override.</summary>
    procedure ArrangeMultiSchemeRsa;
    procedure Arrange;
    /// <summary>Synthesizes a framed ClientHello offering AGroup and AKeyShare; when
    /// AIncludeSchemes is set it carries signature_algorithms = ASchemes.</summary>
    function BuildClientHello(AIncludeSchemes: Boolean;
      const ASchemes: TArray<UInt16>): TTlsHandshakeMessage;
    /// <summary>Feeds AMessage to a freshly-arranged server and returns the fatal alert, or False.</summary>
    function ClientHelloAlert(const AMessage: TTlsHandshakeMessage;
      out AAlert: TTlsAlertDescription): Boolean;
  protected
    procedure SetUp; override;
  published
    procedure TestRfc8448ServerFlightByteExact;
    procedure TestExporterAvailableInHalfRtt;
    procedure TestBadClientFinishedFailsClosed;
    procedure TestServerSigSchemeIncompatibleRejected;
    procedure TestServerSigSchemeMissingRejected;
    procedure TestNonPskWithoutSupportedGroupsRejected;
    procedure TestServerNegotiatesRsaPssSchemeFromCredentialSet;
  end;

implementation

{ TTestTls13ServerReplay }

procedure TTestTls13ServerReplay.SetUp;
begin
  inherited SetUp;
  FDriver := nil;
  FSm := nil;
  FHs := Own<TStringList>(LoadVectorFields('Rfc8448/HandshakeMessages.txt'));
  FSched := Own<TStringList>(LoadVectorFields('Rfc8448/Tls13KeySchedule.txt'));
  FKeys := Own<TStringList>(LoadVectorFields('Certs/SignatureKeys.txt'));
  // FDriver wraps FLayer, so Own both: the base disposes newest-first, freeing the driver
  // before the layer it references (a re-arrange never leaves a dangling driver either)
  FLayer := Own<TRecordLayer>(TRecordLayer.Create);
end;

function TTestTls13ServerReplay.Msg(const AName: string): TTlsHandshakeMessage;
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

procedure TTestTls13ServerReplay.BuildDriver(const ACryptoProvider: ICryptoProvider);
begin
  // a test may arrange more than once; Own accumulates, and the base disposes every driver at
  // TearDown. A superseded driver holds only non-owning refs to FLayer, so it is inert until then
  FDriver := Own<THandshakeDriver>(THandshakeDriver.Create(
    THandshakeChannel.Create(FLayer) as IHandshakeChannel,
    TRecordLayerInstaller.Create(FLayer) as IRecordEpochInstaller, ACryptoProvider,
    TMockHandshakeSink.Create as IHandshakeSink));
end;

procedure TTestTls13ServerReplay.Arrange;
var
  LParams: TServerHandshakeParams;
  LServerHello: TBytes;
  LServerShare: TBytes;
  LCred: TTlsCredential;
  LReplay: ITls13ServerReplay;
begin
  // the server's key_share pubshare and 32-byte random come straight from the RFC
  // ServerHello (the mock KEM returns this share and the recorded shared secret)
  LServerHello := DecodeHex(FHs.Values['server_hello']);
  // the 32-byte key_share sits just before the trailing supported_versions
  // extension (00 2b 00 02 03 04, six bytes)
  LServerShare := System.Copy(LServerHello, System.Length(LServerHello) - 38, 32);

  LParams := Default(TServerHandshakeParams);
  LParams.Clock := TSystemClock.Create;
  // a fixed HasHardwareAes=True makes the suite choice deterministically AES-128-GCM
  LParams.Crypto := TFixedAesProvider.Create(Crypto, True);
  LParams.Inspector := Pkix.Certificates;
  LParams.Policy := TNegotiationPolicy.CreateDefault(LParams.Crypto);
  LParams.CipherSuites := TCipherSuiteRegistry.CreateDefault(LParams.Crypto);
  LParams.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  LParams.Group := TFixedSecretGroup.Create(LServerShare,
    DecodeHex(FSched.Values['shared_secret'])) as INamedGroup;
  // the ServerHello random sits after type(1) length(3) legacy_version(2)
  LParams.ServerRandom := System.Copy(LServerHello, 6, 32);
  // the RFC 8448 server signs with rsa_pss_rsae_sha256, which the RFC client offers;
  // the Certificate and CertificateVerify are replayed verbatim, so the credential only drives
  // scheme selection
  LCred := Default(TTlsCredential);
  LCred.CertificateChain := TArray<TBytes>.Create(DecodeHex(FKeys.Values['rsa_cert']));
  LCred.PrivateKey := Crypto.Signing.ImportSigningKey(DecodeHex(FKeys.Values['rsa_key']), nil);
  LParams.CredentialResolver := TSniCredentialResolver.ForCredential(LCred);
  FSm := TTls13ServerStateMachine.Create(LParams);
  // inject the RFC 8448 EncryptedExtensions + Certificate + CertificateVerify verbatim
  // for byte-exact replay
  LReplay := FSm as ITls13ServerReplay;
  LReplay.SetVerbatimEncryptedExtensions(DecodeHex(FHs.Values['encrypted_ext']));
  LReplay.SetVerbatimCertificate(DecodeHex(FHs.Values['certificate']));
  LReplay.SetVerbatimCertificateVerify(DecodeHex(FHs.Values['cert_verify']));
  BuildDriver(LParams.Crypto);
  FSm.Start;
end;

procedure TTestTls13ServerReplay.TestRfc8448ServerFlightByteExact;
var
  LEffects: TArray<THandshakeEffect>;
  LFlight: TArray<TBytes>;
  LEffect: THandshakeEffect;
  LAlert: TTlsAlertDescription;
  LEstablished: Boolean;
begin
  Arrange;

  // the ClientHello drives the whole server flight
  LEffects := FSm.ProcessMessage(Msg('client_hello'));
  LFlight := AllSendHandshake(LEffects);
  CheckEquals(5, System.Length(LFlight),
    'the server sends ServerHello, EncryptedExtensions, Certificate, CertificateVerify, Finished');
  // the reconstructed ServerHello is byte-exact (so its transcript matches the RFC)
  CheckEqualBytes('ServerHello byte-exact vs RFC 8448',
    DecodeHex(FHs.Values['server_hello']), LFlight[0]);
  // and the server Finished verify_data derived from that transcript is byte-exact
  CheckEqualBytes('server Finished byte-exact vs RFC 8448',
    DecodeHex(FHs.Values['server_finished']), LFlight[4]);

  // applying the flight installs the handshake/application keys without error
  FDriver.ApplyAll(LEffects);

  // the RFC client Finished verifies against the server-side transcript, and the
  // handshake is established
  LEffects := FSm.ProcessMessage(Msg('client_finished'));
  CheckFalse(FailAlertOf(LEffects, LAlert), 'the genuine client Finished is not refused');
  LEstablished := False;
  for LEffect in LEffects do
    if LEffect.Kind = THandshakeEffectKind.HandshakeEstablished then
      LEstablished := True;
  CheckTrue(LEstablished, 'accepting the client Finished establishes the handshake');
  FDriver.ApplyAll(LEffects);
end;

procedure TTestTls13ServerReplay.TestExporterAvailableInHalfRtt;
var
  LExport: TBytes;
begin
  Arrange;
  CheckFalse(FSm.CanExportKeyingMaterial,
    'no exporter before the server derives its secrets');
  // the ClientHello drives the server flight, which derives the exporter secret; the server is
  // now in half-RTT (its Finished sent, the client Finished not yet processed)
  FSm.ProcessMessage(Msg('client_hello'));
  CheckTrue(FSm.CanExportKeyingMaterial, 'the exporter is available in half-RTT');
  LExport := FSm.ExportKeyingMaterial('EXPORTER-test', DecodeHex('00010203'), 32);
  CheckEquals(32, System.Length(LExport),
    'the machine exports keying material in half-RTT');
  FSm.ProcessMessage(Msg('client_finished'));
  CheckTrue(FSm.CanExportKeyingMaterial, 'the exporter stays available after completion');
end;

procedure TTestTls13ServerReplay.TestBadClientFinishedFailsClosed;
var
  LTampered: TBytes;
  LMessage: TTlsHandshakeMessage;
  LReader: THandshakeMessageReader;
  LAlert: TTlsAlertDescription;
begin
  Arrange;
  FSm.ProcessMessage(Msg('client_hello'));

  // flip a byte of the client Finished verify_data
  LTampered := DecodeHex(FHs.Values['client_finished']);
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
    'a bad client Finished aborts');
  CheckTrue(LAlert = TTlsAlertDescription.DecryptError,
    'a bad client Finished is decrypt_error');
end;

function TTestTls13ServerReplay.BuildClientHello(AIncludeSchemes: Boolean;
  const ASchemes: TArray<UInt16>): TTlsHandshakeMessage;
var
  LCodec: IExtensionBlockCodec;
  LContext: TExtensionContext;
  LHello: TTlsClientHello;
  LKeyShare: TBytes;
  LFramed: TBytes;
  LReader: THandshakeMessageReader;
begin
  LKeyShare := nil;
  SetLength(LKeyShare, 32); // X25519 share bytes (the mock KEM ignores their value)
  LCodec := TExtensionBlockCodec.Create(TCoreExtensions.CreateDefaultRegistry)
    as IExtensionBlockCodec;
  LContext := TExtensionContext.Create;
  try
    LContext.SupportedVersions := TArray<UInt16>.Create(TlsWireVersionTls13);
    LContext.SupportedGroups := TArray<UInt16>.Create(TNamedGroupCatalog.X25519);
    SetLength(LContext.ClientKeyShares, 1);
    LContext.ClientKeyShares[0].Group := TNamedGroupCatalog.X25519;
    LContext.ClientKeyShares[0].KeyExchange := LKeyShare;
    if AIncludeSchemes then
      LContext.SignatureSchemes := ASchemes;
    LHello.Random := nil;
    SetLength(LHello.Random, 32);
    LHello.LegacySessionId := nil;
    LHello.CipherSuites := TArray<UInt16>.Create(TCipherSuites13.Aes128GcmSha256);
    LHello.Extensions := LCodec.ProduceBlock(LContext,
      TTlsExtensionContextKind.ClientHello);
  finally
    LContext.Free;
  end;
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

function TTestTls13ServerReplay.ClientHelloAlert(const AMessage: TTlsHandshakeMessage;
  out AAlert: TTlsAlertDescription): Boolean;
begin
  Arrange;
  // an in-band failure now surfaces as a Fail effect, not a raised exception
  Result := FailAlertOf(FSm.ProcessMessage(AMessage), AAlert);
end;

procedure TTestTls13ServerReplay.TestServerSigSchemeIncompatibleRejected;
var
  LAlert: TTlsAlertDescription;
begin
  // the client offers only ECDSA; the RFC credential can only produce rsa_pss_rsae_sha256
  CheckTrue(ClientHelloAlert(BuildClientHello(True,
    TArray<UInt16>.Create(TSignatureSchemes.EcdsaSecp256r1Sha256)), LAlert),
    'an incompatible signature_algorithms aborts the handshake');
  CheckTrue(LAlert = TTlsAlertDescription.HandshakeFailure,
    'an incompatible signature_algorithms is handshake_failure, not an opaque client error');
end;

procedure TTestTls13ServerReplay.TestServerSigSchemeMissingRejected;
var
  LAlert: TTlsAlertDescription;
begin
  // a ClientHello without signature_algorithms cannot drive certificate-based auth
  CheckTrue(ClientHelloAlert(BuildClientHello(False, nil), LAlert),
    'a missing signature_algorithms aborts the handshake');
  CheckTrue(LAlert = TTlsAlertDescription.MissingExtension,
    'a missing signature_algorithms is missing_extension');
end;

procedure TTestTls13ServerReplay.TestNonPskWithoutSupportedGroupsRejected;
var
  LCodec: IExtensionBlockCodec;
  LContext: TExtensionContext;
  LHello: TTlsClientHello;
  LFramed: TBytes;
  LReader: THandshakeMessageReader;
  LMessage: TTlsHandshakeMessage;
  LAlert: TTlsAlertDescription;
begin
  // a non-PSK ClientHello that omits both supported_groups and key_share: the present/absent XOR
  // passes (both absent), so without the RFC 9846 9.2 guard it would fail later at group selection
  // with handshake_failure instead of missing_extension. signature_algorithms is present so the
  // only defect is the missing supported_groups.
  LCodec := TExtensionBlockCodec.Create(TCoreExtensions.CreateDefaultRegistry)
    as IExtensionBlockCodec;
  LContext := TExtensionContext.Create;
  try
    LContext.SupportedVersions := TArray<UInt16>.Create(TlsWireVersionTls13);
    LContext.SignatureSchemes :=
      TArray<UInt16>.Create(TSignatureSchemes.RsaPssRsaeSha256);
    LHello.Random := nil;
    SetLength(LHello.Random, 32);
    LHello.LegacySessionId := nil;
    LHello.CipherSuites := TArray<UInt16>.Create(TCipherSuites13.Aes128GcmSha256);
    LHello.Extensions := LCodec.ProduceBlock(LContext,
      TTlsExtensionContextKind.ClientHello);
  finally
    LContext.Free;
  end;
  LFramed := THandshakeFraming.Frame(TTlsHandshakeType.ClientHello,
    THandshakeMessages.EncodeClientHello(LHello));
  LReader := THandshakeMessageReader.Create;
  try
    LReader.Append(LFramed, 0, System.Length(LFramed));
    LReader.NextMessage(LMessage);
  finally
    LReader.Free;
  end;

  CheckTrue(ClientHelloAlert(LMessage, LAlert),
    'a non-PSK ClientHello without supported_groups aborts the handshake');
  CheckTrue(LAlert = TTlsAlertDescription.MissingExtension,
    'a non-PSK ClientHello without supported_groups is missing_extension');
end;

procedure TTestTls13ServerReplay.ArrangeMultiSchemeRsa;
var
  LParams: TServerHandshakeParams;
  LFill: TBytes;
  LCred: TTlsCredential;
begin
  LFill := DecodeHex(StringOfChar('a', 64)); // 32 bytes; the mock KEM ignores its value
  LParams := Default(TServerHandshakeParams);
  LParams.Clock := TSystemClock.Create;
  LParams.Crypto := Crypto;
  LParams.Inspector := Pkix.Certificates;
  LParams.Policy := TNegotiationPolicy.CreateDefault(Crypto);
  LParams.CipherSuites := TCipherSuiteRegistry.CreateDefault(Crypto);
  LParams.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  LParams.Group := TFixedSecretGroup.Create(LFill, LFill) as INamedGroup;
  LParams.ServerRandom := LFill;
  // one RSA key; its capable schemes are the three rsa_pss_rsae_* variants, and the
  // machine signs for real (no verbatim CertificateVerify is set)
  LCred := Default(TTlsCredential);
  LCred.CertificateChain := TArray<TBytes>.Create(DecodeHex(FKeys.Values['rsa_cert']));
  LCred.PrivateKey := Crypto.Signing.ImportSigningKey(DecodeHex(FKeys.Values['rsa_key']), nil);
  LParams.CredentialResolver := TSniCredentialResolver.ForCredential(LCred);
  FSm := TTls13ServerStateMachine.Create(LParams);
  BuildDriver(Crypto);
  FSm.Start;
end;

procedure TTestTls13ServerReplay.TestServerNegotiatesRsaPssSchemeFromCredentialSet;
var
  LEffects: TArray<THandshakeEffect>;
  LAlert: TTlsAlertDescription;

  // the algorithm the server stamped on its emitted CertificateVerify for a client
  // offering exactly ASchemes
  function SignedScheme(const ASchemes: TArray<UInt16>): UInt16;
  var
    LFlight: TArray<TBytes>;
    LCv: TBytes;
  begin
    ArrangeMultiSchemeRsa;
    LFlight := AllSendHandshake(FSm.ProcessMessage(BuildClientHello(True, ASchemes)));
    CheckEquals(5, System.Length(LFlight), 'the server emits its full flight');
    LCv := LFlight[3]; // ServerHello, EncryptedExtensions, Certificate, CertificateVerify
    Result := THandshakeMessages.DecodeCertificateVerify(
      System.Copy(LCv, 4, System.Length(LCv) - 4)).Algorithm;
  end;

begin
  // one RSA key signs whichever rsa_pss_rsae_* variant the client actually offered
  CheckEquals(TSignatureSchemes.RsaPssRsaeSha384,
    SignedScheme(TArray<UInt16>.Create(TSignatureSchemes.RsaPssRsaeSha384)),
    'a client offering only rsa_pss_rsae_sha384 gets a sha384 CertificateVerify');
  CheckEquals(TSignatureSchemes.RsaPssRsaeSha512,
    SignedScheme(TArray<UInt16>.Create(TSignatureSchemes.RsaPssRsaeSha512)),
    'the same RSA key signs rsa_pss_rsae_sha512 when that is all the client offered');

  // nothing the RSA key can produce -> handshake_failure (not an opaque error)
  ArrangeMultiSchemeRsa;
  LEffects := FSm.ProcessMessage(BuildClientHello(True,
    TArray<UInt16>.Create(TSignatureSchemes.EcdsaSecp256r1Sha256)));
  CheckTrue(FailAlertOf(LEffects, LAlert),
    'an RSA credential rejects an ECDSA-only client');
  CheckTrue(LAlert = TTlsAlertDescription.HandshakeFailure,
    'no compatible signature scheme is handshake_failure');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestTls13ServerReplay);
{$ELSE}
  RegisterTest(TTestTls13ServerReplay.Suite);
{$ENDIF FPC}

end.
