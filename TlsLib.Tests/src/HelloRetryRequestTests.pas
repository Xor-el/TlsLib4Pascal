{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit HelloRetryRequestTests;

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
  TlpCryptoDomainTypes,
  TlpISecretBuffer,
  TlpIKeyExchangePrivateKey,
  TlpSecretBuffer,
  TlpNamedGroups,
  TlpNegotiationTypes,
  TlpNegotiationPolicy,
  TlpCipherSuiteRegistry,
  TlpCoreExtensions,
  TlpExtensionVector,
  TlpEchExtension,
  TlpExtensionContext,
  TlpITlsExtension,
  TlpExtensionBlockCodec,
  TlpHandshakeMessage,
  TlpHandshakeMessages,
  TlpHelloRetryCookie,
  TlpTlsCredential,
  TlpCredentialResolvers,
  TlpHandshakeEffect,
  TlpIHandshakeMachine,
  TlpTls13ClientStateMachine,
  TlpTls13ServerStateMachine,
  TlpIEch,
  TlpEchServer,
  MockCryptoProvider,
  TlsLibTestBase,
  TlsLibTestHandshakeDecoder;

type
  TTestHelloRetryRequest = class(TTlsLibAlgorithmTestCase)
  private
    FHrr: TStringList;
    function CookieSecret: ISecretBuffer;
    function Vec(const AName: string): TBytes;
    function SendHandshakeOf(const AEffects: TArray<THandshakeEffect>): TArray<TBytes>;
    function FailAlertOf(const AEffects: TArray<THandshakeEffect>;
      out AAlert: TTlsAlertDescription): Boolean;
    function BuildHrr(AGroup, ASuite: UInt16; const ACookie, ASessionId: TBytes;
      ASelectedVersion: UInt16 = TlsWireVersionTls13): TBytes;
    /// <summary>The retry ClientHello; AServerName defaults to the RFC 8448 first hello's name,
    /// and an empty one omits the extension.</summary>
    function BuildClientHello2(AGroup: UInt16; const AKeyShare, ACookie,
      ASessionId: TBytes; ASuite: UInt16 = 0; const AServerName: string = 'server'): TBytes;
    function CookieFromHrr(const AHrr: TBytes): TBytes;
    function NewSecp256r1Server(const AVerbatimCookie: TBytes): IHandshakeMachine; overload;
    function NewSecp256r1Server(const AVerbatimCookie: TBytes;
      const AEchPolicy: IEchServerPolicy): IHandshakeMachine; overload;
    /// <summary>AFramedClientHello with an ech extension carrying AEchBody appended.</summary>
    function WithEch(const AFramedClientHello, AEchBody: TBytes): TBytes;
    function WithInnerEch(const AFramedClientHello: TBytes): TBytes;
    function WithOuterEch(const AFramedClientHello: TBytes): TBytes;
    function NewRetryClient: IHandshakeMachine; overload;
    function NewRetryClient(ADualVersion: Boolean): IHandshakeMachine; overload;
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestServerEmitsRfc8448Section5HelloRetryRequestByteExact;
    procedure TestCookieMintVerifyRoundTrip;
    procedure TestCookieRejectsTamperedTag;
    procedure TestClientHandlesHelloRetryRequestEmitsSecondClientHello;
    procedure TestClientRejectsSecondHelloRetryRequest;
    procedure TestClientRejectsHelloRetryWithTls12Suite;
    procedure TestClientRejectsHelloRetryUnofferedGroup;
    procedure TestClientRejectsHelloRetryWithoutSupportedVersions;
    procedure TestClientRejectsHelloRetrySelectingTls12;
    procedure TestClientRejectsHelloRetryWithBadLegacyVersion;
    procedure TestServerRejectsSecondClientHelloWithoutCookie;
    procedure TestServerRejectsTamperedCookie;
    procedure TestServerRejectsCookieMintedForAnotherFirstClientHello;
    procedure TestServerRejectsUnexpectedMessageDuringRetryWait;
    procedure TestServerRejectsRetryClientHelloThatChangesSuite;
    procedure TestServerRejectsRetryClientHelloThatChangesSessionId;
    procedure TestServerRejectsRetryClientHelloThatChangesServerName;
    procedure TestServerRejectsInnerEchInRetryClientHello;
    procedure TestBackendServerAcceptsInnerEchInRetryClientHello;
    procedure TestBackendServerRejectsOuterEchInRetryClientHello;
  end;

implementation

{ TTestHelloRetryRequest }

procedure TTestHelloRetryRequest.SetUp;
begin
  inherited SetUp;
  FHrr := LoadVectorFields('Rfc8448/HelloRetryRequest.txt');
end;

procedure TTestHelloRetryRequest.TearDown;
begin
  FHrr.Free;
  inherited TearDown;
end;

function TTestHelloRetryRequest.CookieSecret: ISecretBuffer;
var
  LBytes: TBytes;
  LI: Int32;
begin
  LBytes := nil;
  SetLength(LBytes, 32);
  for LI := 0 to 31 do
    LBytes[LI] := Byte($A0 + LI);
  Result := TSecretBuffer.From(LBytes);
end;

function TTestHelloRetryRequest.Vec(const AName: string): TBytes;
begin
  Result := DecodeHex(FHrr.Values[AName]);
end;

function TTestHelloRetryRequest.SendHandshakeOf(
  const AEffects: TArray<THandshakeEffect>): TArray<TBytes>;
var
  LEffect: THandshakeEffect;
  LCount: Int32;
begin
  Result := nil;
  LCount := 0;
  for LEffect in AEffects do
    if LEffect.Kind = THandshakeEffectKind.SendHandshake then
    begin
      SetLength(Result, LCount + 1);
      Result[LCount] := LEffect.Bytes;
      Inc(LCount);
    end;
end;

function TTestHelloRetryRequest.FailAlertOf(
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

function TTestHelloRetryRequest.BuildHrr(AGroup, ASuite: UInt16;
  const ACookie, ASessionId: TBytes; ASelectedVersion: UInt16): TBytes;
var
  LCodec: IExtensionBlockCodec;
  LContext: TExtensionContext;
  LHello: TTlsServerHello;
begin
  LCodec := TExtensionBlockCodec.Create(TCoreExtensions.CreateDefaultRegistry);
  LContext := TExtensionContext.Create;
  try
    LContext.HelloRetryGroup := AGroup;
    LContext.Cookie := ACookie;
    // 0 omits supported_versions from the HelloRetryRequest (the codec produces nothing for 0)
    LContext.SelectedVersion := ASelectedVersion;
    LHello.Random := THelloRetryRequest.SentinelRandom;
    LHello.LegacySessionIdEcho := ASessionId;
    LHello.CipherSuite := ASuite;
    LHello.Extensions := LCodec.ProduceBlock(LContext,
      TTlsExtensionContextKind.HelloRetryRequest);
  finally
    LContext.Free;
  end;
  Result := THandshakeFraming.Frame(TTlsHandshakeType.ServerHello,
    THandshakeMessages.EncodeServerHello(LHello));
end;

function TTestHelloRetryRequest.BuildClientHello2(AGroup: UInt16;
  const AKeyShare, ACookie, ASessionId: TBytes; ASuite: UInt16;
  const AServerName: string): TBytes;
var
  LCodec: IExtensionBlockCodec;
  LContext: TExtensionContext;
  LHello: TTlsClientHello;
begin
  if ASuite = 0 then
    ASuite := TCipherSuites13.Aes128GcmSha256;
  LCodec := TExtensionBlockCodec.Create(TCoreExtensions.CreateDefaultRegistry);
  LContext := TExtensionContext.Create;
  try
    LContext.SupportedVersions := TArray<UInt16>.Create(TlsWireVersionTls13);
    LContext.SupportedGroups := TArray<UInt16>.Create(AGroup,
      TNamedGroupCatalog.X25519);
    LContext.SignatureSchemes := TArray<UInt16>.Create(
      TSignatureSchemes.EcdsaSecp256r1Sha256);
    LContext.Cookie := ACookie;
    LContext.ServerName := AServerName;
    SetLength(LContext.ClientKeyShares, 1);
    LContext.ClientKeyShares[0].Group := AGroup;
    LContext.ClientKeyShares[0].KeyExchange := AKeyShare;
    LHello.Random := nil;
    SetLength(LHello.Random, 32);
    LHello.LegacySessionId := ASessionId;
    LHello.CipherSuites := TArray<UInt16>.Create(ASuite);
    LHello.Extensions := LCodec.ProduceBlock(LContext,
      TTlsExtensionContextKind.ClientHello);
  finally
    LContext.Free;
  end;
  Result := THandshakeFraming.Frame(TTlsHandshakeType.ClientHello,
    THandshakeMessages.EncodeClientHello(LHello));
end;

function TTestHelloRetryRequest.CookieFromHrr(const AHrr: TBytes): TBytes;
var
  LMsg: TTlsHandshakeMessage;
  LHello: TTlsServerHello;
  LCodec: IExtensionBlockCodec;
  LContext: TExtensionContext;
begin
  LMsg := TTlsLibTestHandshakeDecoder.HandshakeMessage(AHrr);
  LHello := THandshakeMessages.DecodeServerHello(LMsg.Body);
  LCodec := TExtensionBlockCodec.Create(TCoreExtensions.CreateDefaultRegistry);
  LContext := TExtensionContext.Create;
  try
    LContext.MarkOffered(TExtensionTypes.KeyShare);
    LContext.MarkOffered(TExtensionTypes.Cookie);
    LContext.MarkOffered(TExtensionTypes.SupportedVersions);
    // an accepting ECH backend confirms in the HelloRetryRequest (RFC 9849 sec. 7.2.1)
    LContext.MarkOffered(TExtensionTypes.EncryptedClientHello);
    LCodec.ConsumeBlock(LContext, TTlsExtensionContextKind.HelloRetryRequest,
      LHello.Extensions);
    Result := System.Copy(LContext.Cookie);
  finally
    LContext.Free;
  end;
end;

function TTestHelloRetryRequest.NewSecp256r1Server(
  const AVerbatimCookie: TBytes): IHandshakeMachine;
begin
  Result := NewSecp256r1Server(AVerbatimCookie, nil);
end;

function TTestHelloRetryRequest.WithEch(const AFramedClientHello, AEchBody: TBytes): TBytes;
var
  LHello: TTlsClientHello;
  LExtensions: TExtensionVector;
begin
  LHello := THandshakeMessages.DecodeClientHello(
    System.Copy(AFramedClientHello, 4, System.Length(AFramedClientHello) - 4));
  LExtensions := TExtensionVector.Parse(LHello.Extensions);
  LExtensions.Append(TExtensionEntry.Create(TExtensionTypes.EncryptedClientHello, AEchBody));
  LHello.Extensions := LExtensions.Encode;
  Result := THandshakeFraming.Frame(TTlsHandshakeType.ClientHello,
    THandshakeMessages.EncodeClientHello(LHello));
end;

function TTestHelloRetryRequest.WithInnerEch(const AFramedClientHello: TBytes): TBytes;
begin
  Result := WithEch(AFramedClientHello, TEchExtension.EncodeInner);
end;

function TTestHelloRetryRequest.WithOuterEch(const AFramedClientHello: TBytes): TBytes;
var
  LOuter: TEchOuterClientHello;
begin
  LOuter := Default(TEchOuterClientHello);
  LOuter.CipherSuite.KdfId := THpkeKdf.HKDF_SHA256;
  LOuter.CipherSuite.AeadId := THpkeAead.AES_128_GCM;
  LOuter.ConfigId := $07;
  LOuter.Enc := DecodeHex(StringOfChar('1', 64));
  LOuter.Payload := DecodeHex(StringOfChar('2', 128));
  Result := WithEch(AFramedClientHello, TEchExtension.EncodeOuter(LOuter));
end;

function TTestHelloRetryRequest.NewSecp256r1Server(
  const AVerbatimCookie: TBytes; const AEchPolicy: IEchServerPolicy): IHandshakeMachine;
var
  LParams: TServerHandshakeParams;
  LCerts: TStringList;
  LCred: TTlsCredential;
begin
  LParams := Default(TServerHandshakeParams);
  LParams.Clock := TSystemClock.Create;
  // a fixed HasHardwareAes=True makes the suite choice deterministically AES-128-GCM
  LParams.Crypto := TFixedAesProvider.Create(Crypto, True);
  LParams.Inspector := Pkix.Certificates;
  LParams.Policy := TNegotiationPolicy.CreateDefault(LParams.Crypto);
  LParams.CipherSuites := TCipherSuiteRegistry.CreateDefault(LParams.Crypto);
  LParams.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  // the server offers only secp256r1, which the RFC 8448 Section 5 client listed but
  // did not key-share, so the server answers with a HelloRetryRequest
  LParams.Group := TNamedGroups.CreateNistEcdh(LParams.Crypto, 'secp256r1');
  LParams.ServerRandom := DecodeHex(StringOfChar('2', 64));
  LParams.CookieSecret := CookieSecret;
  LParams.EchPolicy := AEchPolicy;
  // a P-256 signing key; its lone capable scheme is ecdsa_secp256r1_sha256, which the
  // negotiation needs when it processes the first ClientHello (before the retry)
  LCerts := LoadVectorFields('Certs/EcP256Chain.txt');
  try
    LCred := Default(TTlsCredential);
    LCred.CertificateChain := TArray<TBytes>.Create(DecodeHex(LCerts.Values['leaf_cert']));
    LCred.PrivateKey := Crypto.Signing.ImportSigningKey(DecodeHex(LCerts.Values['leaf_key']), nil);
    LParams.CredentialResolver := TSniCredentialResolver.ForCredential(LCred);
  finally
    LCerts.Free;
  end;
  Result := TTls13ServerStateMachine.Create(LParams);
  // a preset cookie makes the emitted HelloRetryRequest byte-exact; empty mints one
  if System.Length(AVerbatimCookie) > 0 then
    (Result as ITls13ServerReplay).SetVerbatimRetryCookie(AVerbatimCookie);
  Result.Start;
end;

function TTestHelloRetryRequest.NewRetryClient: IHandshakeMachine;
begin
  Result := NewRetryClient(False);
end;

function TTestHelloRetryRequest.NewRetryClient(ADualVersion: Boolean): IHandshakeMachine;
var
  LParams: TClientHandshakeParams;
begin
  LParams := Default(TClientHandshakeParams);
  LParams.Clock := TSystemClock.Create;
  LParams.Crypto := Crypto;
  LParams.Inspector := Pkix.Certificates;
  LParams.Group := TNamedGroups.CreateX25519(Crypto);
  LParams.GroupCode := TNamedGroupCatalog.X25519;
  // advertises secp256r1 as well, so the server may retry us onto it
  LParams.OfferedGroups := TArray<UInt16>.Create(TNamedGroupCatalog.Secp256r1,
    TNamedGroupCatalog.X25519);
  LParams.GroupRegistry := TNamedGroups.CreateDefaultRegistry(Crypto);
  LParams.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  if ADualVersion then
  begin
    LParams.CipherSuites := TCipherSuiteRegistry.CreateDualVersion(Crypto);
    LParams.OfferedSuites := TArray<UInt16>.Create(TCipherSuites13.Aes128GcmSha256,
      TCipherSuites12.EcdheRsaAes128GcmSha256);
  end
  else
  begin
    LParams.CipherSuites := TCipherSuiteRegistry.CreateDefault(Crypto);
    LParams.OfferedSuites := TArray<UInt16>.Create(TCipherSuites13.Aes128GcmSha256);
  end;
  LParams.OfferedSchemes := TArray<UInt16>.Create(
    TSignatureSchemes.EcdsaSecp256r1Sha256);
  LParams.ClientRandom := DecodeHex(StringOfChar('1', 64));
  LParams.LegacySessionId := DecodeHex(StringOfChar('3', 64));
  Result := TTls13ClientStateMachine.Create(LParams);
  Result.Start;
end;

procedure TTestHelloRetryRequest.TestServerEmitsRfc8448Section5HelloRetryRequestByteExact;
var
  LServer: IHandshakeMachine;
  LFlight: TArray<TBytes>;
begin
  // feed the RFC 8448 Section 5 ClientHello1; injecting the RFC's cookie as an
  // override makes the emitted HelloRetryRequest byte-exact against the RFC
  LServer := NewSecp256r1Server(Vec('cookie'));
  LFlight := SendHandshakeOf(LServer.ProcessMessage(TTlsLibTestHandshakeDecoder.HandshakeMessage(Vec('client_hello_1'))));
  CheckEquals(1, System.Length(LFlight),
    'the server answers a share-less ClientHello with a single HelloRetryRequest');
  CheckEqualBytes('HelloRetryRequest byte-exact vs RFC 8448 Section 5',
    Vec('hello_retry_request'), LFlight[0]);
end;

procedure TTestHelloRetryRequest.TestCookieMintVerifyRoundTrip;
var
  LCookie: THelloRetryCookie;
  LMinted, LCh1Hash, LOutHash, LSid, LOutSid: TBytes;
  LSuite, LGroup: UInt16;
begin
  LCookie := THelloRetryCookie.Create(Crypto, CookieSecret);
  try
    LCh1Hash := DecodeHex(StringOfChar('5', 64)); // a 32-byte stand-in transcript hash
    LSid := DecodeHex(StringOfChar('a', 8)); // a 4-byte stand-in legacy_session_id
    LMinted := LCookie.Mint(LCh1Hash, TCipherSuites13.Aes128GcmSha256,
      TNamedGroupCatalog.Secp256r1, LSid);
    CheckTrue(LCookie.TryOpen(LMinted, LOutHash, LSuite, LGroup, LOutSid),
      'a minted cookie verifies');
    CheckEqualBytes('the bound transcript hash round-trips', LCh1Hash, LOutHash);
    CheckEquals(TCipherSuites13.Aes128GcmSha256, LSuite, 'the bound suite round-trips');
    CheckEquals(TNamedGroupCatalog.Secp256r1, LGroup, 'the bound group round-trips');
    CheckEqualBytes('the bound session id round-trips', LSid, LOutSid);
  finally
    LCookie.Free;
  end;
end;

procedure TTestHelloRetryRequest.TestCookieRejectsTamperedTag;
var
  LCookie: THelloRetryCookie;
  LMinted, LOutHash, LOutSid: TBytes;
  LSuite, LGroup: UInt16;
begin
  LCookie := THelloRetryCookie.Create(Crypto, CookieSecret);
  try
    LMinted := LCookie.Mint(DecodeHex(StringOfChar('5', 64)),
      TCipherSuites13.Aes128GcmSha256, TNamedGroupCatalog.Secp256r1,
      DecodeHex(StringOfChar('a', 8)));
    // flip the last MAC byte
    LMinted[System.Length(LMinted) - 1] :=
      Byte(LMinted[System.Length(LMinted) - 1] xor $01);
    CheckFalse(LCookie.TryOpen(LMinted, LOutHash, LSuite, LGroup, LOutSid),
      'a tampered cookie MAC does not verify');
  finally
    LCookie.Free;
  end;
end;

procedure TTestHelloRetryRequest.TestClientHandlesHelloRetryRequestEmitsSecondClientHello;
var
  LClient: IHandshakeMachine;
  LHrr, LCookie: TBytes;
  LCh2: TArray<TBytes>;
  LHello: TTlsClientHello;
  LCodec: IExtensionBlockCodec;
  LContext: TExtensionContext;
begin
  LClient := NewRetryClient;
  LCookie := DecodeHex('a1b2c3d4e5f6');
  LHrr := BuildHrr(TNamedGroupCatalog.Secp256r1, TCipherSuites13.Aes128GcmSha256,
    LCookie, DecodeHex(StringOfChar('3', 64)));
  LCh2 := SendHandshakeOf(LClient.ProcessMessage(TTlsLibTestHandshakeDecoder.HandshakeMessage(LHrr)));
  CheckEquals(1, System.Length(LCh2), 'the client resends a single ClientHello');

  // the second ClientHello key-shares the requested group and echoes the cookie
  LHello := THandshakeMessages.DecodeClientHello(TTlsLibTestHandshakeDecoder.HandshakeMessage(LCh2[0]).Body);
  LCodec := TExtensionBlockCodec.Create(TCoreExtensions.CreateDefaultRegistry)
    as IExtensionBlockCodec;
  LContext := TExtensionContext.Create;
  try
    LCodec.ConsumeBlock(LContext, TTlsExtensionContextKind.ClientHello,
      LHello.Extensions);
    CheckEquals(1, System.Length(LContext.ClientKeyShares), 'one key_share offered');
    CheckEquals(TNamedGroupCatalog.Secp256r1, LContext.ClientKeyShares[0].Group,
      'the key_share is for the requested group');
    CheckEqualBytes('the cookie is echoed verbatim', LCookie, LContext.Cookie);
  finally
    LContext.Free;
  end;
end;

procedure TTestHelloRetryRequest.TestClientRejectsSecondHelloRetryRequest;
var
  LClient: IHandshakeMachine;
  LHrr: TBytes;
  LAlert: TTlsAlertDescription;
begin
  LClient := NewRetryClient;
  LHrr := BuildHrr(TNamedGroupCatalog.Secp256r1, TCipherSuites13.Aes128GcmSha256,
    DecodeHex('a1b2c3'), DecodeHex(StringOfChar('3', 64)));
  // the first retry is accepted; a second HelloRetryRequest is fatal
  LClient.ProcessMessage(TTlsLibTestHandshakeDecoder.HandshakeMessage(LHrr));
  CheckTrue(FailAlertOf(LClient.ProcessMessage(TTlsLibTestHandshakeDecoder.HandshakeMessage(LHrr)), LAlert),
    'a second HelloRetryRequest aborts');
  CheckTrue(LAlert = TTlsAlertDescription.UnexpectedMessage,
    'a second HelloRetryRequest is unexpected_message');
end;

procedure TTestHelloRetryRequest.TestClientRejectsHelloRetryWithBadLegacyVersion;
var
  LClient: IHandshakeMachine;
  LHrr: TBytes;
  LAlert: TTlsAlertDescription;
begin
  LClient := NewRetryClient;
  // a well-formed HRR for an offered group, then its legacy_version (framed bytes 4..5) patched
  // from 0x0303 to a bogus value: the client rejects it like any ServerHello (RFC 8446 4.1.3)
  LHrr := BuildHrr(TNamedGroupCatalog.Secp256r1, TCipherSuites13.Aes128GcmSha256,
    DecodeHex('a1b2c3'), DecodeHex(StringOfChar('3', 64)));
  LHrr[4] := $03;
  LHrr[5] := $05;
  CheckTrue(FailAlertOf(LClient.ProcessMessage(TTlsLibTestHandshakeDecoder.HandshakeMessage(LHrr)), LAlert),
    'a HelloRetryRequest with a bad legacy_version aborts');
  CheckTrue(LAlert = TTlsAlertDescription.ProtocolVersion,
    'a bad HRR legacy_version is protocol_version');
end;

procedure TTestHelloRetryRequest.TestClientRejectsHelloRetryWithTls12Suite;
var
  LClient: IHandshakeMachine;
  LHrr: TBytes;
  LAlert: TTlsAlertDescription;
begin
  // a dual-version client offered the 1.2 suite, but a 1.3 HelloRetryRequest may not pin it
  LClient := NewRetryClient(True);
  LHrr := BuildHrr(TNamedGroupCatalog.Secp256r1, TCipherSuites12.EcdheRsaAes128GcmSha256,
    DecodeHex('a1b2c3'), DecodeHex(StringOfChar('3', 64)));
  CheckTrue(FailAlertOf(LClient.ProcessMessage(TTlsLibTestHandshakeDecoder.HandshakeMessage(LHrr)), LAlert),
    'a HelloRetryRequest selecting a TLS 1.2 suite aborts');
  CheckTrue(LAlert = TTlsAlertDescription.IllegalParameter,
    'a TLS 1.2 suite in a HelloRetryRequest is illegal_parameter');
end;

procedure TTestHelloRetryRequest.TestClientRejectsHelloRetryUnofferedGroup;
var
  LClient: IHandshakeMachine;
  LHrr: TBytes;
  LAlert: TTlsAlertDescription;
begin
  LClient := NewRetryClient;
  // secp384r1 was never advertised in supported_groups
  LHrr := BuildHrr(TNamedGroupCatalog.Secp384r1, TCipherSuites13.Aes128GcmSha256,
    DecodeHex('a1b2c3'), DecodeHex(StringOfChar('3', 64)));
  CheckTrue(FailAlertOf(LClient.ProcessMessage(TTlsLibTestHandshakeDecoder.HandshakeMessage(LHrr)), LAlert),
    'a HelloRetryRequest for an unoffered group aborts');
  CheckTrue(LAlert = TTlsAlertDescription.IllegalParameter,
    'an unoffered retry group is illegal_parameter');
end;

procedure TTestHelloRetryRequest.TestClientRejectsHelloRetryWithoutSupportedVersions;
var
  LClient: IHandshakeMachine;
  LHrr: TBytes;
  LAlert: TTlsAlertDescription;
begin
  LClient := NewRetryClient;
  // a HelloRetryRequest is a TLS 1.3 message: one lacking supported_versions did not select 1.3
  LHrr := BuildHrr(TNamedGroupCatalog.Secp256r1, TCipherSuites13.Aes128GcmSha256,
    DecodeHex('a1b2c3'), DecodeHex(StringOfChar('3', 64)), 0);
  CheckTrue(FailAlertOf(LClient.ProcessMessage(TTlsLibTestHandshakeDecoder.HandshakeMessage(LHrr)), LAlert),
    'a HelloRetryRequest without supported_versions aborts');
  CheckTrue(LAlert = TTlsAlertDescription.IllegalParameter,
    'a HelloRetryRequest that does not select TLS 1.3 is illegal_parameter');
end;

procedure TTestHelloRetryRequest.TestClientRejectsHelloRetrySelectingTls12;
var
  LClient: IHandshakeMachine;
  LHrr: TBytes;
  LAlert: TTlsAlertDescription;
begin
  LClient := NewRetryClient;
  LHrr := BuildHrr(TNamedGroupCatalog.Secp256r1, TCipherSuites13.Aes128GcmSha256,
    DecodeHex('a1b2c3'), DecodeHex(StringOfChar('3', 64)), TlsWireVersionTls12);
  CheckTrue(FailAlertOf(LClient.ProcessMessage(TTlsLibTestHandshakeDecoder.HandshakeMessage(LHrr)), LAlert),
    'a HelloRetryRequest selecting TLS 1.2 aborts');
  CheckTrue(LAlert = TTlsAlertDescription.IllegalParameter,
    'a HelloRetryRequest selecting a non-1.3 version is illegal_parameter');
end;

procedure TTestHelloRetryRequest.TestServerRejectsSecondClientHelloWithoutCookie;
var
  LServer: IHandshakeMachine;
  LCh2: TBytes;
  LAlert: TTlsAlertDescription;
begin
  // drive the server to expect a second ClientHello, then send one lacking the cookie
  LServer := NewSecp256r1Server(nil);
  LServer.ProcessMessage(TTlsLibTestHandshakeDecoder.HandshakeMessage(Vec('client_hello_1')));
  LCh2 := BuildClientHello2(TNamedGroupCatalog.Secp256r1, DecodeHex(StringOfChar('4', 130)),
    nil, DecodeHex(''));
  CheckTrue(FailAlertOf(LServer.ProcessMessage(TTlsLibTestHandshakeDecoder.HandshakeMessage(LCh2)), LAlert),
    'a second ClientHello without a cookie aborts');
  CheckTrue(LAlert = TTlsAlertDescription.MissingExtension,
    'a missing cookie is missing_extension');
end;

procedure TTestHelloRetryRequest.TestServerRejectsTamperedCookie;
var
  LServer: IHandshakeMachine;
  LHrr, LCookie, LCh2: TBytes;
  LAlert: TTlsAlertDescription;
begin
  LServer := NewSecp256r1Server(nil);
  LHrr := SendHandshakeOf(LServer.ProcessMessage(TTlsLibTestHandshakeDecoder.HandshakeMessage(Vec('client_hello_1'))))[0];
  // echo the minted cookie back, but with a flipped byte
  LCookie := CookieFromHrr(LHrr);
  LCookie[System.Length(LCookie) - 1] :=
    Byte(LCookie[System.Length(LCookie) - 1] xor $01);
  LCh2 := BuildClientHello2(TNamedGroupCatalog.Secp256r1,
    DecodeHex(StringOfChar('4', 130)), LCookie, DecodeHex(''));
  CheckTrue(FailAlertOf(LServer.ProcessMessage(TTlsLibTestHandshakeDecoder.HandshakeMessage(LCh2)), LAlert),
    'a tampered cookie aborts');
  CheckTrue(LAlert = TTlsAlertDescription.DecryptError,
    'a tampered cookie is decrypt_error');
end;

procedure TTestHelloRetryRequest.TestServerRejectsCookieMintedForAnotherFirstClientHello;
var
  LServerA, LServerB: IHandshakeMachine;
  LHrr, LCookie, LCh1B, LCh2, LShare: TBytes;
  LPriv: IKeyExchangePrivateKey;
  LAlert: TTlsAlertDescription;
begin
  // two connections share the cookie secret; B's first ClientHello differs from A's only in its
  // random. A's cookie is valid under the secret and matches B's suite, group and session id, but
  // it binds A's first hello, so B must refuse it
  TNamedGroups.CreateNistEcdh(Crypto, 'secp256r1').GenerateKeyPair(LPriv, LShare);
  LServerA := NewSecp256r1Server(nil);
  LHrr := SendHandshakeOf(LServerA.ProcessMessage(TTlsLibTestHandshakeDecoder.HandshakeMessage(Vec('client_hello_1'))))[0];
  LCookie := CookieFromHrr(LHrr);
  LCh2 := BuildClientHello2(TNamedGroupCatalog.Secp256r1, LShare, LCookie, DecodeHex(''),
    TCipherSuites13.Aes128GcmSha256);
  // control: the cookie on the connection that minted it proceeds to a ServerHello, so the refusal
  // below is the first-hello binding and not an earlier suite, group or session-id check
  CheckTrue(System.Length(SendHandshakeOf(LServerA.ProcessMessage(TTlsLibTestHandshakeDecoder.HandshakeMessage(LCh2)))) > 0,
    'the cookie is accepted on the connection that minted it');
  LCh1B := System.Copy(Vec('client_hello_1'));
  LCh1B[10] := Byte(LCh1B[10] xor $01); // inside ClientHello.random
  LServerB := NewSecp256r1Server(nil);
  LServerB.ProcessMessage(TTlsLibTestHandshakeDecoder.HandshakeMessage(LCh1B));
  CheckTrue(FailAlertOf(LServerB.ProcessMessage(TTlsLibTestHandshakeDecoder.HandshakeMessage(LCh2)), LAlert),
    'a cookie minted for another first ClientHello aborts');
  CheckTrue(LAlert = TTlsAlertDescription.IllegalParameter,
    'it is illegal_parameter');
end;

procedure TTestHelloRetryRequest.TestServerRejectsUnexpectedMessageDuringRetryWait;
var
  LServer: IHandshakeMachine;
  LAlert: TTlsAlertDescription;
begin
  // after emitting a HelloRetryRequest the server waits for the second ClientHello;
  // any other message (here a Finished) is unexpected (RFC 8446 centralized handling)
  LServer := NewSecp256r1Server(nil);
  LServer.ProcessMessage(TTlsLibTestHandshakeDecoder.HandshakeMessage(Vec('client_hello_1')));
  CheckTrue(FailAlertOf(LServer.ProcessMessage(
    TTlsLibTestHandshakeDecoder.HandshakeMessage(DecodeHex('140000200000000000000000000000000000000000000000000000000000000000000000'))),
    LAlert), 'a non-ClientHello during the retry wait aborts');
  CheckTrue(LAlert = TTlsAlertDescription.UnexpectedMessage,
    'it is unexpected_message');
end;

procedure TTestHelloRetryRequest.TestServerRejectsRetryClientHelloThatChangesSuite;
var
  LServer: IHandshakeMachine;
  LHrr, LCookie, LCh2, LShare: TBytes;
  LPriv: IKeyExchangePrivateKey;
  LAlert: TTlsAlertDescription;
begin
  // a valid P-256 share, so the retry reaches suite negotiation rather than aborting on the share:
  // a server without the pin would emit a ServerHello, which is what makes this test discriminate
  TNamedGroups.CreateNistEcdh(Crypto, 'secp256r1').GenerateKeyPair(LPriv, LShare);

  // the server selects AES-128-GCM from ClientHello1 and names it in the HelloRetryRequest; a
  // retry that offers a different suite (here ChaCha20-Poly1305, same SHA-256 hash) must abort
  // rather than re-negotiate (RFC 8446 4.1.4)
  LServer := NewSecp256r1Server(nil);
  LHrr := SendHandshakeOf(LServer.ProcessMessage(TTlsLibTestHandshakeDecoder.HandshakeMessage(Vec('client_hello_1'))))[0];
  LCookie := CookieFromHrr(LHrr);
  LCh2 := BuildClientHello2(TNamedGroupCatalog.Secp256r1, LShare, LCookie, DecodeHex(''),
    TCipherSuites13.ChaCha20Poly1305Sha256);
  CheckTrue(FailAlertOf(LServer.ProcessMessage(TTlsLibTestHandshakeDecoder.HandshakeMessage(LCh2)), LAlert),
    'a retry ClientHello that changes the cipher suite aborts');
  CheckTrue(LAlert = TTlsAlertDescription.IllegalParameter,
    'a changed retry suite is illegal_parameter');

  // positive control: the same retry keeping the selected suite proceeds to a ServerHello, proving
  // the pin does not trip on a conformant retry
  LServer := NewSecp256r1Server(nil);
  LHrr := SendHandshakeOf(LServer.ProcessMessage(TTlsLibTestHandshakeDecoder.HandshakeMessage(Vec('client_hello_1'))))[0];
  LCookie := CookieFromHrr(LHrr);
  LCh2 := BuildClientHello2(TNamedGroupCatalog.Secp256r1, LShare, LCookie, DecodeHex(''),
    TCipherSuites13.Aes128GcmSha256);
  CheckTrue(System.Length(SendHandshakeOf(LServer.ProcessMessage(TTlsLibTestHandshakeDecoder.HandshakeMessage(LCh2)))) > 0,
    'a conformant retry that keeps the suite proceeds to a ServerHello');
end;

procedure TTestHelloRetryRequest.TestServerRejectsRetryClientHelloThatChangesServerName;
var
  LServer: IHandshakeMachine;
  LHrr, LCookie, LCh2, LShare: TBytes;
  LPriv: IKeyExchangePrivateKey;
  LAlert: TTlsAlertDescription;
  LI: Int32;
const
  Names: array [0 .. 2] of string = ('other.example', '', 'server');
begin
  TNamedGroups.CreateNistEcdh(Crypto, 'secp256r1').GenerateKeyPair(LPriv, LShare);
  // the first hello names "server"; a retry that renames the host, or drops the name, must abort
  // (RFC 8446 4.1.2), else the host check made on the first hello (ticket scope) is bypassed.
  // The last case keeps the name: the positive control that a conformant retry proceeds.
  for LI := Low(Names) to High(Names) do
  begin
    LServer := NewSecp256r1Server(nil);
    LHrr := SendHandshakeOf(LServer.ProcessMessage(TTlsLibTestHandshakeDecoder.HandshakeMessage(Vec('client_hello_1'))))[0];
    LCookie := CookieFromHrr(LHrr);
    LCh2 := BuildClientHello2(TNamedGroupCatalog.Secp256r1, LShare, LCookie, DecodeHex(''), 0,
      Names[LI]);
    if Names[LI] = 'server' then
      CheckTrue(System.Length(SendHandshakeOf(LServer.ProcessMessage(TTlsLibTestHandshakeDecoder.HandshakeMessage(LCh2)))) > 0,
        'a retry that keeps the server_name proceeds to a ServerHello')
    else
    begin
      CheckTrue(FailAlertOf(LServer.ProcessMessage(TTlsLibTestHandshakeDecoder.HandshakeMessage(LCh2)), LAlert),
        Format('a retry with server_name "%s" aborts', [Names[LI]]));
      CheckTrue(LAlert = TTlsAlertDescription.IllegalParameter,
        'a changed retry server_name is illegal_parameter');
    end;
  end;
end;

procedure TTestHelloRetryRequest.TestServerRejectsRetryClientHelloThatChangesSessionId;
var
  LServer: IHandshakeMachine;
  LHrr, LCookie, LCh2, LShare: TBytes;
  LPriv: IKeyExchangePrivateKey;
  LAlert: TTlsAlertDescription;
begin
  // the retry ClientHello must resend CH1 unchanged except for the permitted fields; a changed
  // legacy_session_id is illegal_parameter (RFC 8446 4.1.2). ClientHello1 (the vector) carried an
  // empty session id, which the cookie binds; CH2 here sends a 32-byte one.
  TNamedGroups.CreateNistEcdh(Crypto, 'secp256r1').GenerateKeyPair(LPriv, LShare);
  LServer := NewSecp256r1Server(nil);
  LHrr := SendHandshakeOf(LServer.ProcessMessage(TTlsLibTestHandshakeDecoder.HandshakeMessage(Vec('client_hello_1'))))[0];
  LCookie := CookieFromHrr(LHrr);
  LCh2 := BuildClientHello2(TNamedGroupCatalog.Secp256r1, LShare, LCookie,
    DecodeHex(StringOfChar('a', 64)), TCipherSuites13.Aes128GcmSha256);
  CheckTrue(FailAlertOf(LServer.ProcessMessage(TTlsLibTestHandshakeDecoder.HandshakeMessage(LCh2)), LAlert),
    'a retry that changes legacy_session_id aborts');
  CheckTrue(LAlert = TTlsAlertDescription.IllegalParameter,
    'a changed retry session id is illegal_parameter');
end;

procedure TTestHelloRetryRequest.TestServerRejectsInnerEchInRetryClientHello;
var
  LServer: IHandshakeMachine;
  LHrr, LCookie, LCh2, LShare: TBytes;
  LPriv: IKeyExchangePrivateKey;
  LAlert: TTlsAlertDescription;
begin
  // an inner-type ech is a decrypted ClientHelloInner, which only a split-mode backend may see
  // (RFC 9849 sec. 7); the retry ClientHello is held to the same rule as the first
  TNamedGroups.CreateNistEcdh(Crypto, 'secp256r1').GenerateKeyPair(LPriv, LShare);
  LServer := NewSecp256r1Server(nil);
  LHrr := SendHandshakeOf(LServer.ProcessMessage(TTlsLibTestHandshakeDecoder.HandshakeMessage(Vec('client_hello_1'))))[0];
  LCookie := CookieFromHrr(LHrr);
  LCh2 := WithInnerEch(BuildClientHello2(TNamedGroupCatalog.Secp256r1, LShare, LCookie, nil,
    TCipherSuites13.Aes128GcmSha256));
  CheckTrue(FailAlertOf(LServer.ProcessMessage(TTlsLibTestHandshakeDecoder.HandshakeMessage(LCh2)), LAlert),
    'an inner-type ech in the retry ClientHello aborts');
  CheckTrue(LAlert = TTlsAlertDescription.IllegalParameter,
    'it is illegal_parameter');
end;

procedure TTestHelloRetryRequest.TestBackendServerAcceptsInnerEchInRetryClientHello;
var
  LServer: IHandshakeMachine;
  LHrr, LCookie, LCh2, LShare: TBytes;
  LPriv: IKeyExchangePrivateKey;
  LEffects: TArray<THandshakeEffect>;
  LAlert: TTlsAlertDescription;
begin
  // a keyless split-mode backend takes the forwarded inner hello on both flights: after the
  // HelloRetryRequest the retry's inner-type ech is accepted and the handshake continues
  TNamedGroups.CreateNistEcdh(Crypto, 'secp256r1').GenerateKeyPair(LPriv, LShare);
  LServer := NewSecp256r1Server(nil, TEchServerPolicy.Backend);
  LHrr := SendHandshakeOf(LServer.ProcessMessage(TTlsLibTestHandshakeDecoder.HandshakeMessage(WithInnerEch(Vec('client_hello_1')))))[0];
  LCookie := CookieFromHrr(LHrr);
  LCh2 := WithInnerEch(BuildClientHello2(TNamedGroupCatalog.Secp256r1, LShare, LCookie, nil,
    TCipherSuites13.Aes128GcmSha256));
  LEffects := LServer.ProcessMessage(TTlsLibTestHandshakeDecoder.HandshakeMessage(LCh2));
  CheckFalse(FailAlertOf(LEffects, LAlert),
    'a backend server does not abort an inner-type ech in the retry ClientHello');
  CheckTrue(System.Length(SendHandshakeOf(LEffects)) > 0,
    'the backend answers the retry ClientHello with a ServerHello flight');
end;

procedure TTestHelloRetryRequest.TestBackendServerRejectsOuterEchInRetryClientHello;
var
  LServer: IHandshakeMachine;
  LHrr, LCookie, LCh2, LShare: TBytes;
  LPriv: IKeyExchangePrivateKey;
  LAlert: TTlsAlertDescription;
begin
  // a backend takes only the forwarded inner hello on the retry flight too: an outer-type ech
  // aborts with illegal_parameter (RFC 9849 sec. 7)
  TNamedGroups.CreateNistEcdh(Crypto, 'secp256r1').GenerateKeyPair(LPriv, LShare);
  LServer := NewSecp256r1Server(nil, TEchServerPolicy.Backend);
  LHrr := SendHandshakeOf(LServer.ProcessMessage(TTlsLibTestHandshakeDecoder.HandshakeMessage(WithInnerEch(Vec('client_hello_1')))))[0];
  LCookie := CookieFromHrr(LHrr);
  LCh2 := WithOuterEch(BuildClientHello2(TNamedGroupCatalog.Secp256r1, LShare, LCookie, nil,
    TCipherSuites13.Aes128GcmSha256));
  CheckTrue(FailAlertOf(LServer.ProcessMessage(TTlsLibTestHandshakeDecoder.HandshakeMessage(LCh2)), LAlert),
    'an outer-type ech in the retry ClientHello aborts at a backend');
  CheckTrue(LAlert = TTlsAlertDescription.IllegalParameter, 'it is illegal_parameter');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestHelloRetryRequest);
{$ELSE}
  RegisterTest(TTestHelloRetryRequest.Suite);
{$ENDIF FPC}

end.
