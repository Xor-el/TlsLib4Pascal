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
  TlpTlsLibExceptions,
  TlpISecretBuffer,
  TlpSecretBuffer,
  TlpICryptoProvider,
  TlpCryptoAlgorithms,
  TlpINamedGroup,
  TlpNamedGroups,
  TlpNegotiationTypes,
  TlpINegotiation,
  TlpNegotiationPolicy,
  TlpCipherSuiteRegistry,
  TlpCoreExtensions,
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
  MockCryptoProvider,
  TlsLibTestBase;

type
  TTestHelloRetryRequest = class(TTlsLibAlgorithmTestCase)
  private
    FHrr: TStringList;
    function CookieSecret: ISecretBuffer;
    function MsgFrom(const AFramed: TBytes): TTlsHandshakeMessage;
    function Vec(const AName: string): TBytes;
    function SendHandshakeOf(const AEffects: TArray<THandshakeEffect>): TArray<TBytes>;
    function FailAlertOf(const AEffects: TArray<THandshakeEffect>;
      out AAlert: TTlsAlertDescription): Boolean;
    function BuildHrr(AGroup, ASuite: UInt16; const ACookie, ASessionId: TBytes): TBytes;
    function BuildClientHello2(AGroup: UInt16; const AKeyShare, ACookie,
      ASessionId: TBytes): TBytes;
    function CookieFromHrr(const AHrr: TBytes): TBytes;
    function NewSecp256r1Server(const ACookieOverride: TBytes): IHandshakeMachine;
    function NewRetryClient: IHandshakeMachine;
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestServerEmitsRfc8448Section5HelloRetryRequestByteExact;
    procedure TestCookieMintVerifyRoundTrip;
    procedure TestCookieRejectsTamperedTag;
    procedure TestClientHandlesHelloRetryRequestEmitsSecondClientHello;
    procedure TestClientRejectsSecondHelloRetryRequest;
    procedure TestClientRejectsHelloRetryUnofferedGroup;
    procedure TestServerRejectsSecondClientHelloWithoutCookie;
    procedure TestServerRejectsTamperedCookie;
    procedure TestServerRejectsUnexpectedMessageDuringRetryWait;
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

function TTestHelloRetryRequest.MsgFrom(
  const AFramed: TBytes): TTlsHandshakeMessage;
var
  LReader: THandshakeMessageReader;
begin
  LReader := THandshakeMessageReader.Create;
  try
    LReader.Append(AFramed, 0, System.Length(AFramed));
    LReader.NextMessage(Result);
  finally
    LReader.Free;
  end;
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
  const ACookie, ASessionId: TBytes): TBytes;
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
    LContext.SelectedVersion := TlsWireVersionTls13;
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
  const AKeyShare, ACookie, ASessionId: TBytes): TBytes;
var
  LCodec: IExtensionBlockCodec;
  LContext: TExtensionContext;
  LHello: TTlsClientHello;
begin
  LCodec := TExtensionBlockCodec.Create(TCoreExtensions.CreateDefaultRegistry);
  LContext := TExtensionContext.Create;
  try
    LContext.SupportedVersions := TArray<UInt16>.Create(TlsWireVersionTls13);
    LContext.SupportedGroups := TArray<UInt16>.Create(AGroup,
      TNamedGroupCatalog.X25519);
    LContext.SignatureSchemes := TArray<UInt16>.Create(
      TSignatureSchemes.EcdsaSecp256r1Sha256);
    LContext.Cookie := ACookie;
    SetLength(LContext.ClientKeyShares, 1);
    LContext.ClientKeyShares[0].Group := AGroup;
    LContext.ClientKeyShares[0].KeyExchange := AKeyShare;
    LHello.Random := nil;
    SetLength(LHello.Random, 32);
    LHello.LegacySessionId := ASessionId;
    LHello.CipherSuites := TArray<UInt16>.Create(TCipherSuites13.Aes128GcmSha256);
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
  LMsg := MsgFrom(AHrr);
  LHello := THandshakeMessages.DecodeServerHello(LMsg.Body);
  LCodec := TExtensionBlockCodec.Create(TCoreExtensions.CreateDefaultRegistry);
  LContext := TExtensionContext.Create;
  try
    LContext.MarkOffered(TExtensionTypes.KeyShare);
    LContext.MarkOffered(TExtensionTypes.Cookie);
    LContext.MarkOffered(TExtensionTypes.SupportedVersions);
    LCodec.ConsumeBlock(LContext, TTlsExtensionContextKind.HelloRetryRequest,
      LHello.Extensions);
    Result := System.Copy(LContext.Cookie);
  finally
    LContext.Free;
  end;
end;

function TTestHelloRetryRequest.NewSecp256r1Server(
  const ACookieOverride: TBytes): IHandshakeMachine;
var
  LParams: TServerHandshakeParams;
  LCerts: TStringList;
  LCred: TTlsCredential;
begin
  LParams := Default(TServerHandshakeParams);
  LParams.Clock := TSystemClock.Create;
  // a fixed HasHardwareAes=True makes the suite choice deterministically AES-128-GCM
  LParams.Provider := TFixedAesProvider.Create(Provider, True);
  LParams.Policy := TNegotiationPolicy.CreateDefault(LParams.Provider);
  LParams.CipherSuites := TCipherSuiteRegistry.CreateDefault(LParams.Provider);
  LParams.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  // the server offers only secp256r1, which the RFC 8448 Section 5 client listed but
  // did not key-share, so the server answers with a HelloRetryRequest
  LParams.Group := TNamedGroups.CreateNistEcdh(LParams.Provider, 'secp256r1');
  LParams.ServerRandom := DecodeHex(StringOfChar('2', 64));
  LParams.CookieSecret := CookieSecret;
  LParams.CookieOverride := ACookieOverride;
  // a P-256 signing key; its lone capable scheme is ecdsa_secp256r1_sha256, which the
  // negotiation needs when it processes the first ClientHello (before the retry)
  LCerts := LoadVectorFields('Certs/EcP256Chain.txt');
  try
    LCred := Default(TTlsCredential);
    LCred.PrivateKey := Provider.ImportSigningKey(DecodeHex(LCerts.Values['leaf_key']));
    LParams.CredentialResolver := TSniCredentialResolver.ForCredential(LCred);
  finally
    LCerts.Free;
  end;
  Result := TTls13ServerStateMachine.Create(LParams);
  Result.Start;
end;

function TTestHelloRetryRequest.NewRetryClient: IHandshakeMachine;
var
  LParams: TClientHandshakeParams;
begin
  LParams := Default(TClientHandshakeParams);
  LParams.Clock := TSystemClock.Create;
  LParams.Provider := Provider;
  LParams.Group := TNamedGroups.CreateX25519(Provider);
  LParams.GroupCode := TNamedGroupCatalog.X25519;
  // advertises secp256r1 as well, so the server may retry us onto it
  LParams.OfferedGroups := TArray<UInt16>.Create(TNamedGroupCatalog.Secp256r1,
    TNamedGroupCatalog.X25519);
  LParams.GroupRegistry := TNamedGroups.CreateDefaultRegistry(Provider);
  LParams.CipherSuites := TCipherSuiteRegistry.CreateDefault(Provider);
  LParams.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  LParams.OfferedSuites := TArray<UInt16>.Create(TCipherSuites13.Aes128GcmSha256);
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
  LFlight := SendHandshakeOf(LServer.ProcessMessage(MsgFrom(Vec('client_hello_1'))));
  CheckEquals(1, System.Length(LFlight),
    'the server answers a share-less ClientHello with a single HelloRetryRequest');
  CheckEqualBytes('HelloRetryRequest byte-exact vs RFC 8448 Section 5',
    Vec('hello_retry_request'), LFlight[0]);
end;

procedure TTestHelloRetryRequest.TestCookieMintVerifyRoundTrip;
var
  LCookie: THelloRetryCookie;
  LMinted, LCh1Hash: TBytes;
  LOutHash: TBytes;
  LGroup: UInt16;
begin
  LCookie := THelloRetryCookie.Create(Provider, CookieSecret);
  try
    LCh1Hash := DecodeHex(StringOfChar('5', 64)); // a 32-byte stand-in transcript hash
    LMinted := LCookie.Mint(LCh1Hash, TNamedGroupCatalog.Secp256r1);
    CheckTrue(LCookie.TryOpen(LMinted, LOutHash, LGroup), 'a minted cookie verifies');
    CheckEqualBytes('the bound transcript hash round-trips', LCh1Hash, LOutHash);
    CheckEquals(TNamedGroupCatalog.Secp256r1, LGroup, 'the bound group round-trips');
  finally
    LCookie.Free;
  end;
end;

procedure TTestHelloRetryRequest.TestCookieRejectsTamperedTag;
var
  LCookie: THelloRetryCookie;
  LMinted, LOutHash: TBytes;
  LGroup: UInt16;
begin
  LCookie := THelloRetryCookie.Create(Provider, CookieSecret);
  try
    LMinted := LCookie.Mint(DecodeHex(StringOfChar('5', 64)),
      TNamedGroupCatalog.Secp256r1);
    // flip the last MAC byte
    LMinted[System.Length(LMinted) - 1] :=
      Byte(LMinted[System.Length(LMinted) - 1] xor $01);
    CheckFalse(LCookie.TryOpen(LMinted, LOutHash, LGroup),
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
  LCh2 := SendHandshakeOf(LClient.ProcessMessage(MsgFrom(LHrr)));
  CheckEquals(1, System.Length(LCh2), 'the client resends a single ClientHello');

  // the second ClientHello key-shares the requested group and echoes the cookie
  LHello := THandshakeMessages.DecodeClientHello(MsgFrom(LCh2[0]).Body);
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
  LClient.ProcessMessage(MsgFrom(LHrr));
  CheckTrue(FailAlertOf(LClient.ProcessMessage(MsgFrom(LHrr)), LAlert),
    'a second HelloRetryRequest aborts');
  CheckTrue(LAlert = TTlsAlertDescription.UnexpectedMessage,
    'a second HelloRetryRequest is unexpected_message');
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
  CheckTrue(FailAlertOf(LClient.ProcessMessage(MsgFrom(LHrr)), LAlert),
    'a HelloRetryRequest for an unoffered group aborts');
  CheckTrue(LAlert = TTlsAlertDescription.IllegalParameter,
    'an unoffered retry group is illegal_parameter');
end;

procedure TTestHelloRetryRequest.TestServerRejectsSecondClientHelloWithoutCookie;
var
  LServer: IHandshakeMachine;
  LCh2: TBytes;
  LAlert: TTlsAlertDescription;
begin
  // drive the server to expect a second ClientHello, then send one lacking the cookie
  LServer := NewSecp256r1Server(nil);
  LServer.ProcessMessage(MsgFrom(Vec('client_hello_1')));
  LCh2 := BuildClientHello2(TNamedGroupCatalog.Secp256r1, DecodeHex(StringOfChar('4', 130)),
    nil, DecodeHex(''));
  CheckTrue(FailAlertOf(LServer.ProcessMessage(MsgFrom(LCh2)), LAlert),
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
  LHrr := SendHandshakeOf(LServer.ProcessMessage(MsgFrom(Vec('client_hello_1'))))[0];
  // echo the minted cookie back, but with a flipped byte
  LCookie := CookieFromHrr(LHrr);
  LCookie[System.Length(LCookie) - 1] :=
    Byte(LCookie[System.Length(LCookie) - 1] xor $01);
  LCh2 := BuildClientHello2(TNamedGroupCatalog.Secp256r1,
    DecodeHex(StringOfChar('4', 130)), LCookie, DecodeHex(''));
  CheckTrue(FailAlertOf(LServer.ProcessMessage(MsgFrom(LCh2)), LAlert),
    'a tampered cookie aborts');
  CheckTrue(LAlert = TTlsAlertDescription.DecryptError,
    'a tampered cookie is decrypt_error');
end;

procedure TTestHelloRetryRequest.TestServerRejectsUnexpectedMessageDuringRetryWait;
var
  LServer: IHandshakeMachine;
  LAlert: TTlsAlertDescription;
begin
  // after emitting a HelloRetryRequest the server waits for the second ClientHello;
  // any other message (here a Finished) is unexpected (RFC 8446 centralized handling)
  LServer := NewSecp256r1Server(nil);
  LServer.ProcessMessage(MsgFrom(Vec('client_hello_1')));
  CheckTrue(FailAlertOf(LServer.ProcessMessage(
    MsgFrom(DecodeHex('140000200000000000000000000000000000000000000000000000000000000000000000'))),
    LAlert), 'a non-ClientHello during the retry wait aborts');
  CheckTrue(LAlert = TTlsAlertDescription.UnexpectedMessage,
    'it is unexpected_message');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestHelloRetryRequest);
{$ELSE}
  RegisterTest(TTestHelloRetryRequest.Suite);
{$ENDIF FPC}

end.
