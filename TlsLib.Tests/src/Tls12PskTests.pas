{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit Tls12PskTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  TlpTlsVersion,
  TlpTlsLibExceptions,
  TlpTlsAlert,
  TlpICryptoProvider,
  TlpCertificateVerifierSource,
  TlpTrustTypes,
  TlpTlsCredential,
  TlpISecretBuffer,
  TlpSecretBuffer,
  TlpSession,
  TlpISession,
  TlpInMemorySessionCache,
  TlpInMemorySessionStore,
  TlpNegotiationTypes,
  TlpCipherSuiteCatalog,
  TlpCipherSuiteRegistry,
  TlpINegotiation,
  TlpTls12KeySchedule,
  TlpHandshakeMessage,
  TlpHandshakeMessages,
  TlpITlsConfig,
  TlpITlsConfigBuilder,
  TlpTlsPresets,
  TlpTlsEngineFactory,
  TlpTlsConnectionInfo,
  TlpITlsEngine,
  TlsLibTestCertificates,
  TlsLibHandshakeTestBase;

type
  TTestTls12Psk = class(TTlsLibHandshakeTestCase)
  private
  const
    ServerHost = 'localhost';
    Identity1 = 'client-one';
    Identity2 = 'client-two';
    function Psk(const AIdentity: string; ASeed: Byte): TTls12Psk;
    function Only12: TArray<UInt16>;
    function NewClient(const APsk: TTls12Psk): ITlsEngine;
    function NewServer(const APsks: TArray<TTls12Psk>): ITlsEngine;
    function NewServerWithCertificate(const APsks: TArray<TTls12Psk>): ITlsEngine;
    function NewCertificateClient: ITlsEngine;
    /// <summary>A PSK and certificate-trust client that re-verifies resumed servers.</summary>
    function NewReverifyClient(const ACache: ISessionCache;
      ADeferral: TVerdictDeferral): ITlsEngine;
    /// <summary>A resuming certificate server over AStore that also accepts APsks.</summary>
    function NewStoreServer(const AStore: ISessionStore;
      const APsks: TArray<TTls12Psk>): ITlsEngine;
    procedure CheckClientDataReachesServer(const AClient, AServer: ITlsEngine);
    /// <summary>Runs an unknown-identity or wrong-secret handshake and returns the alert the
    /// server and the client each end on.</summary>
    procedure RunFailing(const APsk: TTls12Psk; const AServerPsks: TArray<TTls12Psk>;
      out AServerAlert, AClientAlert: TTlsAlertDescription);
    /// <summary>The server's first flight with a handshake message of AType spliced in after
    /// record number AAfter (0 based).</summary>
    function Splice(const AFlight: TBytes; AAfter: Int32; const AFramed: TBytes): TBytes;
    function ClientRefused(const AFacet: ITls12ClientConfigFacet): Boolean;
    function ServerRefused(const AFacet: ITls12ServerConfigFacet): Boolean;
  published
    procedure TestPremasterFraming;
    procedure TestPremasterRefusesAnOversizeOperand;
    procedure TestPremasterAcceptsTheLargestOperand;
    procedure TestPremasterRefusesAMissingOperand;
    procedure TestServerKeyExchangeRoundTrips;
    procedure TestClientKeyExchangeRoundTrips;
    procedure TestPskSuitesAreInTheCatalogAndNotInTheDefaults;
    procedure TestEachPskSuiteCompletesAndFlowsData;
    procedure TestServerReportsTheIdentityTheClientProved;
    procedure TestServerPicksThePskByIdentity;
    procedure TestWrongSecretAndUnknownIdentityEndTheSame;
    procedure TestRequiredPskClientRefusesACertificateOnlyServer;
    procedure TestNonRequiredClientFallsBackToCertificate;
    procedure TestPskServerAlsoServesACertificateClient;
    procedure TestConfiguredPskIsPreferredOverTheCertificate;
    procedure TestKnownIdentityStandsInForRequiredClientAuth;
    procedure TestPskSessionResumes;
    procedure TestPskSessionIsNotResumedOnceItsKeyIsGone;
    procedure TestPskSessionIsNotResumedOnceItsSecretIsRotated;
    procedure TestDeclinedPskOfferDoesNotStampACertificateSession;
    procedure TestDeclinedCertificateOfferDoesNotStampAPskSession;
    procedure TestPskResumeUnderReverifyDoesNotParkForAVerdict;
    procedure TestConnectionInfoPskIdentityIsACopy;
    procedure TestServerWithoutPsksNeverSelectsAPskSuite;
    procedure TestClientRefusesACertificateUnderAPskSuite;
    procedure TestClientRefusesACertificateRequestUnderAPskSuite;
    procedure TestBuilderRefusals;
    procedure TestIdentityBeyondTheWireLimitIsRefused;
    procedure TestSecretBeyondTheWireLimitIsRefused;
    procedure TestSecretAtTheWireLimitIsAccepted;
  end;

implementation

{ TTestTls12Psk }

function TTestTls12Psk.Psk(const AIdentity: string; ASeed: Byte): TTls12Psk;
var
  LSecret: TBytes;
  LI: Int32;
begin
  Result.Identity := BytesOf(AIdentity);
  SetLength(LSecret, 32);
  for LI := 0 to 31 do
    LSecret[LI] := Byte(ASeed + LI);
  Result.Secret := TSecretBuffer.From(LSecret);
end;

function TTestTls12Psk.Only12: TArray<UInt16>;
begin
  Result := TArray<UInt16>.Create(TlsWireVersionTls12);
end;

function TTestTls12Psk.NewClient(const APsk: TTls12Psk): ITlsEngine;
begin
  // a PSK-only client: no trust source, TLS 1.2 only, the PSK required
  Result := TTlsEngineFactory.CreateClientEngine(TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithSupportedVersions(Only12).Tls12.WithPreSharedKey(APsk).Build, ServerHost);
end;

function TTestTls12Psk.NewServer(const APsks: TArray<TTls12Psk>): ITlsEngine;
begin
  Result := TTlsEngineFactory.CreateServerEngine(TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithSupportedVersions(Only12).Tls12.WithPreSharedKeys(APsks).Build);
end;

function TTestTls12Psk.NewServerWithCertificate(const APsks: TArray<TTls12Psk>): ITlsEngine;
begin
  Result := TTlsEngineFactory.CreateServerEngine(TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithSupportedVersions(Only12).WithCredential(ServerCredential)
    .Tls12.WithPreSharedKeys(APsks).Build);
end;

function TTestTls12Psk.NewCertificateClient: ITlsEngine;
begin
  Result := TTlsEngineFactory.CreateClientEngine(TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithSupportedVersions(Only12)
    .WithServerVerification(
      TServerVerification.WebPki(TTlsLibTestCertificates.EcP256RootStore).Build)
    .Build, ServerHost);
end;

function TTestTls12Psk.NewReverifyClient(const ACache: ISessionCache;
  ADeferral: TVerdictDeferral): ITlsEngine;
var
  LBuilder: ITlsClientConfigBuilder;
begin
  LBuilder := TTlsPresets.Compatible(Crypto, Pkix).Client.WithSupportedVersions(Only12)
    .WithServerVerification(
      TServerVerification.WebPki(TTlsLibTestCertificates.EcP256RootStore).Build)
    .WithResumption(True).WithSessionCache(ACache)
    .WithResumptionScope(BytesOf('reverify-client')).WithResumeVerification(TResumeVerification.Reverify);
  if ADeferral = TVerdictDeferral.LiveRevocation then
    LBuilder.WithLiveRevocationVerdict(0)
  else if ADeferral = TVerdictDeferral.HostDecision then
    LBuilder.WithAsyncCertificateVerdict(0);
  Result := TTlsEngineFactory.CreateClientEngine(LBuilder.Tls12
    .WithPreSharedKey(Psk(Identity1, 1)).WithPreSharedKeyRequired(False).Build, ServerHost);
end;

function TTestTls12Psk.NewStoreServer(const AStore: ISessionStore;
  const APsks: TArray<TTls12Psk>): ITlsEngine;
var
  LBuilder: ITlsServerConfigBuilder;
begin
  LBuilder := TTlsPresets.Compatible(Crypto, Pkix).Server.WithSupportedVersions(Only12)
    .WithCredential(ServerCredential).WithSessionStore(AStore);
  if System.Length(APsks) > 0 then
    Result := TTlsEngineFactory.CreateServerEngine(LBuilder.Tls12.WithPreSharedKeys(APsks).Build)
  else
    Result := TTlsEngineFactory.CreateServerEngine(LBuilder.Build);
end;

procedure TTestTls12Psk.CheckClientDataReachesServer(const AClient, AServer: ITlsEngine);
var
  LFromClient: TBytes;
begin
  LFromClient := BytesOf('hello over a pre-shared key');
  AClient.Write(LFromClient, 0, System.Length(LFromClient));
  Pump(AClient, AServer);
  CheckEqualBytes('the server decrypts the client application data', LFromClient,
    ReadAllApp(AServer));
end;

procedure TTestTls12Psk.RunFailing(const APsk: TTls12Psk; const AServerPsks: TArray<TTls12Psk>;
  out AServerAlert, AClientAlert: TTlsAlertDescription);
var
  LClient, LServer: ITlsEngine;
begin
  LClient := NewClient(APsk);
  LServer := NewServer(AServerPsks);
  RunHandshake(LClient, LServer);
  CheckTrue(LServer.IsTerminal, 'the server ended the handshake');
  AServerAlert := LServer.LastError.Alert.Description;
  AClientAlert := TTlsAlertDescription.CloseNotify;
  if LClient.IsTerminal then
    AClientAlert := LClient.LastError.Alert.Description;
end;

function TTestTls12Psk.Splice(const AFlight: TBytes; AAfter: Int32;
  const AFramed: TBytes): TBytes;
var
  LPos, LLen, LIndex: Int32;
  LRecord: TBytes;
begin
  Result := nil;
  LPos := 0;
  LIndex := 0;
  LRecord := ConcatBytes(TBytes.Create($16, $03, $03, Byte(System.Length(AFramed) shr 8),
    Byte(System.Length(AFramed))), AFramed);
  while LPos + 5 <= System.Length(AFlight) do
  begin
    LLen := 5 + ((AFlight[LPos + 3] shl 8) or AFlight[LPos + 4]);
    Result := ConcatBytes(Result, System.Copy(AFlight, LPos, LLen));
    if LIndex = AAfter then
      Result := ConcatBytes(Result, LRecord);
    Inc(LPos, LLen);
    Inc(LIndex);
  end;
end;

function TTestTls12Psk.ClientRefused(const AFacet: ITls12ClientConfigFacet): Boolean;
begin
  Result := False;
  try
    AFacet.Build;
  except
    on E: EArgumentTlsLibException do
      Result := True;
    on E: EInvalidOperationTlsLibException do
      Result := True;
  end;
end;

function TTestTls12Psk.ServerRefused(const AFacet: ITls12ServerConfigFacet): Boolean;
begin
  Result := False;
  try
    AFacet.Build;
  except
    on E: EArgumentTlsLibException do
      Result := True;
    on E: EInvalidOperationTlsLibException do
      Result := True;
  end;
end;

procedure TTestTls12Psk.TestPremasterFraming;
var
  LPremaster: ISecretBuffer;
begin
  // RFC 5489 2 / RFC 4279 2: uint16(len Z) || Z || uint16(len PSK) || PSK
  LPremaster := TTls12PskPremaster.Build(
    TSecretBuffer.From(TBytes.Create($AA, $BB)),
    TSecretBuffer.From(TBytes.Create($01, $02, $03)));
  CheckEqualBytes('the framed premaster',
    TBytes.Create($00, $02, $AA, $BB, $00, $03, $01, $02, $03), LPremaster.ToBytes);
end;

procedure TTestTls12Psk.TestPremasterRefusesAnOversizeOperand;
var
  LSmall, LBig: ISecretBuffer;
  LSharedRefused, LPskRefused: Boolean;
begin
  // a uint16 length prefix cannot frame 65536 bytes (RFC 4279 2)
  LSmall := TSecretBuffer.From(TBytes.Create($AA));
  LBig := TSecretBuffer.Allocate(65536);
  LSharedRefused := False;
  try
    TTls12PskPremaster.Build(LBig, LSmall);
  except
    on E: EArgumentTlsLibException do
      LSharedRefused := True;
  end;
  CheckTrue(LSharedRefused, 'an oversize shared secret is refused');
  LPskRefused := False;
  try
    TTls12PskPremaster.Build(LSmall, LBig);
  except
    on E: EArgumentTlsLibException do
      LPskRefused := True;
  end;
  CheckTrue(LPskRefused, 'an oversize PSK is refused');
end;

procedure TTestTls12Psk.TestPremasterAcceptsTheLargestOperand;
var
  LPremaster: ISecretBuffer;
  LBytes: TBytes;
begin
  LPremaster := TTls12PskPremaster.Build(TSecretBuffer.Allocate(65535),
    TSecretBuffer.From(TBytes.Create($AA)));
  CheckEquals(2 + 65535 + 2 + 1, LPremaster.Len, 'the 65535-byte boundary is framed');
  LBytes := LPremaster.ToBytes;
  CheckEquals($FFFF, (Int32(LBytes[0]) shl 8) or LBytes[1], 'the length prefix is FF FF');
  CheckEquals($0001, (Int32(LBytes[2 + 65535]) shl 8) or LBytes[2 + 65535 + 1],
    'the PSK length prefix follows the 65535-byte operand');
end;

procedure TTestTls12Psk.TestPremasterRefusesAMissingOperand;
var
  LRefused: Boolean;
begin
  LRefused := False;
  try
    TTls12PskPremaster.Build(TSecretBuffer.From(TBytes.Create($AA)), nil);
  except
    on E: EArgumentTlsLibException do
      LRefused := True;
  end;
  CheckTrue(LRefused, 'a missing PSK is refused');
end;

procedure TTestTls12Psk.TestServerKeyExchangeRoundTrips;
var
  LIn, LOut: TTlsServerKeyExchangeEcdhePsk;
begin
  LIn.IdentityHint := nil;
  LIn.NamedCurve := TNamedGroupCatalog.Secp256r1;
  LIn.PublicKey := TBytes.Create($04, $01, $02);
  LOut := THandshakeMessages.DecodeServerKeyExchangeEcdhePsk(
    THandshakeMessages.EncodeServerKeyExchangeEcdhePsk(LIn));
  CheckEquals(0, System.Length(LOut.IdentityHint), 'an empty hint');
  CheckEquals(Int64(LIn.NamedCurve), Int64(LOut.NamedCurve), 'the curve');
  CheckEqualBytes('the point', LIn.PublicKey, LOut.PublicKey);
  // a hint a peer sends is parsed, to be ignored
  LIn.IdentityHint := BytesOf('hint');
  LOut := THandshakeMessages.DecodeServerKeyExchangeEcdhePsk(
    THandshakeMessages.EncodeServerKeyExchangeEcdhePsk(LIn));
  CheckEqualBytes('a hint survives', LIn.IdentityHint, LOut.IdentityHint);
end;

procedure TTestTls12Psk.TestClientKeyExchangeRoundTrips;
var
  LIn, LOut: TTlsClientKeyExchangeEcdhePsk;
  LRefused: Boolean;
begin
  LIn.Identity := BytesOf(Identity1);
  LIn.PublicKey := TBytes.Create($04, $05);
  LOut := THandshakeMessages.DecodeClientKeyExchangeEcdhePsk(
    THandshakeMessages.EncodeClientKeyExchangeEcdhePsk(LIn));
  CheckEqualBytes('the identity', LIn.Identity, LOut.Identity);
  CheckEqualBytes('the point', LIn.PublicKey, LOut.PublicKey);
  // an empty identity is syntactically valid (the vector is <0..2^16-1>)
  LIn.Identity := nil;
  LOut := THandshakeMessages.DecodeClientKeyExchangeEcdhePsk(
    THandshakeMessages.EncodeClientKeyExchangeEcdhePsk(LIn));
  CheckEquals(0, System.Length(LOut.Identity), 'an empty identity decodes');
  // trailing bytes are a decode_error
  LRefused := False;
  try
    THandshakeMessages.DecodeClientKeyExchangeEcdhePsk(
      ConcatBytes(THandshakeMessages.EncodeClientKeyExchangeEcdhePsk(LIn), TBytes.Create($00)));
  except
    on E: EDecodeErrorTlsLibException do
      LRefused := True;
  end;
  CheckTrue(LRefused, 'trailing bytes are refused');
end;

procedure TTestTls12Psk.TestPskSuitesAreInTheCatalogAndNotInTheDefaults;
var
  LSuite: TTlsCipherSuite;
  LDual: ICipherSuiteRegistry;
begin
  CheckTrue(TCipherSuiteCatalog.TryGet(TCipherSuites12.EcdhePskChaCha20Poly1305Sha256, LSuite),
    'the ChaCha20-Poly1305 PSK suite is catalogued');
  CheckTrue(LSuite.Auth = TAuthMethod.Psk, 'it authenticates by PSK');
  CheckEquals('TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256',
    TCipherSuiteCatalog.Name(TCipherSuites12.EcdhePskChaCha20Poly1305Sha256), 'its IANA name');
  LDual := TCipherSuiteRegistry.CreateDualVersion(Crypto);
  CheckFalse(LDual.TryGet(TCipherSuites12.EcdhePskChaCha20Poly1305Sha256, LSuite),
    'the dual-version defaults never hold a PSK suite');
  CheckTrue(TCipherSuiteRegistry.CreateTls12Psk(Crypto).TryGet(
    TCipherSuites12.EcdhePskAes128GcmSha256, LSuite), 'the PSK registry holds the GCM suite');
end;

procedure TTestTls12Psk.TestEachPskSuiteCompletesAndFlowsData;
var
  LCodes: array[0..2] of UInt16;
  LI: Int32;
  LClient, LServer: ITlsEngine;
  LPsk: TTls12Psk;
begin
  LCodes[0] := TCipherSuites12.EcdhePskChaCha20Poly1305Sha256;
  LCodes[1] := TCipherSuites12.EcdhePskAes128GcmSha256;
  LCodes[2] := TCipherSuites12.EcdhePskAes256GcmSha384;
  LPsk := Psk(Identity1, 1);
  for LI := 0 to 2 do
  begin
    LClient := TTlsEngineFactory.CreateClientEngine(TTlsPresets.Compatible(Crypto, Pkix).Client
      .WithSupportedVersions(Only12).WithCipherSuiteList(TArray<UInt16>.Create(LCodes[LI]))
      .Tls12.WithPreSharedKey(LPsk).Build, ServerHost);
    LServer := TTlsEngineFactory.CreateServerEngine(TTlsPresets.Compatible(Crypto, Pkix).Server
      .WithSupportedVersions(Only12).WithCipherSuiteList(TArray<UInt16>.Create(LCodes[LI]))
      .Tls12.WithPreSharedKeys(TArray<TTls12Psk>.Create(LPsk)).Build);
    RunHandshake(LClient, LServer);
    CheckFalse(LClient.IsTerminal or LServer.IsTerminal, 'the handshake completed');
    CheckEquals(Int64(LCodes[LI]), Int64(LClient.ConnectionInfo.CipherSuite), 'the client suite');
    CheckEquals(Int64(LCodes[LI]), Int64(LServer.ConnectionInfo.CipherSuite), 'the server suite');
    CheckEquals(0, System.Length(LClient.ConnectionInfo.PeerCertificates),
      'no server certificate was sent');
    CheckClientDataReachesServer(LClient, LServer);
  end;
end;

procedure TTestTls12Psk.TestServerReportsTheIdentityTheClientProved;
var
  LClient, LServer: ITlsEngine;
begin
  LClient := NewClient(Psk(Identity1, 1));
  LServer := NewServer(TArray<TTls12Psk>.Create(Psk(Identity1, 1)));
  RunHandshake(LClient, LServer);
  CheckFalse(LClient.IsTerminal or LServer.IsTerminal, 'the handshake completed');
  CheckEqualBytes('the server sees the identity', BytesOf(Identity1),
    LServer.ConnectionInfo.PskIdentity);
  CheckEqualBytes('the client reports its own', BytesOf(Identity1),
    LClient.ConnectionInfo.PskIdentity);
end;

procedure TTestTls12Psk.TestServerPicksThePskByIdentity;
var
  LClient, LServer: ITlsEngine;
begin
  LClient := NewClient(Psk(Identity2, 50));
  LServer := NewServer(TArray<TTls12Psk>.Create(Psk(Identity1, 1), Psk(Identity2, 50)));
  RunHandshake(LClient, LServer);
  CheckFalse(LClient.IsTerminal or LServer.IsTerminal, 'the handshake completed');
  CheckEqualBytes('the second identity was matched', BytesOf(Identity2),
    LServer.ConnectionInfo.PskIdentity);
end;

procedure TTestTls12Psk.TestWrongSecretAndUnknownIdentityEndTheSame;
var
  LWrongServer, LWrongClient, LUnknownServer, LUnknownClient: TTlsAlertDescription;
begin
  // a secret that differs and an identity the server lacks are indistinguishable to the peer
  RunFailing(Psk(Identity1, 9), TArray<TTls12Psk>.Create(Psk(Identity1, 1)),
    LWrongServer, LWrongClient);
  RunFailing(Psk('nobody', 1), TArray<TTls12Psk>.Create(Psk(Identity1, 1)),
    LUnknownServer, LUnknownClient);
  CheckEquals(Int64(Ord(LWrongServer)), Int64(Ord(LUnknownServer)),
    'the server ends on the same alert');
  CheckEquals(Int64(Ord(LWrongClient)), Int64(Ord(LUnknownClient)),
    'the client sees the same alert');
  CheckTrue(LUnknownServer in [TTlsAlertDescription.DecryptError, TTlsAlertDescription.BadRecordMac],
    'an authentication failure, not unknown_psk_identity');
end;

procedure TTestTls12Psk.TestRequiredPskClientRefusesACertificateOnlyServer;
var
  LClient, LServer: ITlsEngine;
begin
  // the PSK-required client offers no certificate suite, so a certificate-only server has no suite
  LClient := NewClient(Psk(Identity1, 1));
  LServer := TTlsEngineFactory.CreateServerEngine(TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithSupportedVersions(Only12).WithCredential(ServerCredential).Build);
  RunHandshake(LClient, LServer);
  CheckTrue(LServer.IsTerminal, 'the server found no common suite');
  CheckEquals(Int64(Ord(TTlsAlertDescription.HandshakeFailure)),
    Int64(Ord(LServer.LastError.Alert.Description)), 'with handshake_failure');
end;

procedure TTestTls12Psk.TestNonRequiredClientFallsBackToCertificate;
var
  LClient, LServer: ITlsEngine;
begin
  LClient := TTlsEngineFactory.CreateClientEngine(TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithSupportedVersions(Only12)
    .WithServerVerification(
      TServerVerification.WebPki(TTlsLibTestCertificates.EcP256RootStore).Build)
    .Tls12.WithPreSharedKey(Psk(Identity1, 1)).WithPreSharedKeyRequired(False).Build, ServerHost);
  LServer := TTlsEngineFactory.CreateServerEngine(TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithSupportedVersions(Only12).WithCredential(ServerCredential).Build);
  RunHandshake(LClient, LServer);
  CheckFalse(LClient.IsTerminal or LServer.IsTerminal, 'the handshake completed');
  CheckTrue(System.Length(LClient.ConnectionInfo.PeerCertificates) > 0, 'a certificate was used');
  CheckEquals(0, System.Length(LClient.ConnectionInfo.PskIdentity), 'and no PSK');
end;

procedure TTestTls12Psk.TestPskServerAlsoServesACertificateClient;
var
  LClient, LServer: ITlsEngine;
begin
  LClient := NewCertificateClient;
  LServer := NewServerWithCertificate(TArray<TTls12Psk>.Create(Psk(Identity1, 1)));
  RunHandshake(LClient, LServer);
  CheckFalse(LClient.IsTerminal or LServer.IsTerminal, 'the handshake completed');
  CheckEquals(0, System.Length(LServer.ConnectionInfo.PskIdentity), 'by certificate');
end;

procedure TTestTls12Psk.TestConfiguredPskIsPreferredOverTheCertificate;
var
  LClient, LServer: ITlsEngine;
begin
  LClient := TTlsEngineFactory.CreateClientEngine(TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithSupportedVersions(Only12)
    .WithServerVerification(
      TServerVerification.WebPki(TTlsLibTestCertificates.EcP256RootStore).Build)
    .Tls12.WithPreSharedKey(Psk(Identity1, 1)).WithPreSharedKeyRequired(False).Build, ServerHost);
  LServer := NewServerWithCertificate(TArray<TTls12Psk>.Create(Psk(Identity1, 1)));
  RunHandshake(LClient, LServer);
  CheckFalse(LClient.IsTerminal or LServer.IsTerminal, 'the handshake completed');
  CheckEqualBytes('the PSK was used', BytesOf(Identity1), LServer.ConnectionInfo.PskIdentity);
  CheckEquals(0, System.Length(LClient.ConnectionInfo.PeerCertificates),
    'and no certificate was sent');
end;

procedure TTestTls12Psk.TestKnownIdentityStandsInForRequiredClientAuth;
var
  LClient, LServer: ITlsEngine;
begin
  LServer := TTlsEngineFactory.CreateServerEngine(TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithSupportedVersions(Only12).WithCredential(ServerCredential)
    .WithClientVerification(
      TClientVerification.WebPki(TTlsLibTestCertificates.EcP256RootStore).Build)
    .WithPeerAuth(TClientAuthMode.Required)
    .Tls12.WithPreSharedKeys(TArray<TTls12Psk>.Create(Psk(Identity1, 1))).Build);
  LClient := NewClient(Psk(Identity1, 1));
  RunHandshake(LClient, LServer);
  CheckFalse(LClient.IsTerminal or LServer.IsTerminal,
    'the PSK authenticated the client, so no certificate was requested');
end;

procedure TTestTls12Psk.TestPskSessionResumes;
var
  LCache: ISessionCache;
  LStore: ISessionStore;
  LClientConfig: ITlsClientConfig;
  LServerConfig: ITlsServerConfig;
  LClient, LServer: ITlsEngine;
begin
  LCache := TInMemorySessionCache.Create;
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);
  LClientConfig := TTlsPresets.Compatible(Crypto, Pkix).Client.WithSupportedVersions(Only12)
    .WithSessionCache(LCache).Tls12.WithPreSharedKey(Psk(Identity1, 1)).Build;
  LServerConfig := TTlsPresets.Compatible(Crypto, Pkix).Server.WithSupportedVersions(Only12)
    .WithSessionStore(LStore).Tls12.WithPreSharedKeys(
    TArray<TTls12Psk>.Create(Psk(Identity1, 1))).Build;
  LClient := TTlsEngineFactory.CreateClientEngine(LClientConfig, ServerHost);
  LServer := TTlsEngineFactory.CreateServerEngine(LServerConfig);
  RunHandshake(LClient, LServer);
  CheckFalse(LClient.ConnectionInfo.Resumed, 'a first handshake is not a resumption');
  Pump(LServer, LClient);
  // the second connection resumes the PSK session, with no key exchange and no certificate
  LClient := TTlsEngineFactory.CreateClientEngine(LClientConfig, ServerHost);
  LServer := TTlsEngineFactory.CreateServerEngine(LServerConfig);
  RunHandshake(LClient, LServer);
  CheckFalse(LClient.IsTerminal or LServer.IsTerminal, 'the second handshake completed');
  CheckTrue(LServer.ConnectionInfo.Resumed, 'the server resumed');
  CheckTrue(LClient.ConnectionInfo.Resumed, 'and so did the client');
  CheckEqualBytes('the resumed server still reports the identity', BytesOf(Identity1),
    LServer.ConnectionInfo.PskIdentity);
  CheckEqualBytes('and so does the client', BytesOf(Identity1),
    LClient.ConnectionInfo.PskIdentity);
  CheckClientDataReachesServer(LClient, LServer);
end;

procedure TTestTls12Psk.TestDeclinedPskOfferDoesNotStampACertificateSession;
var
  LCache: ISessionCache;
  LStoreA, LStoreB: ISessionStore;
  LPsks, LNone: TArray<TTls12Psk>;
  LClient, LServer: ITlsEngine;
begin
  // the declined PSK offer's identity must not stamp the new certificate session
  LCache := TInMemorySessionCache.Create;
  LStoreA := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);
  LStoreB := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);
  LPsks := TArray<TTls12Psk>.Create(Psk(Identity1, 1));
  LNone := nil;

  LClient := NewReverifyClient(LCache, TVerdictDeferral.None);
  LServer := NewStoreServer(LStoreA, LPsks);
  RunHandshake(LClient, LServer);
  Pump(LServer, LClient);
  CheckEqualBytes('the first handshake used the PSK', BytesOf(Identity1),
    LClient.ConnectionInfo.PskIdentity);

  LClient := NewReverifyClient(LCache, TVerdictDeferral.None);
  LServer := NewStoreServer(LStoreB, LNone);
  RunHandshake(LClient, LServer);
  Pump(LServer, LClient);
  CheckFalse(LClient.ConnectionInfo.Resumed, 'the unknown session was declined');
  CheckEquals(0, System.Length(LClient.ConnectionInfo.PskIdentity), 'by certificate');

  LClient := NewReverifyClient(LCache, TVerdictDeferral.None);
  LServer := NewStoreServer(LStoreB, LNone);
  RunHandshake(LClient, LServer);
  CheckTrue(LClient.ConnectionInfo.Resumed, 'the certificate session resumes');
  CheckEquals(0, System.Length(LClient.ConnectionInfo.PskIdentity),
    'and reports no PSK identity');
  CheckTrue(System.Length(LClient.ConnectionInfo.PeerCertificates) > 0,
    'with the verified chain');
end;

procedure TTestTls12Psk.TestDeclinedCertificateOfferDoesNotStampAPskSession;
var
  LCache: ISessionCache;
  LStoreA, LStoreB: ISessionStore;
  LPsks, LNone: TArray<TTls12Psk>;
  LClient, LServer: ITlsEngine;
begin
  // the declined certificate offer's chain must not ride onto the new PSK session
  LCache := TInMemorySessionCache.Create;
  LStoreA := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);
  LStoreB := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);
  LPsks := TArray<TTls12Psk>.Create(Psk(Identity1, 1));
  LNone := nil;

  LClient := NewReverifyClient(LCache, TVerdictDeferral.None);
  LServer := NewStoreServer(LStoreA, LNone);
  RunHandshake(LClient, LServer);
  Pump(LServer, LClient);
  CheckTrue(System.Length(LClient.ConnectionInfo.PeerCertificates) > 0,
    'the first handshake used the certificate');

  LClient := NewReverifyClient(LCache, TVerdictDeferral.None);
  LServer := NewStoreServer(LStoreB, LPsks);
  RunHandshake(LClient, LServer);
  Pump(LServer, LClient);
  CheckFalse(LClient.ConnectionInfo.Resumed, 'the unknown session was declined');
  CheckEqualBytes('the PSK authenticated', BytesOf(Identity1),
    LClient.ConnectionInfo.PskIdentity);

  LClient := NewReverifyClient(LCache, TVerdictDeferral.None);
  LServer := NewStoreServer(LStoreB, LPsks);
  RunHandshake(LClient, LServer);
  CheckTrue(LClient.ConnectionInfo.Resumed, 'the PSK session resumes');
  CheckEqualBytes('under its PSK identity', BytesOf(Identity1),
    LClient.ConnectionInfo.PskIdentity);
  CheckEquals(0, System.Length(LClient.ConnectionInfo.PeerCertificates),
    'with no certificate chain');
end;

procedure TTestTls12Psk.TestPskResumeUnderReverifyDoesNotParkForAVerdict;
var
  LDeferrals: array [0 .. 1] of TVerdictDeferral;
  LCache: ISessionCache;
  LStore: ISessionStore;
  LPsks: TArray<TTls12Psk>;
  LClient, LServer: ITlsEngine;
  LI: Int32;
begin
  // a PSK session has no chain to judge: Reverify must neither re-check nor park for a verdict
  LDeferrals[0] := TVerdictDeferral.HostDecision;
  LDeferrals[1] := TVerdictDeferral.LiveRevocation;
  LPsks := TArray<TTls12Psk>.Create(Psk(Identity1, 1));
  for LI := 0 to 1 do
  begin
    LCache := TInMemorySessionCache.Create;
    LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);
    LClient := NewReverifyClient(LCache, LDeferrals[LI]);
    LServer := NewStoreServer(LStore, LPsks);
    RunHandshake(LClient, LServer);
    Pump(LServer, LClient);
    CheckEqualBytes('the first handshake used the PSK', BytesOf(Identity1),
      LClient.ConnectionInfo.PskIdentity);

    LClient := NewReverifyClient(LCache, LDeferrals[LI]);
    LServer := NewStoreServer(LStore, LPsks);
    RunHandshake(LClient, LServer);
    CheckFalse(LClient.AwaitingCertificateVerdict, 'no verdict is requested for a PSK-authenticated session');
    CheckFalse(LClient.IsHandshaking, 'the resumed handshake completed');
    CheckTrue(LClient.ConnectionInfo.Resumed, 'as a resumption');
  end;
end;

procedure TTestTls12Psk.TestPskSessionIsNotResumedOnceItsKeyIsGone;
var
  LCache: ISessionCache;
  LStore: ISessionStore;
  LScope: TBytes;
  LClientConfig: ITlsClientConfig;
  LServer: ITlsServerConfig;
  LClient, LEngine: ITlsEngine;
begin
  LCache := TInMemorySessionCache.Create;
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);
  LScope := BytesOf('shared-scope');
  LClientConfig := TTlsPresets.Compatible(Crypto, Pkix).Client.WithSupportedVersions(Only12)
    .WithSessionCache(LCache).Tls12.WithPreSharedKey(Psk(Identity1, 1)).Build;
  LServer := TTlsPresets.Compatible(Crypto, Pkix).Server.WithSupportedVersions(Only12)
    .WithSessionStore(LStore).WithResumptionScope(LScope).Tls12.WithPreSharedKeys(
    TArray<TTls12Psk>.Create(Psk(Identity1, 1), Psk(Identity2, 50))).Build;
  LClient := TTlsEngineFactory.CreateClientEngine(LClientConfig, ServerHost);
  LEngine := TTlsEngineFactory.CreateServerEngine(LServer);
  RunHandshake(LClient, LEngine);
  CheckFalse(LClient.IsTerminal or LEngine.IsTerminal, 'the first handshake completed');
  Pump(LEngine, LClient);
  // the same store and scope, but the key that authenticated the session is no longer configured
  LServer := TTlsPresets.Compatible(Crypto, Pkix).Server.WithSupportedVersions(Only12)
    .WithSessionStore(LStore).WithResumptionScope(LScope).Tls12.WithPreSharedKeys(
    TArray<TTls12Psk>.Create(Psk(Identity2, 50))).Build;
  LClient := TTlsEngineFactory.CreateClientEngine(LClientConfig, ServerHost);
  LEngine := TTlsEngineFactory.CreateServerEngine(LServer);
  RunHandshake(LClient, LEngine);
  CheckFalse(LEngine.ConnectionInfo.Resumed, 'a revoked key does not resume its session');
end;

procedure TTestTls12Psk.TestPskSessionIsNotResumedOnceItsSecretIsRotated;
var
  LCache: ISessionCache;
  LStore: ISessionStore;
  LScope: TBytes;
  LClientConfig: ITlsClientConfig;
  LServer: ITlsServerConfig;
  LClient, LEngine: ITlsEngine;
begin
  LCache := TInMemorySessionCache.Create;
  LStore := TInMemorySessionStore.Create(Crypto.Primitives.GetRandom);
  LScope := BytesOf('shared-scope');
  LClientConfig := TTlsPresets.Compatible(Crypto, Pkix).Client.WithSupportedVersions(Only12)
    .WithSessionCache(LCache).Tls12.WithPreSharedKey(Psk(Identity1, 1)).Build;
  LServer := TTlsPresets.Compatible(Crypto, Pkix).Server.WithSupportedVersions(Only12)
    .WithSessionStore(LStore).WithResumptionScope(LScope).Tls12.WithPreSharedKeys(
    TArray<TTls12Psk>.Create(Psk(Identity1, 1))).Build;
  LClient := TTlsEngineFactory.CreateClientEngine(LClientConfig, ServerHost);
  LEngine := TTlsEngineFactory.CreateServerEngine(LServer);
  RunHandshake(LClient, LEngine);
  CheckFalse(LClient.IsTerminal or LEngine.IsTerminal, 'the first handshake completed');
  Pump(LEngine, LClient);
  // the identity is still configured, but its secret has been rotated: the old session must not resume
  LServer := TTlsPresets.Compatible(Crypto, Pkix).Server.WithSupportedVersions(Only12)
    .WithSessionStore(LStore).WithResumptionScope(LScope).Tls12.WithPreSharedKeys(
    TArray<TTls12Psk>.Create(Psk(Identity1, 9))).Build;
  LClient := TTlsEngineFactory.CreateClientEngine(LClientConfig, ServerHost);
  LEngine := TTlsEngineFactory.CreateServerEngine(LServer);
  RunHandshake(LClient, LEngine);
  CheckFalse(LEngine.ConnectionInfo.Resumed, 'a rotated secret does not resume the old session');
end;

procedure TTestTls12Psk.TestConnectionInfoPskIdentityIsACopy;
var
  LClient, LServer: ITlsEngine;
  LInfo: TTlsConnectionInfo;
begin
  LClient := NewClient(Psk(Identity1, 1));
  LServer := NewServer(TArray<TTls12Psk>.Create(Psk(Identity1, 1)));
  RunHandshake(LClient, LServer);
  LInfo := LServer.ConnectionInfo;
  LInfo.PskIdentity[0] := Byte(Ord('X'));
  CheckEqualBytes('the engine keeps its own copy', BytesOf(Identity1),
    LServer.ConnectionInfo.PskIdentity);
end;

procedure TTestTls12Psk.TestServerWithoutPsksNeverSelectsAPskSuite;
var
  LRegistry: ICipherSuiteRegistryBuilder;
  LSuite: TTlsCipherSuite;
  LClient, LServer: ITlsEngine;
begin
  // a registry that holds PSK suites is not a PSK: with no key configured the server selects a
  // certificate suite
  LRegistry := TCipherSuiteRegistry.CreateDualVersion(Crypto).ToBuilder;
  for LSuite in TCipherSuiteRegistry.CreateTls12Psk(Crypto).Items do
    LRegistry.Add(LSuite);
  LClient := TTlsEngineFactory.CreateClientEngine(TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithSupportedVersions(Only12)
    .WithServerVerification(
      TServerVerification.WebPki(TTlsLibTestCertificates.EcP256RootStore).Build)
    .Tls12.WithPreSharedKey(Psk(Identity1, 1)).WithPreSharedKeyRequired(False).Build, ServerHost);
  LServer := TTlsEngineFactory.CreateServerEngine(TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithSupportedVersions(Only12).WithCipherSuites(LRegistry.Build).WithCredential(ServerCredential).Build);
  RunHandshake(LClient, LServer);
  CheckFalse(LClient.IsTerminal or LServer.IsTerminal, 'the handshake completed');
  CheckEquals(0, System.Length(LServer.ConnectionInfo.PskIdentity), 'by certificate, not PSK');
  CheckTrue(System.Length(LClient.ConnectionInfo.PeerCertificates) > 0, 'a certificate was sent');
end;

procedure TTestTls12Psk.TestClientRefusesACertificateUnderAPskSuite;
var
  LClient, LServer: ITlsEngine;
  LFlight: TBytes;
begin
  LClient := NewClient(Psk(Identity1, 1));
  LServer := NewServer(TArray<TTls12Psk>.Create(Psk(Identity1, 1)));
  LClient.StartHandshake;
  Pump(LClient, LServer);
  LFlight := Drain(LServer);
  // ServerHello, then an unsolicited Certificate before the ServerKeyExchange (RFC 4279 2)
  Feed(LClient, Splice(LFlight, 0, THandshakeFraming.Frame(TTlsHandshakeType.Certificate,
    THandshakeMessages.EncodeCertificate12(nil))));
  CheckTrue(LClient.IsTerminal, 'the client aborted');
  CheckEquals(Int64(Ord(TTlsAlertDescription.UnexpectedMessage)),
    Int64(Ord(LClient.LastError.Alert.Description)), 'with unexpected_message');
end;

procedure TTestTls12Psk.TestClientRefusesACertificateRequestUnderAPskSuite;
var
  LClient, LServer: ITlsEngine;
  LFlight: TBytes;
  LRequest: TTlsCertificateRequest12;
begin
  LClient := NewClient(Psk(Identity1, 1));
  LServer := NewServer(TArray<TTls12Psk>.Create(Psk(Identity1, 1)));
  LClient.StartHandshake;
  Pump(LClient, LServer);
  LFlight := Drain(LServer);
  LRequest.CertificateTypes := TBytes.Create(64);
  LRequest.SupportedSignatureAlgorithms := TArray<UInt16>.Create(TSignatureSchemes.EcdsaSecp256r1Sha256);
  LRequest.CertificateAuthorities := nil;
  // ServerHello, ServerKeyExchange, then a CertificateRequest before the ServerHelloDone
  Feed(LClient, Splice(LFlight, 1, THandshakeFraming.Frame(TTlsHandshakeType.CertificateRequest,
    THandshakeMessages.EncodeCertificateRequest12(LRequest))));
  CheckTrue(LClient.IsTerminal, 'the client aborted');
  CheckEquals(Int64(Ord(TTlsAlertDescription.UnexpectedMessage)),
    Int64(Ord(LClient.LastError.Alert.Description)), 'with unexpected_message');
end;

procedure TTestTls12Psk.TestBuilderRefusals;
var
  LEmptyIdentity, LEmptySecret: TTls12Psk;
  LRefused: Boolean;
  LOnly13, LBoth: TArray<UInt16>;
begin
  LEmptyIdentity.Identity := nil;
  LEmptyIdentity.Secret := TSecretBuffer.From(TBytes.Create(1));
  LEmptySecret.Identity := BytesOf(Identity1);
  LEmptySecret.Secret := TSecretBuffer.From(nil);
  LRefused := False;
  try
    TTlsPresets.Compatible(Crypto, Pkix).Client.Tls12.WithPreSharedKey(LEmptyIdentity);
  except
    on E: EArgumentTlsLibException do
      LRefused := True;
  end;
  CheckTrue(LRefused, 'an empty identity is refused');
  LRefused := False;
  try
    TTlsPresets.Compatible(Crypto, Pkix).Client.Tls12.WithPreSharedKey(LEmptySecret);
  except
    on E: EArgumentTlsLibException do
      LRefused := True;
  end;
  CheckTrue(LRefused, 'an empty secret is refused');
  LRefused := False;
  try
    TTlsPresets.Compatible(Crypto, Pkix).Server.Tls12.WithPreSharedKeys(
      TArray<TTls12Psk>.Create(Psk(Identity1, 1), Psk(Identity1, 2)));
  except
    on E: EArgumentTlsLibException do
      LRefused := True;
  end;
  CheckTrue(LRefused, 'a repeated identity is refused');

  LOnly13 := TArray<UInt16>.Create(TlsWireVersionTls13);
  LBoth := TArray<UInt16>.Create(TlsWireVersionTls13, TlsWireVersionTls12);
  CheckTrue(ClientRefused(TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithSupportedVersions(LOnly13)
    .WithServerVerification(
      TServerVerification.WebPki(TTlsLibTestCertificates.EcP256RootStore).Build)
    .Tls12.WithPreSharedKey(Psk(Identity1, 1))), 'a TLS 1.2 PSK without TLS 1.2 offered');
  CheckTrue(ClientRefused(TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithSupportedVersions(LBoth).Tls12.WithPreSharedKey(Psk(Identity1, 1))),
    'a PSK-only client offering TLS 1.3 with no TLS 1.3 key');
  CheckTrue(ServerRefused(TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithSupportedVersions(LBoth).Tls12.WithPreSharedKeys(
    TArray<TTls12Psk>.Create(Psk(Identity1, 1)))),
    'a certificate-less server offering TLS 1.3 with no TLS 1.3 key');
  CheckTrue(ClientRefused(TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithSupportedVersions(Only12)
    .WithCipherSuiteList(TArray<UInt16>.Create(TCipherSuites12.EcdheEcdsaAes128GcmSha256))
    .Tls12.WithPreSharedKey(Psk(Identity1, 1))),
    'a cipher-suite list that names no PSK suite');
end;

procedure TTestTls12Psk.TestIdentityBeyondTheWireLimitIsRefused;
var
  LPsk: TTls12Psk;
  LRefused: Boolean;
begin
  // RFC 4279 2: the identity is opaque psk_identity<0..2^16-1>
  System.SetLength(LPsk.Identity, 65536);
  LPsk.Secret := TSecretBuffer.From(TBytes.Create(1));
  LRefused := False;
  try
    TTlsPresets.Compatible(Crypto, Pkix).Client.Tls12.WithPreSharedKey(LPsk);
  except
    on E: EArgumentTlsLibException do
      LRefused := True;
  end;
  CheckTrue(LRefused, 'a 65536-byte TLS 1.2 PSK identity is refused');
end;

procedure TTestTls12Psk.TestSecretBeyondTheWireLimitIsRefused;
var
  LPsk: TTls12Psk;
  LSecret: TBytes;
  LRefused: Boolean;
begin
  // RFC 4279 2: the secret is opaque psk<0..2^16-1>
  LPsk.Identity := BytesOf(Identity1);
  System.SetLength(LSecret, 65536);
  LPsk.Secret := TSecretBuffer.From(LSecret);
  LRefused := False;
  try
    TTlsPresets.Compatible(Crypto, Pkix).Client.Tls12.WithPreSharedKey(LPsk);
  except
    on E: EArgumentTlsLibException do
      LRefused := True;
  end;
  CheckTrue(LRefused, 'a 65536-byte TLS 1.2 PSK secret is refused');
end;

procedure TTestTls12Psk.TestSecretAtTheWireLimitIsAccepted;
var
  LPsk: TTls12Psk;
  LSecret: TBytes;
  LRefused: Boolean;
begin
  LPsk.Identity := BytesOf(Identity1);
  System.SetLength(LSecret, 65535);
  LPsk.Secret := TSecretBuffer.From(LSecret);
  LRefused := False;
  try
    TTlsPresets.Compatible(Crypto, Pkix).Client.Tls12.WithPreSharedKey(LPsk);
  except
    on E: EArgumentTlsLibException do
      LRefused := True;
  end;
  CheckFalse(LRefused, 'a 65535-byte secret passes the setter');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestTls12Psk);
{$ELSE}
  RegisterTest(TTestTls12Psk.Suite);
{$ENDIF FPC}

end.
