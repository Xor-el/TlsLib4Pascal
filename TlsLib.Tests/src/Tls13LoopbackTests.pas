{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit Tls13LoopbackTests;

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
  TlpTlsAlert,
  TlpICryptoProvider,
  TlpNamedGroups,
  TlpNegotiationTypes,
  TlpNegotiationPolicy,
  TlpCipherSuiteRegistry,
  TlpCoreExtensions,
  TlpITlsEngine,
  TlpTlsEngine,
  TlpIHandshakeMachine,
  TlpICertificateTrust,
  TlpCertificateVerifier,
  TlpCertificateLimits,
  TlpTrustPolicy,
  TlpSecretBuffer,
  TlpTlsCredential,
  TlpCredentialResolvers,
  TlpITlsCredentialResolver,
  TlpTls13ClientStateMachine,
  TlpTls13ServerStateMachine,
  TlsLibTestBase;

type
  TTestTls13Loopback = class(TTlsLibAlgorithmTestCase)
  private
    function Filled(AByte: Byte; ACount: Int32): TBytes;
    function TestRootCertificate: TBytes;
    function ServerCredential: TTlsCredential;
    function WrongNameCredential: TTlsCredential;
    function NewClient: ITlsEngine;
    function NewClientForSni(const ASni, AExpectedHost: string): ITlsEngine;
    function NewServer: ITlsEngine;
    function NewServerWithResolver(
      const AResolver: ITlsServerCredentialResolver): ITlsEngine;
    function NewHrrClient: ITlsEngine;
    function NewHrrServer: ITlsEngine;
    function NewP256OnlyClient: ITlsEngine;
    function NewMultiGroupServer: ITlsEngine;
    function NewHybridClient: ITlsEngine;
    function NewHybridServer: ITlsEngine;
    function NewHybridHrrClient: ITlsEngine;
    function NewHybridHrrServer: ITlsEngine;
    function CountHelloRetryRequests(const AWire: TBytes): Int32;
    function DriveCountingHrr(const AClient, AServer: ITlsEngine): Int32;
    function OcspField(const AName: string): TBytes;
    function NewStaplingServer(const AStaple: TBytes): ITlsEngine;
    function NewHardRevocationClient: ITlsEngine;
    function Drain(const AEngine: ITlsEngine): TBytes;
    procedure Feed(const AEngine: ITlsEngine; const AWire: TBytes);
    procedure FeedCoalesced(const AEngine: ITlsEngine; const AWire: TBytes);
    procedure Pump(const ASrc, ADst: ITlsEngine);
    procedure PumpCoalesced(const ASrc, ADst: ITlsEngine);
    function ReadAllApp(const AEngine: ITlsEngine): TBytes;
  published
    procedure TestClientServerLoopbackReachesApplicationData;
    procedure TestHelloRetryRequestRoundTrip;
    procedure TestHybridDirectHandshakeNegotiates4588;
    procedure TestHybridHrrHandshakeNegotiates4588;
    procedure TestMultiGroupServerSelectsClientGroupWithoutHrr;
    procedure TestCoalescedCrossEpochFlightCompletes;
    procedure TestAppDataAcrossRecordsChunkedReads;
    procedure TestUnexpectedMessageAbortsWithUnexpectedMessage;
    procedure TestMiddleboxChangeCipherSpecIgnored;
    procedure TestStapledGoodOcspCompletesUnderHardPosture;
    procedure TestMissingStapleAbortsUnderHardPosture;
    procedure TestSniSelectsHostCredentialAmongMany;
    procedure TestUnknownSniWithoutDefaultAbortsUnrecognizedName;
    procedure TestSniResolverMatchingMatrix;
  end;

implementation

{ TTestTls13Loopback }

function TTestTls13Loopback.Filled(AByte: Byte; ACount: Int32): TBytes;
var
  LI: Int32;
begin
  Result := nil;
  SetLength(Result, ACount);
  for LI := 0 to ACount - 1 do
    Result[LI] := AByte;
end;

function TTestTls13Loopback.NewClient: ITlsEngine;
begin
  // no SNI on the wire; the leaf is name-checked against localhost
  Result := NewClientForSni('', 'localhost');
end;

function TTestTls13Loopback.NewClientForSni(const ASni,
  AExpectedHost: string): ITlsEngine;
var
  LParams: TClientHandshakeParams;
begin
  LParams := Default(TClientHandshakeParams);
  LParams.Clock := TSystemClock.Create;
  LParams.Provider := Provider;
  LParams.Group := TNamedGroups.CreateX25519(Provider);
  LParams.GroupCode := TNamedGroupCatalog.X25519;
  LParams.CipherSuites := TCipherSuiteRegistry.CreateDefault(Provider);
  LParams.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  // offering a single suite makes the server's choice unambiguous on any CPU
  LParams.OfferedSuites := TArray<UInt16>.Create(TCipherSuites13.Aes128GcmSha256);
  LParams.OfferedSchemes := TArray<UInt16>.Create(TSignatureSchemes.EcdsaSecp256r1Sha256);
  LParams.ClientRandom := Filled($11, 32);
  LParams.LegacySessionId := Filled($33, 32);
  // ServerName is the SNI sent on the wire; ExpectedHostName is the name the leaf is checked against
  LParams.ServerName := ASni;
  LParams.CertificateVerifier := TCertificateVerifier.Create(Provider, TSystemClock.Create as ITlsClock,
    TTrustAnchorStore.Create(TArray<TBytes>.Create(TestRootCertificate)) as ITrustAnchorStore,
    True) as ICertificateVerifier;
  LParams.ExpectedHostName := AExpectedHost;

  Result := TTlsEngine.CreateConfigured(
    TTls13ClientStateMachine.Create(LParams) as IHandshakeMachine, Provider);
end;

function TTestTls13Loopback.TestRootCertificate: TBytes;
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

function TTestTls13Loopback.ServerCredential: TTlsCredential;
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

function TTestTls13Loopback.WrongNameCredential: TTlsCredential;
var
  LCerts: TStringList;
begin
  // the wrongname leaf carries SAN=other.example; it is paired here with the localhost key
  // purely as an opaque decoy entry - a localhost client never selects it, so the mismatched
  // key is never used to sign
  LCerts := LoadVectorFields('Certs/EcP256Chain.txt');
  try
    Result.CertificateChain := TArray<TBytes>.Create(
      DecodeHex(LCerts.Values['wrongname_cert']));
    Result.PrivateKey := Provider.ImportSigningKey(DecodeHex(LCerts.Values['leaf_key']));
  finally
    LCerts.Free;
  end;
end;

function TTestTls13Loopback.NewServer: ITlsEngine;
begin
  Result := NewServerWithResolver(TSniCredentialResolver.ForCredential(ServerCredential));
end;

function TTestTls13Loopback.NewServerWithResolver(
  const AResolver: ITlsServerCredentialResolver): ITlsEngine;
var
  LParams: TServerHandshakeParams;
begin
  LParams := Default(TServerHandshakeParams);
  LParams.Clock := TSystemClock.Create;
  LParams.Provider := Provider;
  LParams.Policy := TNegotiationPolicy.CreateDefault(Provider);
  LParams.CipherSuites := TCipherSuiteRegistry.CreateDefault(Provider);
  LParams.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  LParams.Group := TNamedGroups.CreateX25519(Provider);
  LParams.ServerRandom := Filled($22, 32);
  // the machine serializes EncryptedExtensions itself; the Certificate +
  // CertificateVerify are produced and signed from the credential the resolver picks by SNI
  LParams.CredentialResolver := AResolver;

  Result := TTlsEngine.CreateConfigured(
    TTls13ServerStateMachine.Create(LParams) as IHandshakeMachine, Provider);
end;

function TTestTls13Loopback.OcspField(const AName: string): TBytes;
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

function TTestTls13Loopback.NewStaplingServer(const AStaple: TBytes): ITlsEngine;
var
  LParams: TServerHandshakeParams;
  LCred: TTlsCredential;
begin
  LParams := Default(TServerHandshakeParams);
  LParams.Clock := TSystemClock.Create;
  LParams.Provider := Provider;
  LParams.Policy := TNegotiationPolicy.CreateDefault(Provider);
  LParams.CipherSuites := TCipherSuiteRegistry.CreateDefault(Provider);
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
    TTls13ServerStateMachine.Create(LParams) as IHandshakeMachine, Provider);
end;

function TTestTls13Loopback.NewHardRevocationClient: ITlsEngine;
var
  LParams: TClientHandshakeParams;
begin
  LParams := Default(TClientHandshakeParams);
  LParams.Clock := TSystemClock.Create;
  LParams.Provider := Provider;
  LParams.Group := TNamedGroups.CreateX25519(Provider);
  LParams.GroupCode := TNamedGroupCatalog.X25519;
  LParams.CipherSuites := TCipherSuiteRegistry.CreateDefault(Provider);
  LParams.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  LParams.OfferedSuites := TArray<UInt16>.Create(TCipherSuites13.Aes128GcmSha256);
  LParams.OfferedSchemes := TArray<UInt16>.Create(TSignatureSchemes.EcdsaSecp256r1Sha256);
  LParams.ClientRandom := Filled($11, 32);
  LParams.LegacySessionId := Filled($33, 32);
  // hard-fail revocation: the leaf must come with a current Good stapled OCSP response, so
  // the client offers status_request to solicit the staple
  LParams.RequestOcspStapling := True;
  LParams.CertificateVerifier := TCertificateVerifier.Create(Provider, TSystemClock.Create as ITlsClock,
    TTrustAnchorStore.Create(TArray<TBytes>.Create(OcspField('root_cert')))
    as ITrustAnchorStore, True, TCertificateChainLimits.Defaults,
    TRevocationPosture.Hard) as ICertificateVerifier;
  LParams.ExpectedHostName := 'localhost';

  Result := TTlsEngine.CreateConfigured(
    TTls13ClientStateMachine.Create(LParams) as IHandshakeMachine, Provider);
end;

function TTestTls13Loopback.NewHrrClient: ITlsEngine;
var
  LParams: TClientHandshakeParams;
begin
  LParams := Default(TClientHandshakeParams);
  LParams.Clock := TSystemClock.Create;
  LParams.Provider := Provider;
  // key-shares X25519 but advertises secp256r1 too, so the secp256r1-only server
  // retries the client onto secp256r1
  LParams.Group := TNamedGroups.CreateX25519(Provider);
  LParams.GroupCode := TNamedGroupCatalog.X25519;
  LParams.OfferedGroups := TArray<UInt16>.Create(TNamedGroupCatalog.Secp256r1,
    TNamedGroupCatalog.X25519);
  LParams.GroupRegistry := TNamedGroups.CreateDefaultRegistry(Provider);
  LParams.CipherSuites := TCipherSuiteRegistry.CreateDefault(Provider);
  LParams.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  LParams.OfferedSuites := TArray<UInt16>.Create(TCipherSuites13.Aes128GcmSha256);
  LParams.OfferedSchemes := TArray<UInt16>.Create(TSignatureSchemes.EcdsaSecp256r1Sha256);
  LParams.ClientRandom := Filled($11, 32);
  LParams.LegacySessionId := Filled($33, 32);
  LParams.CertificateVerifier := TCertificateVerifier.Create(Provider, TSystemClock.Create as ITlsClock,
    TTrustAnchorStore.Create(TArray<TBytes>.Create(TestRootCertificate)) as ITrustAnchorStore,
    True) as ICertificateVerifier;
  LParams.ExpectedHostName := 'localhost';

  Result := TTlsEngine.CreateConfigured(
    TTls13ClientStateMachine.Create(LParams) as IHandshakeMachine, Provider);
end;

function TTestTls13Loopback.NewHrrServer: ITlsEngine;
var
  LParams: TServerHandshakeParams;
begin
  LParams := Default(TServerHandshakeParams);
  LParams.Clock := TSystemClock.Create;
  LParams.Provider := Provider;
  LParams.Policy := TNegotiationPolicy.CreateDefault(Provider);
  LParams.CipherSuites := TCipherSuiteRegistry.CreateDefault(Provider);
  LParams.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  // the server offers only secp256r1; a client that key-shared another group is retried
  LParams.Group := TNamedGroups.CreateNistEcdh(Provider, 'secp256r1');
  LParams.ServerRandom := Filled($22, 32);
  LParams.CookieSecret := TSecretBuffer.From(Provider.GetRandom.GenerateBytes(32));
  LParams.CredentialResolver := TSniCredentialResolver.ForCredential(ServerCredential);

  Result := TTlsEngine.CreateConfigured(
    TTls13ServerStateMachine.Create(LParams) as IHandshakeMachine, Provider);
end;

function TTestTls13Loopback.NewP256OnlyClient: ITlsEngine;
var
  LParams: TClientHandshakeParams;
begin
  LParams := Default(TClientHandshakeParams);
  LParams.Clock := TSystemClock.Create;
  LParams.Provider := Provider;
  // a client that key-shares secp256r1 and lists ONLY secp256r1 (like a JDK 11 client that
  // omits X25519); the server must select secp256r1 rather than insisting on X25519
  LParams.Group := TNamedGroups.CreateNistEcdh(Provider, 'secp256r1');
  LParams.GroupCode := TNamedGroupCatalog.Secp256r1;
  LParams.OfferedGroups := TArray<UInt16>.Create(TNamedGroupCatalog.Secp256r1);
  LParams.GroupRegistry := TNamedGroups.CreateDefaultRegistry(Provider);
  LParams.CipherSuites := TCipherSuiteRegistry.CreateDefault(Provider);
  LParams.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  LParams.OfferedSuites := TArray<UInt16>.Create(TCipherSuites13.Aes128GcmSha256);
  LParams.OfferedSchemes := TArray<UInt16>.Create(TSignatureSchemes.EcdsaSecp256r1Sha256);
  LParams.ClientRandom := Filled($11, 32);
  LParams.LegacySessionId := Filled($33, 32);
  LParams.CertificateVerifier := TCertificateVerifier.Create(Provider, TSystemClock.Create as ITlsClock,
    TTrustAnchorStore.Create(TArray<TBytes>.Create(TestRootCertificate)) as ITrustAnchorStore,
    True) as ICertificateVerifier;
  LParams.ExpectedHostName := 'localhost';

  Result := TTlsEngine.CreateConfigured(
    TTls13ClientStateMachine.Create(LParams) as IHandshakeMachine, Provider);
end;

function TTestTls13Loopback.NewMultiGroupServer: ITlsEngine;
var
  LParams: TServerHandshakeParams;
begin
  LParams := Default(TServerHandshakeParams);
  LParams.Clock := TSystemClock.Create;
  LParams.Provider := Provider;
  LParams.Policy := TNegotiationPolicy.CreateDefault(Provider);
  LParams.CipherSuites := TCipherSuiteRegistry.CreateDefault(Provider);
  LParams.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  // the server offers X25519 first, then secp256r1; a client that omits X25519 negotiates
  // secp256r1 (mandatory to implement, RFC 8446 9.1) without a HelloRetryRequest
  LParams.OfferedGroups := TArray<UInt16>.Create(TNamedGroupCatalog.X25519,
    TNamedGroupCatalog.Secp256r1);
  LParams.GroupRegistry := TNamedGroups.CreateDefaultRegistry(Provider);
  LParams.ServerRandom := Filled($22, 32);
  // a cookie secret lets it answer with a HelloRetryRequest if it ever needed to (it must not)
  LParams.CookieSecret := TSecretBuffer.From(Provider.GetRandom.GenerateBytes(32));
  LParams.CredentialResolver := TSniCredentialResolver.ForCredential(ServerCredential);

  Result := TTlsEngine.CreateConfigured(
    TTls13ServerStateMachine.Create(LParams) as IHandshakeMachine, Provider);
end;

function TTestTls13Loopback.NewHybridClient: ITlsEngine;
var
  LParams: TClientHandshakeParams;
begin
  LParams := Default(TClientHandshakeParams);
  LParams.Clock := TSystemClock.Create;
  LParams.Provider := Provider;
  // key-share the X25519MLKEM768 hybrid directly: a large (X25519 32 + ML-KEM
  // encaps-key 1184 = 1216 B) key_share, ML-KEM-first on the wire
  LParams.Group := TNamedGroups.CreateX25519MlKem768(Provider);
  LParams.GroupCode := TNamedGroupCatalog.X25519MlKem768;
  LParams.CipherSuites := TCipherSuiteRegistry.CreateDefault(Provider);
  LParams.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  LParams.OfferedSuites := TArray<UInt16>.Create(TCipherSuites13.Aes128GcmSha256);
  LParams.OfferedSchemes := TArray<UInt16>.Create(TSignatureSchemes.EcdsaSecp256r1Sha256);
  LParams.ClientRandom := Filled($11, 32);
  LParams.LegacySessionId := Filled($33, 32);
  LParams.CertificateVerifier := TCertificateVerifier.Create(Provider, TSystemClock.Create as ITlsClock,
    TTrustAnchorStore.Create(TArray<TBytes>.Create(TestRootCertificate)) as ITrustAnchorStore,
    True) as ICertificateVerifier;
  LParams.ExpectedHostName := 'localhost';

  Result := TTlsEngine.CreateConfigured(
    TTls13ClientStateMachine.Create(LParams) as IHandshakeMachine, Provider);
end;

function TTestTls13Loopback.NewHybridServer: ITlsEngine;
var
  LParams: TServerHandshakeParams;
begin
  LParams := Default(TServerHandshakeParams);
  LParams.Clock := TSystemClock.Create;
  LParams.Provider := Provider;
  LParams.Policy := TNegotiationPolicy.CreateDefault(Provider);
  LParams.CipherSuites := TCipherSuiteRegistry.CreateDefault(Provider);
  LParams.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  LParams.Group := TNamedGroups.CreateX25519MlKem768(Provider);
  LParams.ServerRandom := Filled($22, 32);
  LParams.CredentialResolver := TSniCredentialResolver.ForCredential(ServerCredential);

  Result := TTlsEngine.CreateConfigured(
    TTls13ServerStateMachine.Create(LParams) as IHandshakeMachine, Provider);
end;

function TTestTls13Loopback.NewHybridHrrClient: ITlsEngine;
var
  LParams: TClientHandshakeParams;
begin
  LParams := Default(TClientHandshakeParams);
  LParams.Clock := TSystemClock.Create;
  LParams.Provider := Provider;
  // offers [X25519, X25519MLKEM768] but key-shares the classical X25519 first, so a
  // hybrid-only server retries the client onto X25519MLKEM768 (the Compatible-preset path)
  LParams.Group := TNamedGroups.CreateX25519(Provider);
  LParams.GroupCode := TNamedGroupCatalog.X25519;
  LParams.OfferedGroups := TArray<UInt16>.Create(TNamedGroupCatalog.X25519,
    TNamedGroupCatalog.X25519MlKem768);
  LParams.GroupRegistry := TNamedGroups.CreateDefaultRegistry(Provider);
  LParams.CipherSuites := TCipherSuiteRegistry.CreateDefault(Provider);
  LParams.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  LParams.OfferedSuites := TArray<UInt16>.Create(TCipherSuites13.Aes128GcmSha256);
  LParams.OfferedSchemes := TArray<UInt16>.Create(TSignatureSchemes.EcdsaSecp256r1Sha256);
  LParams.ClientRandom := Filled($11, 32);
  LParams.LegacySessionId := Filled($33, 32);
  LParams.CertificateVerifier := TCertificateVerifier.Create(Provider, TSystemClock.Create as ITlsClock,
    TTrustAnchorStore.Create(TArray<TBytes>.Create(TestRootCertificate)) as ITrustAnchorStore,
    True) as ICertificateVerifier;
  LParams.ExpectedHostName := 'localhost';

  Result := TTlsEngine.CreateConfigured(
    TTls13ClientStateMachine.Create(LParams) as IHandshakeMachine, Provider);
end;

function TTestTls13Loopback.NewHybridHrrServer: ITlsEngine;
var
  LParams: TServerHandshakeParams;
begin
  LParams := Default(TServerHandshakeParams);
  LParams.Clock := TSystemClock.Create;
  LParams.Provider := Provider;
  LParams.Policy := TNegotiationPolicy.CreateDefault(Provider);
  LParams.CipherSuites := TCipherSuiteRegistry.CreateDefault(Provider);
  LParams.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  // the server offers only the hybrid; a client that key-shared a classical group is retried
  LParams.Group := TNamedGroups.CreateX25519MlKem768(Provider);
  LParams.ServerRandom := Filled($22, 32);
  LParams.CookieSecret := TSecretBuffer.From(Provider.GetRandom.GenerateBytes(32));
  LParams.CredentialResolver := TSniCredentialResolver.ForCredential(ServerCredential);

  Result := TTlsEngine.CreateConfigured(
    TTls13ServerStateMachine.Create(LParams) as IHandshakeMachine, Provider);
end;

function TTestTls13Loopback.CountHelloRetryRequests(const AWire: TBytes): Int32;
var
  LI, LJ, LN: Int32;
  LMatch: Boolean;
begin
  // a HelloRetryRequest is a ServerHello whose random is the fixed HRR sentinel
  // (RFC 8446 4.1.3); the 32-byte sentinel is unique enough to scan for directly
  Result := 0;
  LN := System.Length(HelloRetryRequestSentinel);
  LI := 0;
  while LI <= System.Length(AWire) - LN do
  begin
    LMatch := True;
    for LJ := 0 to LN - 1 do
      if AWire[LI + LJ] <> HelloRetryRequestSentinel[LJ] then
      begin
        LMatch := False;
        Break;
      end;
    if LMatch then
    begin
      Inc(Result);
      Inc(LI, LN);
    end
    else
      Inc(LI);
  end;
end;

function TTestTls13Loopback.DriveCountingHrr(const AClient, AServer: ITlsEngine): Int32;
var
  LIterations: Int32;
  LFromServer: TBytes;
begin
  // drive the handshake to completion, counting the HelloRetryRequests the server emits
  Result := 0;
  LIterations := 0;
  while (AClient.IsHandshaking or AServer.IsHandshaking) and (LIterations < 16) do
  begin
    Pump(AClient, AServer);
    LFromServer := Drain(AServer);
    Inc(Result, CountHelloRetryRequests(LFromServer));
    Feed(AClient, LFromServer);
    Inc(LIterations);
  end;
end;

procedure TTestTls13Loopback.TestMultiGroupServerSelectsClientGroupWithoutHrr;
var
  LClient, LServer: ITlsEngine;
  LIterations: Int32;
  LFromClient: TBytes;
begin
  LClient := NewP256OnlyClient;
  LServer := NewMultiGroupServer;

  LClient.StartHandshake;

  // the client key-shared secp256r1 (its only group); the server, though it prefers X25519,
  // selects secp256r1 because the client offered it - and, since the client already sent that
  // key_share, without a HelloRetryRequest. A single direct exchange completes the handshake.
  LIterations := 0;
  while (LClient.IsHandshaking or LServer.IsHandshaking) and (LIterations < 16) do
  begin
    Pump(LClient, LServer);
    Pump(LServer, LClient);
    Inc(LIterations);
  end;

  CheckFalse(LClient.IsHandshaking, 'the client completed the handshake');
  CheckFalse(LServer.IsHandshaking, 'the server completed the handshake');
  CheckFalse(LClient.IsTerminal, 'the client did not fail (secp256r1 was negotiated)');
  CheckFalse(LServer.IsTerminal, 'the server did not fail');
  // a direct (no-retry) handshake needs only a couple of pump rounds; a spurious
  // HelloRetryRequest would take more
  CheckTrue(LIterations <= 3, 'the handshake completed without a HelloRetryRequest');

  LFromClient := DecodeHex('68656c6c6f206f766572207032353620776974686f75742061206872720a');
  LClient.Write(LFromClient, 0, System.Length(LFromClient));
  Pump(LClient, LServer);
  CheckEqualBytes('the server decrypts application data over the secp256r1 keys',
    LFromClient, ReadAllApp(LServer));
end;

function TTestTls13Loopback.Drain(const AEngine: ITlsEngine): TBytes;
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

procedure TTestTls13Loopback.Feed(const AEngine: ITlsEngine; const AWire: TBytes);
var
  LPos, LLen: Int32;
begin
  // deliver one record at a time so an epoch installed while processing one record
  // is active for the next (a coalesced feed cannot cross an epoch boundary)
  LPos := 0;
  while LPos + 5 <= System.Length(AWire) do
  begin
    LLen := (AWire[LPos + 3] shl 8) or AWire[LPos + 4];
    AEngine.ProcessInput(AWire, LPos, 5 + LLen);
    Inc(LPos, 5 + LLen);
  end;
end;

procedure TTestTls13Loopback.FeedCoalesced(const AEngine: ITlsEngine;
  const AWire: TBytes);
begin
  // deliver the whole flight in a single ProcessInput; a flight that changes epoch
  // mid-buffer (a plaintext ServerHello followed by the encrypted rest) must still
  // decode, because each record is decrypted under the epoch installed at pull time
  if System.Length(AWire) > 0 then
    AEngine.ProcessInput(AWire, 0, System.Length(AWire));
end;

procedure TTestTls13Loopback.Pump(const ASrc, ADst: ITlsEngine);
begin
  Feed(ADst, Drain(ASrc));
end;

procedure TTestTls13Loopback.PumpCoalesced(const ASrc, ADst: ITlsEngine);
begin
  FeedCoalesced(ADst, Drain(ASrc));
end;

function TTestTls13Loopback.ReadAllApp(const AEngine: ITlsEngine): TBytes;
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

procedure TTestTls13Loopback.TestClientServerLoopbackReachesApplicationData;
var
  LClient, LServer: ITlsEngine;
  LIterations: Int32;
  LFromClient, LFromServer: TBytes;
begin
  LClient := NewClient;
  LServer := NewServer;

  LClient.StartHandshake; // emits the ClientHello (and the middlebox CCS)

  LIterations := 0;
  while (LClient.IsHandshaking or LServer.IsHandshaking) and (LIterations < 16) do
  begin
    Pump(LClient, LServer);
    Pump(LServer, LClient);
    Inc(LIterations);
  end;

  CheckFalse(LClient.IsHandshaking, 'the client completed the handshake');
  CheckFalse(LServer.IsHandshaking, 'the server completed the handshake');
  CheckFalse(LClient.IsTerminal, 'the client did not fail');
  CheckFalse(LServer.IsTerminal, 'the server did not fail');

  // the negotiated application keys carry real data in both directions
  LFromClient := DecodeHex('68656c6c6f2066726f6d2074686520636c69656e74'); // "hello from the client"
  LClient.Write(LFromClient, 0, System.Length(LFromClient));
  Pump(LClient, LServer);
  CheckEqualBytes('the server decrypts the client application data', LFromClient,
    ReadAllApp(LServer));

  LFromServer := DecodeHex('68656c6c6f2066726f6d2074686520736572766572'); // "hello from the server"
  LServer.Write(LFromServer, 0, System.Length(LFromServer));
  Pump(LServer, LClient);
  CheckEqualBytes('the client decrypts the server application data', LFromServer,
    ReadAllApp(LClient));
end;

procedure TTestTls13Loopback.TestHelloRetryRequestRoundTrip;
var
  LClient, LServer: ITlsEngine;
  LIterations: Int32;
  LFromClient, LFromServer: TBytes;
begin
  LClient := NewHrrClient;
  LServer := NewHrrServer;

  LClient.StartHandshake;

  // the server answers ClientHello1 with a HelloRetryRequest (the client key-shared
  // X25519 but the server offers only secp256r1); the client retries onto secp256r1,
  // the server rebuilds the transcript from the cookie, and the handshake completes
  LIterations := 0;
  while (LClient.IsHandshaking or LServer.IsHandshaking) and (LIterations < 16) do
  begin
    Pump(LClient, LServer);
    Pump(LServer, LClient);
    Inc(LIterations);
  end;

  CheckFalse(LClient.IsHandshaking, 'the client completed after the retry');
  CheckFalse(LServer.IsHandshaking, 'the server completed after the retry');
  CheckFalse(LClient.IsTerminal, 'the client did not fail');
  CheckFalse(LServer.IsTerminal, 'the server did not fail');

  // real application data flows both ways over the negotiated secp256r1 keys
  LFromClient := DecodeHex('68656c6c6f2066726f6d2074686520636c69656e74');
  LClient.Write(LFromClient, 0, System.Length(LFromClient));
  Pump(LClient, LServer);
  CheckEqualBytes('the server decrypts client application data after a retry',
    LFromClient, ReadAllApp(LServer));

  LFromServer := DecodeHex('68656c6c6f2066726f6d2074686520736572766572');
  LServer.Write(LFromServer, 0, System.Length(LFromServer));
  Pump(LServer, LClient);
  CheckEqualBytes('the client decrypts server application data after a retry',
    LFromServer, ReadAllApp(LClient));
end;

procedure TTestTls13Loopback.TestHybridDirectHandshakeNegotiates4588;
var
  LClient, LServer: ITlsEngine;
  LHrr: Int32;
  LFromClient, LFromServer: TBytes;
begin
  LClient := NewHybridClient;
  LServer := NewHybridServer;

  LClient.StartHandshake;
  // both sides offer only the hybrid and the client key-shared it, so the server
  // selects X25519MLKEM768 in one round trip with no HelloRetryRequest
  LHrr := DriveCountingHrr(LClient, LServer);

  CheckFalse(LClient.IsHandshaking, 'the client completed the hybrid handshake');
  CheckFalse(LServer.IsHandshaking, 'the server completed the hybrid handshake');
  CheckFalse(LClient.IsTerminal, 'the client did not fail');
  CheckFalse(LServer.IsTerminal, 'the server did not fail');
  CheckEquals(0, LHrr, 'a direct hybrid handshake needs no HelloRetryRequest');
  CheckEquals(Integer(TNamedGroupCatalog.X25519MlKem768),
    Integer(LClient.NegotiatedGroup), 'the client negotiated X25519MLKEM768');
  CheckEquals(Integer(TNamedGroupCatalog.X25519MlKem768),
    Integer(LServer.NegotiatedGroup), 'the server negotiated X25519MLKEM768');

  LFromClient := DecodeHex('68656c6c6f2066726f6d2074686520636c69656e74');
  LClient.Write(LFromClient, 0, System.Length(LFromClient));
  Pump(LClient, LServer);
  CheckEqualBytes('the server decrypts client application data over the hybrid keys',
    LFromClient, ReadAllApp(LServer));

  LFromServer := DecodeHex('68656c6c6f2066726f6d2074686520736572766572');
  LServer.Write(LFromServer, 0, System.Length(LFromServer));
  Pump(LServer, LClient);
  CheckEqualBytes('the client decrypts server application data over the hybrid keys',
    LFromServer, ReadAllApp(LClient));
end;

procedure TTestTls13Loopback.TestHybridHrrHandshakeNegotiates4588;
var
  LClient, LServer: ITlsEngine;
  LHrr: Int32;
  LFromClient, LFromServer: TBytes;
begin
  LClient := NewHybridHrrClient;
  LServer := NewHybridHrrServer;

  LClient.StartHandshake;
  // the client key-shared X25519 but offered the hybrid too; the hybrid-only server sends
  // one HelloRetryRequest for 4588, the client resends with the hybrid key_share
  LHrr := DriveCountingHrr(LClient, LServer);

  CheckFalse(LClient.IsHandshaking, 'the client completed after the retry');
  CheckFalse(LServer.IsHandshaking, 'the server completed after the retry');
  CheckFalse(LClient.IsTerminal, 'the client did not fail');
  CheckFalse(LServer.IsTerminal, 'the server did not fail');
  CheckEquals(1, LHrr, 'exactly one HelloRetryRequest drove the client onto the hybrid');
  CheckEquals(Integer(TNamedGroupCatalog.X25519MlKem768),
    Integer(LClient.NegotiatedGroup), 'the client negotiated X25519MLKEM768 after the retry');
  CheckEquals(Integer(TNamedGroupCatalog.X25519MlKem768),
    Integer(LServer.NegotiatedGroup), 'the server negotiated X25519MLKEM768 after the retry');

  LFromClient := DecodeHex('68656c6c6f2066726f6d2074686520636c69656e74');
  LClient.Write(LFromClient, 0, System.Length(LFromClient));
  Pump(LClient, LServer);
  CheckEqualBytes('the server decrypts client application data after the hybrid retry',
    LFromClient, ReadAllApp(LServer));

  LFromServer := DecodeHex('68656c6c6f2066726f6d2074686520736572766572');
  LServer.Write(LFromServer, 0, System.Length(LFromServer));
  Pump(LServer, LClient);
  CheckEqualBytes('the client decrypts server application data after the hybrid retry',
    LFromServer, ReadAllApp(LClient));
end;

procedure TTestTls13Loopback.TestCoalescedCrossEpochFlightCompletes;
var
  LClient, LServer: ITlsEngine;
  LIterations: Int32;
  LFromClient, LFromServer: TBytes;
begin
  LClient := NewClient;
  LServer := NewServer;

  LClient.StartHandshake;

  // every flight is delivered coalesced (one ProcessInput per drain). The server's
  // first flight carries a plaintext ServerHello then the encrypted
  // EncryptedExtensions..Finished in one buffer; completing proves the read epoch
  // installed while handling ServerHello governs the records that follow it
  LIterations := 0;
  while (LClient.IsHandshaking or LServer.IsHandshaking) and (LIterations < 16) do
  begin
    PumpCoalesced(LClient, LServer);
    PumpCoalesced(LServer, LClient);
    Inc(LIterations);
  end;

  CheckFalse(LClient.IsHandshaking, 'the client completed the coalesced handshake');
  CheckFalse(LServer.IsHandshaking, 'the server completed the coalesced handshake');
  CheckFalse(LClient.IsTerminal, 'the client did not fail on the coalesced flight');
  CheckFalse(LServer.IsTerminal, 'the server did not fail on the coalesced flight');

  LFromClient := DecodeHex('68656c6c6f2066726f6d2074686520636c69656e74');
  LClient.Write(LFromClient, 0, System.Length(LFromClient));
  PumpCoalesced(LClient, LServer);
  CheckEqualBytes('the server decrypts client application data after a coalesced handshake',
    LFromClient, ReadAllApp(LServer));

  LFromServer := DecodeHex('68656c6c6f2066726f6d2074686520736572766572');
  LServer.Write(LFromServer, 0, System.Length(LFromServer));
  PumpCoalesced(LServer, LClient);
  CheckEqualBytes('the client decrypts server application data after a coalesced handshake',
    LFromServer, ReadAllApp(LClient));
end;

procedure TTestTls13Loopback.TestAppDataAcrossRecordsChunkedReads;
var
  LClient, LServer: ITlsEngine;
  LIterations, LGot: Int32;
  LMsg1, LMsg2, LMsg3, LExpected, LGotAll, LOne: TBytes;
begin
  LClient := NewClient;
  LServer := NewServer;
  LClient.StartHandshake;
  LIterations := 0;
  while (LClient.IsHandshaking or LServer.IsHandshaking) and (LIterations < 16) do
  begin
    Pump(LClient, LServer);
    Pump(LServer, LClient);
    Inc(LIterations);
  end;
  CheckFalse(LClient.IsHandshaking or LServer.IsHandshaking, 'the handshake completed');

  // three separate writes arrive as three application-data records => three queue
  // chunks on the server; reading one byte at a time must cross the chunk boundaries
  // and reassemble every record in order
  LMsg1 := DecodeHex('0102030405');
  LMsg2 := DecodeHex('060708');
  LMsg3 := DecodeHex('090a0b0c0d0e0f');
  LClient.Write(LMsg1, 0, System.Length(LMsg1));
  LClient.Write(LMsg2, 0, System.Length(LMsg2));
  LClient.Write(LMsg3, 0, System.Length(LMsg3));
  Pump(LClient, LServer);

  LExpected := ConcatBytes(ConcatBytes(LMsg1, LMsg2), LMsg3);
  LGotAll := nil;
  SetLength(LOne, 1);
  repeat
    LGot := LServer.ReadAppData(LOne, 0, 1);
    if LGot > 0 then
      LGotAll := ConcatBytes(LGotAll, System.Copy(LOne, 0, LGot));
  until LGot = 0;

  CheckEqualBytes('one-byte reads reassemble all records in order', LExpected, LGotAll);
end;

procedure TTestTls13Loopback.TestUnexpectedMessageAbortsWithUnexpectedMessage;
var
  LClient: ITlsEngine;
  LOutcome: TTlsOutcome;
  LFinishedRecord: TBytes;
begin
  LClient := NewClient;
  LClient.StartHandshake;
  Drain(LClient); // discard the ClientHello flight

  // a client awaiting the ServerHello instead receives a (plaintext) Finished
  LFinishedRecord := DecodeHex('16 03 03 00 24 14 00 00 20' + StringOfChar('0', 64));
  LOutcome := LClient.ProcessInput(LFinishedRecord, 0, System.Length(LFinishedRecord));

  CheckEquals(Ord(TTlsOutcome.Fatal), Ord(LOutcome), 'an out-of-order message is fatal');
  CheckTrue(LClient.IsTerminal, 'the engine is terminal');
  CheckEquals(Ord(TTlsAlertDescription.UnexpectedMessage),
    Ord(LClient.LastError.Alert.Description), 'it aborts with unexpected_message');
end;

procedure TTestTls13Loopback.TestMiddleboxChangeCipherSpecIgnored;
var
  LClient: ITlsEngine;
  LOutcome: TTlsOutcome;
begin
  LClient := NewClient;
  LClient.StartHandshake;
  Drain(LClient);

  // a bare change_cipher_spec arriving mid-handshake is dropped, not an error
  LOutcome := LClient.ProcessInput(DecodeHex('14 03 03 00 01 01'), 0, 6);

  CheckEquals(Ord(TTlsOutcome.NeedMoreInput), Ord(LOutcome),
    'the CCS produced nothing and the engine wants more input');
  CheckFalse(LClient.IsTerminal, 'the CCS did not fail the engine');
  CheckTrue(LClient.IsHandshaking, 'the client is still handshaking');
end;

procedure TTestTls13Loopback.TestStapledGoodOcspCompletesUnderHardPosture;
var
  LClient, LServer: ITlsEngine;
  LIterations: Int32;
begin
  // the server staples a current Good OCSP response in the leaf CertificateEntry, which a
  // hard-fail client requires (RFC 8446 4.4.2.1)
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

procedure TTestTls13Loopback.TestMissingStapleAbortsUnderHardPosture;
var
  LClient, LServer: ITlsEngine;
  LIterations: Int32;
begin
  // the same client, but the server staples nothing: hard-fail rejects the leaf
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

procedure TTestTls13Loopback.TestSniSelectsHostCredentialAmongMany;
var
  LClient, LServer: ITlsEngine;
  LEntries: TArray<TSniCredentialEntry>;
  LIterations: Int32;
  LPing: TBytes;
begin
  // a virtual-hosting server: 'localhost' -> the localhost leaf, 'other.example' -> a decoy.
  // A client that requests SNI 'localhost' must be served the localhost leaf (the decoy would
  // fail the client's name check), so a completed, name-verified handshake proves the resolver
  // selected by SNI rather than by config order (the decoy is listed first)
  SetLength(LEntries, 2);
  LEntries[0].Host := 'other.example';
  LEntries[0].Credential := WrongNameCredential;
  LEntries[1].Host := 'localhost';
  LEntries[1].Credential := ServerCredential;

  LClient := NewClientForSni('localhost', 'localhost');
  LServer := NewServerWithResolver(TSniCredentialResolver.ForEntries(LEntries));

  LClient.StartHandshake;
  LIterations := 0;
  while (LClient.IsHandshaking or LServer.IsHandshaking) and (LIterations < 16) do
  begin
    Pump(LClient, LServer);
    Pump(LServer, LClient);
    Inc(LIterations);
  end;

  CheckFalse(LClient.IsHandshaking, 'the client completed the handshake');
  CheckFalse(LClient.IsTerminal, 'the client accepted the localhost leaf it was served by SNI');
  CheckFalse(LServer.IsTerminal, 'the server completed the handshake');

  LPing := DecodeHex('70696e67'); // "ping"
  LClient.Write(LPing, 0, System.Length(LPing));
  Pump(LClient, LServer);
  CheckEqualBytes('application data flows over the SNI-selected credential', LPing,
    ReadAllApp(LServer));
end;

procedure TTestTls13Loopback.TestUnknownSniWithoutDefaultAbortsUnrecognizedName;
var
  LClient, LServer: ITlsEngine;
  LEntries: TArray<TSniCredentialEntry>;
  LIterations: Int32;
begin
  // the server knows only 'localhost' and has no default credential; a client requesting an
  // unknown host must be rejected with unrecognized_name(112) per RFC 6066 3, not served some
  // arbitrary certificate. This is the discriminator that proves the resolver gates on SNI
  SetLength(LEntries, 1);
  LEntries[0].Host := 'localhost';
  LEntries[0].Credential := ServerCredential;

  LClient := NewClientForSni('unknown.example', 'unknown.example');
  LServer := NewServerWithResolver(TSniCredentialResolver.ForEntries(LEntries));

  LClient.StartHandshake;
  LIterations := 0;
  while (LClient.IsHandshaking or LServer.IsHandshaking) and (LIterations < 16) do
  begin
    Pump(LClient, LServer);
    Pump(LServer, LClient);
    Inc(LIterations);
  end;

  CheckTrue(LServer.IsTerminal, 'the server aborted the unresolvable-SNI handshake');
  CheckEquals(Ord(TTlsAlertDescription.UnrecognizedName),
    Ord(LServer.LastError.Alert.Description),
    'the server aborts an unknown SNI with unrecognized_name(112)');
end;

procedure TTestTls13Loopback.TestSniResolverMatchingMatrix;
var
  LEntries: TArray<TSniCredentialEntry>;
  LExact, LWildcard, LDefault: TTlsCredential;
  LResolver: ITlsServerCredentialResolver;
  LHello: TTlsClientHelloInfo;
  LGot: TTlsCredential;

  function ResolveFor(const ASni: string; out ACred: TTlsCredential): Boolean;
  begin
    LHello := Default(TTlsClientHelloInfo);
    LHello.ServerName := ASni;
    Result := LResolver.TryResolve(LHello, ACred);
  end;

  function LeafOf(const ACred: TTlsCredential): TBytes;
  begin
    Result := ACred.CertificateChain[0];
  end;

begin
  // exercise the resolver's matching rules directly (no handshake): the credentials are opaque
  // payloads distinguished by their leaf bytes, so wildcard and case-folding are testable
  // without needing a certificate that actually carries those names
  LExact := ServerCredential;        // stands in for host.example.com
  LWildcard := WrongNameCredential;  // stands in for *.wild.example
  LDefault := Default(TTlsCredential);
  LDefault.CertificateChain := TArray<TBytes>.Create(TestRootCertificate);

  SetLength(LEntries, 2);
  LEntries[0].Host := 'host.example.com';
  LEntries[0].Credential := LExact;
  LEntries[1].Host := '*.wild.example';
  LEntries[1].Credential := LWildcard;
  LResolver := TSniCredentialResolver.Create(LEntries, True, LDefault);

  CheckTrue(ResolveFor('host.example.com', LGot), 'exact host resolves');
  CheckEqualBytes('exact host -> its credential', LeafOf(LExact), LeafOf(LGot));

  CheckTrue(ResolveFor('HOST.Example.COM', LGot), 'exact host is case-insensitive');
  CheckEqualBytes('case-folded exact host -> its credential', LeafOf(LExact), LeafOf(LGot));

  CheckTrue(ResolveFor('api.wild.example', LGot), 'single-label wildcard resolves');
  CheckEqualBytes('wildcard host -> its credential', LeafOf(LWildcard), LeafOf(LGot));

  CheckTrue(ResolveFor('deep.nested.wild.example', LGot),
    'a wildcard matches only one label but still resolves via the default');
  CheckEqualBytes('multi-label host falls through to the default', LeafOf(LDefault),
    LeafOf(LGot));

  CheckTrue(ResolveFor('', LGot), 'a no-SNI handshake resolves to the default');
  CheckEqualBytes('no SNI -> the default credential', LeafOf(LDefault), LeafOf(LGot));

  CheckTrue(ResolveFor('unrelated.example', LGot), 'an unmatched host resolves to the default');
  CheckEqualBytes('unmatched host -> the default credential', LeafOf(LDefault), LeafOf(LGot));
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestTls13Loopback);
{$ELSE}
  RegisterTest(TTestTls13Loopback.Suite);
{$ENDIF FPC}

end.
