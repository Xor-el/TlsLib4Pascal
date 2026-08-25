{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClientAuthTests;

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
  TlpTlsCredential,
  TlpCredentialResolvers,
  TlpTls13ClientStateMachine,
  TlpTls13ServerStateMachine,
  TlpTls12ClientStateMachine,
  TlpTls12ServerStateMachine,
  TlsLibTestBase;

type
  TTestClientAuth = class(TTlsLibAlgorithmTestCase)
  private
    function Filled(AByte: Byte; ACount: Int32): TBytes;
    function RootCert: TBytes;
    function Credential: TTlsCredential;
    function PeerVerifier: ICertificateVerifier;
    function New13Client(AWithCredential: Boolean): ITlsEngine;
    function New13Server(AMode: TClientAuthMode): ITlsEngine;
    function New12Client(AWithCredential: Boolean): ITlsEngine;
    function New12Server(AMode: TClientAuthMode): ITlsEngine;
    function Drain(const AEngine: ITlsEngine): TBytes;
    procedure Feed(const AEngine: ITlsEngine; const AWire: TBytes);
    procedure Pump(const ASrc, ADst: ITlsEngine);
    procedure Drive(const AClient, AServer: ITlsEngine);
  published
    procedure TestTls13RequiredClientAuthCompletes;
    procedure TestTls13RequiredClientAuthMissingCertAborts;
    procedure TestTls13RequestedClientAuthWithoutCertCompletes;
    procedure TestTls12RequiredClientAuthCompletes;
    procedure TestTls12RequiredClientAuthMissingCertAborts;
    procedure TestTls12RequestedClientAuthWithoutCertCompletes;
  end;

implementation

const
  EcdsaSecp256r1Sha256 = UInt16($0403);

{ TTestClientAuth }

function TTestClientAuth.Filled(AByte: Byte; ACount: Int32): TBytes;
var
  LI: Int32;
begin
  Result := nil;
  SetLength(Result, ACount);
  for LI := 0 to ACount - 1 do
    Result[LI] := AByte;
end;

function TTestClientAuth.RootCert: TBytes;
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

function TTestClientAuth.Credential: TTlsCredential;
var
  LCerts: TStringList;
begin
  LCerts := LoadVectorFields('Certs/EcP256Chain.txt');
  try
    Result.CertificateChain := TArray<TBytes>.Create(
      DecodeHex(LCerts.Values['leaf_cert']));
    Result.PrivateKey := Provider.Signing.ImportSigningKey(DecodeHex(LCerts.Values['leaf_key']));
  finally
    LCerts.Free;
  end;
end;

function TTestClientAuth.PeerVerifier: ICertificateVerifier;
begin
  // trusts the test root; hostname identity is not applied to a peer certificate
  Result := TCertificateVerifier.Create(Provider, TSystemClock.Create as ITlsClock,
    TTrustAnchorStore.Create(TArray<TBytes>.Create(RootCert)) as ITrustAnchorStore,
    False) as ICertificateVerifier;
end;

function TTestClientAuth.New13Client(AWithCredential: Boolean): ITlsEngine;
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
  LParams.OfferedSchemes := TArray<UInt16>.Create(EcdsaSecp256r1Sha256);
  LParams.ClientRandom := Filled($11, 32);
  LParams.LegacySessionId := Filled($33, 32);
  LParams.CertificateVerifier := PeerVerifier;
  LParams.ExpectedHostName := 'localhost';
  if AWithCredential then
    LParams.ClientCredential := Credential;
  Result := TTlsEngine.CreateConfigured(
    TTls13ClientStateMachine.Create(LParams) as IHandshakeMachine, Provider);
end;

function TTestClientAuth.New13Server(AMode: TClientAuthMode): ITlsEngine;
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
  LParams.CredentialResolver := TSniCredentialResolver.ForCredential(Credential);
  LParams.ClientAuth := AMode;
  LParams.ClientAuthSignatureSchemes := TArray<UInt16>.Create(EcdsaSecp256r1Sha256);
  LParams.ClientCertificateVerifier := PeerVerifier;
  Result := TTlsEngine.CreateConfigured(
    TTls13ServerStateMachine.Create(LParams) as IHandshakeMachine, Provider);
end;

function TTestClientAuth.New12Client(AWithCredential: Boolean): ITlsEngine;
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
  LParams.OfferedSchemes := TArray<UInt16>.Create(EcdsaSecp256r1Sha256);
  LParams.OfferedVersions := TArray<UInt16>.Create(TlsWireVersionTls12);
  LParams.ClientRandom := Filled($11, 32);
  LParams.OfferExtendedMasterSecret := True;
  LParams.CertificateVerifier := PeerVerifier;
  LParams.ExpectedHostName := 'localhost';
  if AWithCredential then
    LParams.ClientCredential := Credential;
  Result := TTlsEngine.CreateConfigured(
    TTls12ClientStateMachine.Create(LParams) as IHandshakeMachine, Provider);
end;

function TTestClientAuth.New12Server(AMode: TClientAuthMode): ITlsEngine;
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
  LParams.CredentialResolver := TSniCredentialResolver.ForCredential(Credential);
  LParams.ClientAuth := AMode;
  LParams.ClientAuthSignatureSchemes := TArray<UInt16>.Create(EcdsaSecp256r1Sha256);
  LParams.ClientCertificateVerifier := PeerVerifier;
  Result := TTlsEngine.CreateConfigured(
    TTls12ServerStateMachine.Create(LParams) as IHandshakeMachine, Provider);
end;

function TTestClientAuth.Drain(const AEngine: ITlsEngine): TBytes;
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

procedure TTestClientAuth.Feed(const AEngine: ITlsEngine; const AWire: TBytes);
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

procedure TTestClientAuth.Pump(const ASrc, ADst: ITlsEngine);
begin
  Feed(ADst, Drain(ASrc));
end;

procedure TTestClientAuth.Drive(const AClient, AServer: ITlsEngine);
var
  LIterations: Int32;
begin
  AClient.StartHandshake;
  LIterations := 0;
  while (AClient.IsHandshaking or AServer.IsHandshaking) and
    not AClient.IsTerminal and not AServer.IsTerminal and (LIterations < 16) do
  begin
    Pump(AClient, AServer);
    Pump(AServer, AClient);
    Inc(LIterations);
  end;
end;

procedure TTestClientAuth.TestTls13RequiredClientAuthCompletes;
var
  LClient, LServer: ITlsEngine;
begin
  LClient := New13Client(True);
  LServer := New13Server(TClientAuthMode.Required);
  Drive(LClient, LServer);
  CheckFalse(LClient.IsHandshaking, '1.3 mTLS: client completed');
  CheckFalse(LServer.IsHandshaking, '1.3 mTLS: server completed');
  CheckFalse(LClient.IsTerminal or LServer.IsTerminal, '1.3 mTLS: no failure');
end;

procedure TTestClientAuth.TestTls13RequiredClientAuthMissingCertAborts;
var
  LClient, LServer: ITlsEngine;
begin
  LClient := New13Client(False);
  LServer := New13Server(TClientAuthMode.Required);
  Drive(LClient, LServer);
  CheckTrue(LServer.IsTerminal, '1.3 required mTLS with no client cert fails closed');
end;

procedure TTestClientAuth.TestTls13RequestedClientAuthWithoutCertCompletes;
var
  LClient, LServer: ITlsEngine;
begin
  LClient := New13Client(False);
  LServer := New13Server(TClientAuthMode.Requested);
  Drive(LClient, LServer);
  CheckFalse(LClient.IsHandshaking or LServer.IsHandshaking,
    '1.3 requested mTLS completes without a client cert');
  CheckFalse(LClient.IsTerminal or LServer.IsTerminal, '1.3 requested mTLS: no failure');
end;

procedure TTestClientAuth.TestTls12RequiredClientAuthCompletes;
var
  LClient, LServer: ITlsEngine;
begin
  LClient := New12Client(True);
  LServer := New12Server(TClientAuthMode.Required);
  Drive(LClient, LServer);
  CheckFalse(LClient.IsHandshaking, '1.2 mTLS: client completed');
  CheckFalse(LServer.IsHandshaking, '1.2 mTLS: server completed');
  CheckFalse(LClient.IsTerminal or LServer.IsTerminal, '1.2 mTLS: no failure');
end;

procedure TTestClientAuth.TestTls12RequiredClientAuthMissingCertAborts;
var
  LClient, LServer: ITlsEngine;
begin
  LClient := New12Client(False);
  LServer := New12Server(TClientAuthMode.Required);
  Drive(LClient, LServer);
  CheckTrue(LServer.IsTerminal, '1.2 required mTLS with no client cert fails closed');
end;

procedure TTestClientAuth.TestTls12RequestedClientAuthWithoutCertCompletes;
var
  LClient, LServer: ITlsEngine;
begin
  LClient := New12Client(False);
  LServer := New12Server(TClientAuthMode.Requested);
  Drive(LClient, LServer);
  CheckFalse(LClient.IsHandshaking or LServer.IsHandshaking,
    '1.2 requested mTLS completes without a client cert');
  CheckFalse(LClient.IsTerminal or LServer.IsTerminal, '1.2 requested mTLS: no failure');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestClientAuth);
{$ELSE}
  RegisterTest(TTestClientAuth.Suite);
{$ENDIF FPC}

end.
