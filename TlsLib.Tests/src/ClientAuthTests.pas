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
  TlpHandshakeEffect,
  TlpHandshakeMessage,
  TlpHandshakeMessages,
  TlpICertificateTrust,
  TlpITrustAnchorStore,
  TlpTrustAnchorStore,
  TlpTlsConnection,
  TlpICryptoProvider,
  TlpIPkixProvider,
  TlpTrustTypes,
  TlpCertificateVerify,
  TlpTlsAlert,
  TlpTlsLibExceptions,
  TlpServerName,
  TlpCertificateVerifier,
  TlpCertificateLimits,
  TlpCertificateCompression,
  TlpICertificateCompression,
  TlpICertificateCompressionCache,
  TlpInMemoryCertificateCompressionCache,
  TlpZlibCertificateCompression,
  TlpTlsCredential,
  TlpCredentialResolvers,
  TlpTls13ClientStateMachine,
  TlpTls13ServerStateMachine,
  TlpTls12ClientStateMachine,
  TlpTls12ServerStateMachine,
  MockCertificateCompression,
  TlsLibHandshakeTestBase,
  TlsLibTestCertificates,
  TlsLibTestHandshakeDecoder;

type
  TTestClientAuth = class(TTlsLibHandshakeTestCase)
  private
    function Credential: TTlsCredential;
    // an ECDSA leaf under an issuer signed with SHA-1, a hash no stock server advertises
    function Sha1IssuerCredential: TTlsCredential;
    function PeerVerifier: TCertificateVerifier;
    // AWire with its first handshake message of type AMsgType replaced by ANewMessage (framed), the
    // record length adjusted; nil when no plaintext handshake record carries that type
    function ReplaceHandshakeMessage(const AWire: TBytes; AMsgType: Byte;
      const ANewMessage: TBytes): TBytes;
    /// <summary>A TLS 1.3 mutual-TLS client (with credential) and a server requiring it, with the
    /// given certificate-compression sets on each side; the server is returned through AServer.</summary>
    function New13CompressionPair(const AClientCompressors: TArray<ICertificateCompressor>;
      const AClientDecompressors: TArray<ICertificateDecompressor>;
      const AClientCache: ICertificateCompressionCache;
      const AServerCompressors: TArray<ICertificateCompressor>;
      const AServerDecompressors: TArray<ICertificateDecompressor>;
      out AServer: ITlsEngine): ITlsEngine;
    function New13Client(AWithCredential: Boolean): ITlsEngine;
    // an empty credential offers none
    function New13ClientWith(const ACredential: TTlsCredential): ITlsEngine;
    function New13Server(AMode: TClientAuthMode): ITlsEngine;
    function New13ServerWithSchemes(AMode: TClientAuthMode;
      const ASchemes: TArray<UInt16>): ITlsEngine;
    // a 1.3 mTLS server whose client-certificate verifier is wrapped in the client-side SPKI
    // pinning decorator, as the engine factory composes it when server pins are configured
    function New13ServerPinned(AMode: TClientAuthMode;
      const APins: TArray<TBytes>): ITlsEngine;
    function New13ClientMachine(AWithCredential: Boolean): IHandshakeMachine;
    function New13ServerMachine(AMode: TClientAuthMode): IHandshakeMachine;
    // a Required-auth server that advertised zlib decompression, under the given chain budget
    function New13CompressingServerMachine(
      const ALimits: TCertificateChainLimits): IHandshakeMachine;
    // the alert (if any) a server with a budget one under, or equal to, the client Certificate
    // body length raises on CompressedClientCertificate
    function ServerAlertOnCompressedClientCertificate(ABudgetBelowBody: Boolean;
      out AAlert: TTlsAlertDescription): Boolean;
    function New12Client(AWithCredential: Boolean): ITlsEngine;
    // an empty credential offers none
    function New12ClientWith(const ACredential: TTlsCredential): ITlsEngine;
    function New12Server(AMode: TClientAuthMode): ITlsEngine;
    // rewrites the signature scheme of the first plaintext CertificateVerify (handshake type 15)
    // in a wire flight, to forge a client CertificateVerify under an unadvertised scheme
    procedure PatchFirstCertVerifyScheme(var AWire: TBytes; AScheme: UInt16);
    // inserts a duplicate of the first CertificateRequest (handshake type 13) record into a wire
    // flight, right after the original, to drive a second CertificateRequest in the same phase
    function DuplicateCertificateRequest(const AWire: TBytes): TBytes;
    // a client Certificate zlib-compressed and framed as a CompressedCertificate, for a server
    // that never advertised compress_certificate
    function CompressedClientCertificate: TBytes;
    procedure Drive(const AClient, AServer: ITlsEngine);
  published
    procedure TestTls13RequiredClientAuthCompletes;
    procedure TestTls13RequiredClientAuthWithComposerPkcs12Completes;
    procedure TestTls13RequiredClientAuthMissingCertAborts;
    procedure TestTls13RequestedClientAuthWithoutCertCompletes;
    procedure TestTls13RequestedClientAuthWithNoMatchingSchemeDeclines;
    procedure TestTls13RequiredClientAuthWithNoMatchingSchemeAborts;
    procedure TestTls13RequiredClientAuthSaysWhy;
    procedure TestTls12RequiredClientAuthCompletes;
    procedure TestTls12RequiredClientAuthMissingCertAborts;
    procedure TestTls12RequestedClientAuthWithoutCertCompletes;
    procedure TestTls13ClientDeclinesASha1ChainTheServerDidNotAdvertise;
    procedure TestTls13RequiredServerRefusesTheDeclinedSha1Chain;
    procedure TestTls12ClientDeclinesASha1ChainTheServerDidNotAdvertise;
    procedure TestTls12RequiredServerRefusesTheDeclinedSha1Chain;
    procedure TestVerifyClientChainNilVerifierFailsClosed;
    procedure TestTls13NilClientVerifierWithCertAborts;
    procedure TestTls12ServerRejectsUnrequestedClientCertVerifyScheme;
    procedure TestTls12ClientRejectsSecondCertificateRequest;
    procedure TestTls13CertificateRequestWithoutSignatureAlgorithmsAborts;
    procedure TestTls13CertificateRequestWithNoUsableSchemeAborts;
    procedure TestTls13ServerRejectsNonEmptyClientCertificateContext;
    procedure TestTls13ServerRejectsClientIntermediateExtension;
    // an id-RSASSA-PSS peer leaf can complete no handshake here (no rsa_pss_pss_* scheme is
    // offered), so every machine refuses it at the Certificate message
    procedure TestTls13ClientRefusesPssSpkiServerLeaf;
    procedure TestTls13ServerRefusesPssSpkiClientLeaf;
    procedure TestTls12ClientRefusesPssSpkiServerLeaf;
    procedure TestTls12ServerRefusesPssSpkiClientLeaf;
    procedure TestTls13ClientCertPinMatchCompletes;
    procedure TestTls13ClientCertPinMismatchAborts;
    procedure TestClientCertificateIsCompressedInBothDirections;
    procedure TestEmptyClientCompressorsSendAPlainCertificate;
    procedure TestServerAdvertisingNothingGetsAPlainCertificate;
    procedure TestClientCertificateCompressionIsMemoizedOnTheClient;
    procedure TestDecliningClientCompressorSendsAPlainCertificate;
    procedure TestCompressorReportingSuccessWithNothingFailsTheHandshake;
    procedure TestRaisingCompressorIsNotSwallowed;
    procedure TestFailingDecompressorIsBadCertificate;
    procedure TestRaisingDecompressorIsBadCertificate;
    procedure TestWrongLengthDecompressionIsBadCertificate;
    procedure TestClientDecompressorContractBreachesAreBadCertificate;
    procedure TestOversizeCompressionFallsBackToAPlainCertificate;
    procedure TestUnsolicitedCompressedCertificateIsUnexpected;
    procedure TestCompressedCertificateWithoutClientAuthIsUnexpected;
    procedure TestServerRejectsCompressedClientCertificateOverTheChainBudget;
    procedure TestServerAcceptsCompressedClientCertificateAtTheChainBudget;
  end;

implementation

{ TTestClientAuth }

function TTestClientAuth.Credential: TTlsCredential;
var
  LCerts: TStringList;
begin
  LCerts := LoadVectorFields('Certs/ClientAuthChain.txt');
  try
    Result.CertificateChain := TArray<TBytes>.Create(
      DecodeHex(LCerts.Values['leaf_cert']));
    Result.PrivateKey := Crypto.Signing.ImportSigningKey(DecodeHex(LCerts.Values['leaf_key']), nil);
  finally
    LCerts.Free;
  end;
end;

function TTestClientAuth.Sha1IssuerCredential: TTlsCredential;
var
  LCerts: TStringList;
begin
  LCerts := LoadVectorFields('Certs/ReissuedRoot.txt');
  try
    Result.CertificateChain := TArray<TBytes>.Create(
      DecodeHex(LCerts.Values['leaf_cert']), DecodeHex(LCerts.Values['issuer_sha1_cert']));
    Result.PrivateKey := Crypto.Signing.ImportSigningKey(DecodeHex(LCerts.Values['leaf_key']), nil);
  finally
    LCerts.Free;
  end;
end;

function TTestClientAuth.PeerVerifier: TCertificateVerifier;
begin
  // trusts the test root; hostname identity is not applied to a peer certificate
  Result := TCertificateVerifier.Create(Pkix, TSystemClock.Create as ITlsClock,
    TTrustAnchorStore.Create(TArray<TBytes>.Create(
      TTlsLibTestCertificates.Field('Certs/ClientAuthChain.txt', 'root_cert')))
      as ITrustAnchorStore,
    False);
end;

function TTestClientAuth.ReplaceHandshakeMessage(const AWire: TBytes; AMsgType: Byte;
  const ANewMessage: TBytes): TBytes;
var
  LPos, LInner, LMsgLen, LNewRecLen: Int32;
begin
  if not TTlsLibTestHandshakeDecoder.FindPlaintextHandshakeMessage(AWire, AMsgType, LPos,
    LInner, LMsgLen) then
    Exit(nil);
  LNewRecLen := ((AWire[LPos + 3] shl 8) or AWire[LPos + 4]) - (4 + LMsgLen) +
    System.Length(ANewMessage);
  Result := ConcatBytes(ConcatBytes(ConcatBytes(ConcatBytes(
    System.Copy(AWire, 0, LPos),
    TBytes.Create(AWire[LPos], AWire[LPos + 1], AWire[LPos + 2],
    Byte(LNewRecLen shr 8), Byte(LNewRecLen and $FF))),
    System.Copy(AWire, LPos + 5, LInner - (LPos + 5))), ANewMessage),
    System.Copy(AWire, LInner + 4 + LMsgLen, System.Length(AWire) - (LInner + 4 + LMsgLen)));
end;

function TTestClientAuth.New13ServerPinned(AMode: TClientAuthMode;
  const APins: TArray<TBytes>): ITlsEngine;
var
  LParams: TServerHandshakeParams;
begin
  LParams := Default(TServerHandshakeParams);
  LParams.Clock := TSystemClock.Create;
  LParams.Crypto := Crypto;
  LParams.Inspector := Pkix.Certificates;
  LParams.Policy := TNegotiationPolicy.CreateDefault(Crypto);
  LParams.CipherSuites := TCipherSuiteRegistry.CreateDefault(Crypto);
  LParams.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  LParams.Group := TNamedGroups.CreateX25519(Crypto);
  LParams.ServerRandom := Filled($22, 32);
  LParams.CredentialResolver := TSniCredentialResolver.ForCredential(Credential);
  LParams.ClientAuth := AMode;
  LParams.ClientAuthSignatureSchemes := TArray<UInt16>.Create(TSignatureSchemes.EcdsaSecp256r1Sha256);
  // wrap the client verifier in the pinning decorator, as the factory does for a server with pins
  LParams.ClientCertificateVerifier := TClientPinningVerifier.Create(
    PeerVerifier as IClientCertificateVerifier, APins, Crypto, Pkix)
    as IClientCertificateVerifier;
  Result := TTlsEngine.CreateConfigured(
    TTls13ServerStateMachine.Create(LParams) as IHandshakeMachine, Crypto);
end;

function TTestClientAuth.New13Client(AWithCredential: Boolean): ITlsEngine;
var
  LCredential: TTlsCredential;
begin
  if AWithCredential then
    LCredential := Credential
  else
    LCredential := Default(TTlsCredential);
  Result := New13ClientWith(LCredential);
end;

function TTestClientAuth.New13ClientWith(const ACredential: TTlsCredential): ITlsEngine;
var
  LParams: TClientHandshakeParams;
begin
  LParams := Default(TClientHandshakeParams);
  LParams.Clock := TSystemClock.Create;
  LParams.Crypto := Crypto;
  LParams.Inspector := Pkix.Certificates;
  LParams.Group := TNamedGroups.CreateX25519(Crypto);
  LParams.GroupCode := TNamedGroupCatalog.X25519;
  LParams.CipherSuites := TCipherSuiteRegistry.CreateDefault(Crypto);
  LParams.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  LParams.OfferedSuites := TArray<UInt16>.Create(TCipherSuites13.Aes128GcmSha256);
  LParams.OfferedSchemes := TArray<UInt16>.Create(TSignatureSchemes.EcdsaSecp256r1Sha256);
  LParams.ClientRandom := Filled($11, 32);
  LParams.LegacySessionId := Filled($33, 32);
  LParams.CertificateVerifier := PeerVerifier;
  LParams.ExpectedServerName := TServerName.DnsName('localhost');
  if System.Length(ACredential.CertificateChain) > 0 then
    LParams.ClientCredential := ACredential;
  Result := TTlsEngine.CreateConfigured(
    TTls13ClientStateMachine.Create(LParams) as IHandshakeMachine, Crypto);
end;

function TTestClientAuth.New13CompressionPair(
  const AClientCompressors: TArray<ICertificateCompressor>;
  const AClientDecompressors: TArray<ICertificateDecompressor>;
  const AClientCache: ICertificateCompressionCache;
  const AServerCompressors: TArray<ICertificateCompressor>;
  const AServerDecompressors: TArray<ICertificateDecompressor>;
  out AServer: ITlsEngine): ITlsEngine;
var
  LClient: TClientHandshakeParams;
  LServer: TServerHandshakeParams;
begin
  LClient := Default(TClientHandshakeParams);
  LClient.Clock := TSystemClock.Create;
  LClient.Crypto := Crypto;
  LClient.Inspector := Pkix.Certificates;
  LClient.Group := TNamedGroups.CreateX25519(Crypto);
  LClient.GroupCode := TNamedGroupCatalog.X25519;
  LClient.CipherSuites := TCipherSuiteRegistry.CreateDefault(Crypto);
  LClient.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  LClient.OfferedSuites := TArray<UInt16>.Create(TCipherSuites13.Aes128GcmSha256);
  LClient.OfferedSchemes := TArray<UInt16>.Create(TSignatureSchemes.EcdsaSecp256r1Sha256);
  LClient.ClientRandom := Filled($11, 32);
  LClient.LegacySessionId := Filled($33, 32);
  LClient.CertificateVerifier := PeerVerifier;
  LClient.ExpectedServerName := TServerName.DnsName('localhost');
  LClient.ClientCredential := Credential;
  LClient.CertificateChainLimits := TCertificateChainLimits.Defaults;
  LClient.CertificateCompressors := AClientCompressors;
  LClient.CertificateDecompressors := AClientDecompressors;
  LClient.CertificateCompressionCache := AClientCache;
  Result := TTlsEngine.CreateConfigured(
    TTls13ClientStateMachine.Create(LClient) as IHandshakeMachine, Crypto);

  LServer := Default(TServerHandshakeParams);
  LServer.Clock := TSystemClock.Create;
  LServer.Crypto := Crypto;
  LServer.Inspector := Pkix.Certificates;
  LServer.Policy := TNegotiationPolicy.CreateDefault(Crypto);
  LServer.CipherSuites := TCipherSuiteRegistry.CreateDefault(Crypto);
  LServer.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  LServer.Group := TNamedGroups.CreateX25519(Crypto);
  LServer.ServerRandom := Filled($22, 32);
  LServer.CredentialResolver := TSniCredentialResolver.ForCredential(Credential);
  LServer.ClientAuth := TClientAuthMode.Required;
  LServer.ClientAuthSignatureSchemes :=
    TArray<UInt16>.Create(TSignatureSchemes.EcdsaSecp256r1Sha256);
  LServer.ClientCertificateVerifier := PeerVerifier;
  LServer.CertificateChainLimits := TCertificateChainLimits.Defaults;
  LServer.CertificateCompressors := AServerCompressors;
  LServer.CertificateDecompressors := AServerDecompressors;
  AServer := TTlsEngine.CreateConfigured(
    TTls13ServerStateMachine.Create(LServer) as IHandshakeMachine, Crypto);
end;

function TTestClientAuth.New13Server(AMode: TClientAuthMode): ITlsEngine;
begin
  Result := New13ServerWithSchemes(AMode,
    TArray<UInt16>.Create(TSignatureSchemes.EcdsaSecp256r1Sha256));
end;

function TTestClientAuth.New13ServerWithSchemes(AMode: TClientAuthMode;
  const ASchemes: TArray<UInt16>): ITlsEngine;
var
  LParams: TServerHandshakeParams;
begin
  LParams := Default(TServerHandshakeParams);
  LParams.Clock := TSystemClock.Create;
  LParams.Crypto := Crypto;
  LParams.Inspector := Pkix.Certificates;
  LParams.Policy := TNegotiationPolicy.CreateDefault(Crypto);
  LParams.CipherSuites := TCipherSuiteRegistry.CreateDefault(Crypto);
  LParams.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  LParams.Group := TNamedGroups.CreateX25519(Crypto);
  LParams.ServerRandom := Filled($22, 32);
  LParams.CredentialResolver := TSniCredentialResolver.ForCredential(Credential);
  LParams.ClientAuth := AMode;
  LParams.ClientAuthSignatureSchemes := ASchemes;
  LParams.ClientCertificateVerifier := PeerVerifier;
  Result := TTlsEngine.CreateConfigured(
    TTls13ServerStateMachine.Create(LParams) as IHandshakeMachine, Crypto);
end;

function TTestClientAuth.New13ClientMachine(
  AWithCredential: Boolean): IHandshakeMachine;
var
  LParams: TClientHandshakeParams;
begin
  LParams := Default(TClientHandshakeParams);
  LParams.Clock := TSystemClock.Create;
  LParams.Crypto := Crypto;
  LParams.Inspector := Pkix.Certificates;
  LParams.Group := TNamedGroups.CreateX25519(Crypto);
  LParams.GroupCode := TNamedGroupCatalog.X25519;
  LParams.CipherSuites := TCipherSuiteRegistry.CreateDefault(Crypto);
  LParams.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  LParams.OfferedSuites := TArray<UInt16>.Create(TCipherSuites13.Aes128GcmSha256);
  LParams.OfferedSchemes := TArray<UInt16>.Create(TSignatureSchemes.EcdsaSecp256r1Sha256);
  LParams.ClientRandom := Filled($11, 32);
  LParams.LegacySessionId := Filled($33, 32);
  LParams.CertificateVerifier := PeerVerifier;
  LParams.ExpectedServerName := TServerName.DnsName('localhost');
  if AWithCredential then
    LParams.ClientCredential := Credential;
  Result := TTls13ClientStateMachine.Create(LParams) as IHandshakeMachine;
end;

function TTestClientAuth.New13ServerMachine(
  AMode: TClientAuthMode): IHandshakeMachine;
var
  LParams: TServerHandshakeParams;
begin
  LParams := Default(TServerHandshakeParams);
  LParams.Clock := TSystemClock.Create;
  LParams.Crypto := Crypto;
  LParams.Inspector := Pkix.Certificates;
  LParams.Policy := TNegotiationPolicy.CreateDefault(Crypto);
  LParams.CipherSuites := TCipherSuiteRegistry.CreateDefault(Crypto);
  LParams.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  LParams.Group := TNamedGroups.CreateX25519(Crypto);
  LParams.ServerRandom := Filled($22, 32);
  LParams.CredentialResolver := TSniCredentialResolver.ForCredential(Credential);
  LParams.ClientAuth := AMode;
  LParams.ClientAuthSignatureSchemes := TArray<UInt16>.Create(TSignatureSchemes.EcdsaSecp256r1Sha256);
  LParams.ClientCertificateVerifier := PeerVerifier;
  Result := TTls13ServerStateMachine.Create(LParams) as IHandshakeMachine;
end;

function TTestClientAuth.New13CompressingServerMachine(
  const ALimits: TCertificateChainLimits): IHandshakeMachine;
var
  LParams: TServerHandshakeParams;
begin
  LParams := Default(TServerHandshakeParams);
  LParams.Clock := TSystemClock.Create;
  LParams.Crypto := Crypto;
  LParams.Inspector := Pkix.Certificates;
  LParams.Policy := TNegotiationPolicy.CreateDefault(Crypto);
  LParams.CipherSuites := TCipherSuiteRegistry.CreateDefault(Crypto);
  LParams.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  LParams.Group := TNamedGroups.CreateX25519(Crypto);
  LParams.ServerRandom := Filled($22, 32);
  LParams.CredentialResolver := TSniCredentialResolver.ForCredential(Credential);
  LParams.ClientAuth := TClientAuthMode.Required;
  LParams.ClientAuthSignatureSchemes := TArray<UInt16>.Create(TSignatureSchemes.EcdsaSecp256r1Sha256);
  LParams.ClientCertificateVerifier := PeerVerifier;
  LParams.CertificateDecompressors := TZlibCertificateCompression.DefaultDecompressors;
  LParams.CertificateChainLimits := ALimits;
  Result := TTls13ServerStateMachine.Create(LParams) as IHandshakeMachine;
end;

function TTestClientAuth.ServerAlertOnCompressedClientCertificate(
  ABudgetBelowBody: Boolean; out AAlert: TTlsAlertDescription): Boolean;
var
  LLimits: TCertificateChainLimits;
  LClient, LServer: IHandshakeMachine;
  LFramed: TBytes;
  LBodyLength: Int32;
begin
  LFramed := CompressedClientCertificate;
  LBodyLength := THandshakeMessages.DecodeCompressedCertificate(
    TTlsLibTestHandshakeDecoder.HandshakeMessage(LFramed).Body).UncompressedLength;
  LLimits := TCertificateChainLimits.Defaults;
  if ABudgetBelowBody then
    LLimits.MaxTotalChainLength := LBodyLength - 1
  else
    LLimits.MaxTotalChainLength := LBodyLength;
  LClient := New13ClientMachine(True);
  LServer := New13CompressingServerMachine(LLimits);
  AllSendHandshake(LServer.ProcessMessage(
    TTlsLibTestHandshakeDecoder.HandshakeMessage(FirstSendHandshake(LClient.Start))));
  Result := FailAlertOf(LServer.ProcessMessage(
    TTlsLibTestHandshakeDecoder.HandshakeMessage(LFramed)), AAlert);
end;

procedure TTestClientAuth.TestServerRejectsCompressedClientCertificateOverTheChainBudget;
var
  LAlert: TTlsAlertDescription;
begin
  // the body compresses far less than 100x, so only the budget passed in can refuse it
  CheckTrue(ServerAlertOnCompressedClientCertificate(True, LAlert),
    'a declared length over the chain budget aborts');
  CheckEquals(Int64(Ord(TTlsAlertDescription.IllegalParameter)), Int64(Ord(LAlert)),
    'the abort is illegal_parameter');
end;

procedure TTestClientAuth.TestServerAcceptsCompressedClientCertificateAtTheChainBudget;
var
  LAlert: TTlsAlertDescription;
begin
  // the control for the over-budget test: a budget of exactly the body length passes the check
  CheckFalse(ServerAlertOnCompressedClientCertificate(False, LAlert),
    'a declared length at the chain budget is accepted');
end;

function TTestClientAuth.New12Client(AWithCredential: Boolean): ITlsEngine;
var
  LCredential: TTlsCredential;
begin
  if AWithCredential then
    LCredential := Credential
  else
    LCredential := Default(TTlsCredential);
  Result := New12ClientWith(LCredential);
end;

function TTestClientAuth.New12ClientWith(const ACredential: TTlsCredential): ITlsEngine;
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
  // TLS 1.2 supported_groups gates both the ECDHE key-exchange group and the ECDSA leaf's
  // curve (RFC 8422 5.3), so it lists X25519 and Secp256r1 (the P-256 certificate curve)
  LParams.OfferedGroups := TArray<UInt16>.Create(TNamedGroupCatalog.X25519,
    TNamedGroupCatalog.Secp256r1);
  LParams.OfferedSchemes := TArray<UInt16>.Create(TSignatureSchemes.EcdsaSecp256r1Sha256);
  LParams.OfferedVersions := TArray<UInt16>.Create(TlsWireVersionTls12);
  LParams.ClientRandom := Filled($11, 32);
  LParams.OfferExtendedMasterSecret := True;
  LParams.CertificateVerifier := PeerVerifier;
  LParams.ExpectedServerName := TServerName.DnsName('localhost');
  if System.Length(ACredential.CertificateChain) > 0 then
    LParams.ClientCredential := ACredential;
  Result := TTlsEngine.CreateConfigured(
    TTls12ClientStateMachine.Create(LParams) as IHandshakeMachine, Crypto);
end;

function TTestClientAuth.New12Server(AMode: TClientAuthMode): ITlsEngine;
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
  LParams.CredentialResolver := TSniCredentialResolver.ForCredential(Credential);
  LParams.ClientAuth := AMode;
  LParams.ClientAuthSignatureSchemes := TArray<UInt16>.Create(TSignatureSchemes.EcdsaSecp256r1Sha256);
  LParams.ClientCertificateVerifier := PeerVerifier;
  Result := TTlsEngine.CreateConfigured(
    TTls12ServerStateMachine.Create(LParams) as IHandshakeMachine, Crypto);
end;

procedure TTestClientAuth.PatchFirstCertVerifyScheme(var AWire: TBytes;
  AScheme: UInt16);
var
  LRecordPos, LMsgPos, LMsgLen: Int32;
begin
  CheckTrue(TTlsLibTestHandshakeDecoder.FindPlaintextHandshakeMessage(AWire,
    Ord(TTlsHandshakeType.CertificateVerify), LRecordPos, LMsgPos, LMsgLen),
    'the flight carries a plaintext CertificateVerify');
  // the body starts with the 2-byte scheme
  AWire[LMsgPos + 4] := Byte(AScheme shr 8);
  AWire[LMsgPos + 5] := Byte(AScheme and $FF);
end;

function TTestClientAuth.DuplicateCertificateRequest(const AWire: TBytes): TBytes;
var
  LRecordPos, LMsgPos, LMsgLen, LRecordEnd: Int32;
  LMsg, LRecord: TBytes;
begin
  CheckTrue(TTlsLibTestHandshakeDecoder.FindPlaintextHandshakeMessage(AWire,
    Ord(TTlsHandshakeType.CertificateRequest), LRecordPos, LMsgPos, LMsgLen),
    'the flight carries a plaintext CertificateRequest');
  LMsg := System.Copy(AWire, LMsgPos, 4 + LMsgLen);
  LRecord := ConcatBytes(TBytes.Create(22, 3, 3, Byte(System.Length(LMsg) shr 8),
    Byte(System.Length(LMsg) and $FF)), LMsg);
  LRecordEnd := LRecordPos + 5 + ((AWire[LRecordPos + 3] shl 8) or AWire[LRecordPos + 4]);
  // original wire up to and including this record, then the duplicate, then the rest
  Result := ConcatBytes(ConcatBytes(System.Copy(AWire, 0, LRecordEnd), LRecord),
    System.Copy(AWire, LRecordEnd, System.Length(AWire) - LRecordEnd));
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

procedure TTestClientAuth.TestTls13RequiredClientAuthWithComposerPkcs12Completes;
var
  LOpts: TTlsOptions;
  LFields: TStringList;
  LCredential: TTlsCredential;
  LClient, LServer: ITlsEngine;
begin
  // the client credential the composer opens from a PKCS#12 authenticates in a real handshake
  LFields := LoadVectorFields('Certs/ClientAuthChain.txt');
  try
    LOpts := TTlsOptions.Default;
    LOpts.Crypto := Crypto;
    LOpts.Pkix := Pkix;
    LOpts.Certificate := TTlsBlobSource.FromBytes(DecodeHex(LFields.Values['leaf_pfx']));
    LOpts.CredentialForm := TTlsCredentialForm.Pkcs12;
    LOpts.KeyPassword := 'tlslib';
  finally
    LFields.Free;
  end;
  LOpts.CustomTrustStore := TTrustAnchorStore.Create(
    TArray<TBytes>.Create(
      TTlsLibTestCertificates.Field('Certs/ClientAuthChain.txt', 'root_cert')))
    as ITrustAnchorStore;
  LCredential := TTlsConfigComposer.BuildClientConfig(LOpts).Credential;
  // the PKCS#12's leaf is the one presented, with its CA bag behind it
  CheckEquals(2, System.Length(LCredential.CertificateChain), 'leaf and CA bag');
  CheckTrue(AreEqual(LCredential.CertificateChain[0],
    TTlsLibTestCertificates.Field('Certs/ClientAuthChain.txt', 'leaf_cert')),
    'the PFX leaf leads');
  LClient := New13ClientWith(LCredential);
  LServer := New13Server(TClientAuthMode.Required);
  Drive(LClient, LServer);
  CheckFalse(LClient.IsHandshaking, '1.3 mTLS from a PKCS#12: client completed');
  CheckFalse(LServer.IsHandshaking, '1.3 mTLS from a PKCS#12: server completed');
  CheckFalse(LClient.IsTerminal or LServer.IsTerminal, '1.3 mTLS from a PKCS#12: no failure');
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

procedure TTestClientAuth.TestTls13RequestedClientAuthWithNoMatchingSchemeDeclines;
var
  LClient, LServer: ITlsEngine;
begin
  // the credential's only scheme (ECDSA P-256) is not in the server's signature_algorithms, so the
  // client sends an empty Certificate (RFC 9846 4.5.1) and a Requested server carries on
  LClient := New13Client(True);
  LServer := New13ServerWithSchemes(TClientAuthMode.Requested,
    TArray<UInt16>.Create(TSignatureSchemes.Ed25519));
  Drive(LClient, LServer);
  CheckFalse(LClient.IsHandshaking or LServer.IsHandshaking,
    'no usable scheme: a Requested handshake completes without a client certificate');
  CheckFalse(LClient.IsTerminal or LServer.IsTerminal, 'no usable scheme: no failure');
end;

procedure TTestClientAuth.TestTls13RequiredClientAuthWithNoMatchingSchemeAborts;
var
  LClient, LServer: ITlsEngine;
begin
  // the same decline under Required is refused by the server's own policy
  LClient := New13Client(True);
  LServer := New13ServerWithSchemes(TClientAuthMode.Required,
    TArray<UInt16>.Create(TSignatureSchemes.Ed25519));
  Drive(LClient, LServer);
  CheckTrue(LServer.IsTerminal, 'no usable scheme: a Required server fails closed');
  CheckEquals(Ord(TTlsAlertDescription.CertificateRequired),
    Ord(LServer.LastError.Alert.Description),
    'the server refuses the empty Certificate with certificate_required, not the client aborting');
end;

procedure TTestClientAuth.TestTls13RequiredClientAuthSaysWhy;
var
  LClient, LServer: ITlsEngine;
begin
  LClient := New13Client(True);
  LServer := New13ServerWithSchemes(TClientAuthMode.Required,
    TArray<UInt16>.Create(TSignatureSchemes.Ed25519));
  Drive(LClient, LServer);
  CheckEquals('client authentication is required but none was sent',
    LServer.LastError.Message, 'the server machine''s reason reaches LastError');
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

procedure TTestClientAuth.TestTls13ClientDeclinesASha1ChainTheServerDidNotAdvertise;
var
  LClient, LServer: ITlsEngine;
begin
  // the client would otherwise send the SHA-1-signed chain, which the server cannot trust, and fail
  LClient := New13ClientWith(Sha1IssuerCredential);
  LServer := New13Server(TClientAuthMode.Requested);
  Drive(LClient, LServer);
  CheckFalse(LClient.IsHandshaking or LServer.IsHandshaking,
    '1.3: the client answers without a certificate and the handshake completes');
  CheckFalse(LClient.IsTerminal or LServer.IsTerminal, '1.3: no failure (RFC 9846 4.5.1.2)');
end;

procedure TTestClientAuth.TestTls13RequiredServerRefusesTheDeclinedSha1Chain;
var
  LClient, LServer: ITlsEngine;
begin
  LClient := New13ClientWith(Sha1IssuerCredential);
  LServer := New13Server(TClientAuthMode.Required);
  Drive(LClient, LServer);
  CheckTrue(LServer.IsTerminal, '1.3: a Required server fails closed');
  CheckEquals(Ord(TTlsAlertDescription.CertificateRequired),
    Ord(LServer.LastError.Alert.Description),
    '1.3: the server refuses the empty Certificate, the client did not abort');
end;

procedure TTestClientAuth.TestTls12ClientDeclinesASha1ChainTheServerDidNotAdvertise;
var
  LClient, LServer: ITlsEngine;
begin
  LClient := New12ClientWith(Sha1IssuerCredential);
  LServer := New12Server(TClientAuthMode.Requested);
  Drive(LClient, LServer);
  CheckFalse(LClient.IsHandshaking or LServer.IsHandshaking,
    '1.2: the client answers without a certificate and the handshake completes');
  CheckFalse(LClient.IsTerminal or LServer.IsTerminal, '1.2: no failure (RFC 9846 4.5.1.2)');
end;

procedure TTestClientAuth.TestTls12RequiredServerRefusesTheDeclinedSha1Chain;
var
  LClient, LServer: ITlsEngine;
begin
  LClient := New12ClientWith(Sha1IssuerCredential);
  LServer := New12Server(TClientAuthMode.Required);
  Drive(LClient, LServer);
  CheckTrue(LServer.IsTerminal, '1.2: a Required server fails closed');
  CheckEquals(Ord(TTlsAlertDescription.HandshakeFailure),
    Ord(LServer.LastError.Alert.Description),
    '1.2: the server refuses the empty Certificate, the client did not abort');
end;

procedure TTestClientAuth.TestVerifyClientChainNilVerifierFailsClosed;
var
  LChain: TArray<TBytes>;
  LVerified: TVerifiedChain;
  LAlert, LGotAlert: TTlsAlertDescription;
  LRaised: Boolean;
begin
  // the shared client-chain gate must fail closed on a nil verifier (a server misconfiguration):
  // there is no basis to trust the chain, and it must not read an unassigned alert
  LChain := TArray<TBytes>.Create(Filled($01, 32));
  LRaised := False;
  LGotAlert := TTlsAlertDescription.CloseNotify; // a sentinel distinct from the expected alert
  try
    TCertificateVerify.VerifyClientChain(nil, LChain, LVerified, LAlert);
  except
    on E: EFatalAlertTlsLibException do
    begin
      LRaised := True;
      LGotAlert := E.AlertDescription;
    end;
  end;
  CheckTrue(LRaised, 'a nil client-certificate verifier fails closed');
  CheckEquals(Int64(Ord(TTlsAlertDescription.InternalError)), Int64(Ord(LGotAlert)),
    'the nil-verifier failure is internal_error');
end;

procedure TTestClientAuth.TestTls13NilClientVerifierWithCertAborts;
var
  LParams: TServerHandshakeParams;
  LClient, LServer: ITlsEngine;
begin
  // end-to-end: a 1.3 server that requires client auth but has no verifier configured must abort
  // with internal_error when a client presents a certificate (the call site routes through the
  // fail-closed gate), rather than raising with an unassigned alert
  LParams := Default(TServerHandshakeParams);
  LParams.Clock := TSystemClock.Create;
  LParams.Crypto := Crypto;
  LParams.Inspector := Pkix.Certificates;
  LParams.Policy := TNegotiationPolicy.CreateDefault(Crypto);
  LParams.CipherSuites := TCipherSuiteRegistry.CreateDefault(Crypto);
  LParams.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  LParams.Group := TNamedGroups.CreateX25519(Crypto);
  LParams.ServerRandom := Filled($22, 32);
  LParams.CredentialResolver := TSniCredentialResolver.ForCredential(Credential);
  LParams.ClientAuth := TClientAuthMode.Required;
  LParams.ClientAuthSignatureSchemes := TArray<UInt16>.Create(
    TSignatureSchemes.EcdsaSecp256r1Sha256);
  // ClientCertificateVerifier deliberately left nil (Default leaves it nil)
  LServer := TTlsEngine.CreateConfigured(
    TTls13ServerStateMachine.Create(LParams) as IHandshakeMachine, Crypto);
  LClient := New13Client(True);
  Drive(LClient, LServer);
  CheckTrue(LServer.IsTerminal, 'a nil client-certificate verifier aborts the handshake');
  CheckEquals(Int64(Ord(TTlsAlertDescription.InternalError)),
    Int64(Ord(LServer.LastError.Alert.Description)),
    'the nil-verifier abort is internal_error');
end;

procedure TTestClientAuth.TestTls12ServerRejectsUnrequestedClientCertVerifyScheme;
var
  LClient, LServer: ITlsEngine;
  LFlight: TBytes;
begin
  // the server's CertificateRequest advertises only ecdsa_secp256r1_sha256; forge the client's
  // CertificateVerify to claim ecdsa_secp384r1_sha384 (0x0503) - a valid, recognized code the
  // request did not offer. The server must reject the unadvertised scheme (RFC 5246 7.4.8) rather
  // than merely fail signature verification (which pre-fix gave decrypt_error), so the alert
  // discriminates the fix.
  LClient := New12Client(True);
  LServer := New12Server(TClientAuthMode.Required);
  LClient.StartHandshake;
  Pump(LClient, LServer); // ClientHello -> server
  Pump(LServer, LClient); // server flight -> client; the client now holds its response flight
  LFlight := Drain(LClient);
  PatchFirstCertVerifyScheme(LFlight, $0503);
  Feed(LServer, LFlight);
  CheckTrue(LServer.IsTerminal, 'the server aborts a CertificateVerify under an unadvertised scheme');
  CheckEquals(Int64(Ord(TTlsAlertDescription.IllegalParameter)),
    Int64(Ord(LServer.LastError.Alert.Description)),
    'the abort is illegal_parameter, not a signature-verification failure');
end;

procedure TTestClientAuth.TestTls12ClientRejectsSecondCertificateRequest;
var
  LClient, LServer: ITlsEngine;
  LFlight: TBytes;
begin
  // a CertificateRequest may appear at most once (the flow of RFC 5246 7.3); duplicating the server's real
  // request in the same flight must make the client abort with unexpected_message
  LClient := New12Client(True);
  LServer := New12Server(TClientAuthMode.Required);
  LClient.StartHandshake;
  Pump(LClient, LServer); // ClientHello -> server
  LFlight := DuplicateCertificateRequest(Drain(LServer));
  Feed(LClient, LFlight);
  CheckTrue(LClient.IsTerminal, 'the client aborts a second CertificateRequest');
  CheckEquals(Int64(Ord(TTlsAlertDescription.UnexpectedMessage)),
    Int64(Ord(LClient.LastError.Alert.Description)),
    'a second CertificateRequest is unexpected_message');
end;

procedure TTestClientAuth.TestTls13CertificateRequestWithoutSignatureAlgorithmsAborts;
var
  LClient, LServer: IHandshakeMachine;
  LFlight: TArray<TBytes>;
  LReq: TTlsCertificateRequest13;
  LCertReq: TBytes;
  LAlert: TTlsAlertDescription;
begin
  // a TLS 1.3 CertificateRequest MUST carry signature_algorithms (RFC 9846 4.4.2); drive the
  // client to WaitCertificate, then feed a CertificateRequest whose extensions omit it
  LClient := New13ClientMachine(True);
  LServer := New13ServerMachine(TClientAuthMode.Required);
  LFlight := AllSendHandshake(LServer.ProcessMessage(TTlsLibTestHandshakeDecoder.HandshakeMessage(FirstSendHandshake(LClient.Start))));
  LClient.ProcessMessage(TTlsLibTestHandshakeDecoder.HandshakeMessage(LFlight[0])); // ServerHello
  LClient.ProcessMessage(TTlsLibTestHandshakeDecoder.HandshakeMessage(LFlight[1])); // EncryptedExtensions
  LReq.RequestContext := nil;
  LReq.Extensions := TBytes.Create($00, $00); // a present-but-empty extensions vector
  LCertReq := THandshakeFraming.Frame(TTlsHandshakeType.CertificateRequest,
    THandshakeMessages.EncodeCertificateRequest13(LReq));
  CheckTrue(FailAlertOf(LClient.ProcessMessage(TTlsLibTestHandshakeDecoder.HandshakeMessage(LCertReq)), LAlert),
    'a CertificateRequest without signature_algorithms aborts');
  CheckEquals(Int64(Ord(TTlsAlertDescription.MissingExtension)), Int64(Ord(LAlert)),
    'the abort is missing_extension');
end;

procedure TTestClientAuth.TestTls13CertificateRequestWithNoUsableSchemeAborts;
var
  LClient, LServer: IHandshakeMachine;
  LFlight: TArray<TBytes>;
  LReq: TTlsCertificateRequest13;
  LCertReq: TBytes;
  LAlert: TTlsAlertDescription;
begin
  // a request whose only scheme is rsa_pkcs1_sha256 (not usable in TLS 1.3) could never accept a
  // CertificateVerify: the client refuses it whatever its credential
  LClient := New13ClientMachine(True);
  LServer := New13ServerMachine(TClientAuthMode.Required);
  LFlight := AllSendHandshake(LServer.ProcessMessage(TTlsLibTestHandshakeDecoder.HandshakeMessage(FirstSendHandshake(LClient.Start))));
  LClient.ProcessMessage(TTlsLibTestHandshakeDecoder.HandshakeMessage(LFlight[0])); // ServerHello
  LClient.ProcessMessage(TTlsLibTestHandshakeDecoder.HandshakeMessage(LFlight[1])); // EncryptedExtensions
  LReq.RequestContext := nil;
  // extensions: one signature_algorithms (13) carrying [rsa_pkcs1_sha256 = 0x0401]
  LReq.Extensions := TBytes.Create($00, $08, $00, $0D, $00, $04, $00, $02, $04, $01);
  LCertReq := THandshakeFraming.Frame(TTlsHandshakeType.CertificateRequest,
    THandshakeMessages.EncodeCertificateRequest13(LReq));
  CheckTrue(FailAlertOf(LClient.ProcessMessage(TTlsLibTestHandshakeDecoder.HandshakeMessage(LCertReq)), LAlert),
    'a CertificateRequest with no TLS 1.3-usable scheme aborts');
  CheckEquals(Int64(Ord(TTlsAlertDescription.HandshakeFailure)), Int64(Ord(LAlert)),
    'the abort is handshake_failure');
  // the same request refuses a client with no credential at all
  LClient := New13ClientMachine(False);
  LServer := New13ServerMachine(TClientAuthMode.Required);
  LFlight := AllSendHandshake(LServer.ProcessMessage(TTlsLibTestHandshakeDecoder.HandshakeMessage(FirstSendHandshake(LClient.Start))));
  LClient.ProcessMessage(TTlsLibTestHandshakeDecoder.HandshakeMessage(LFlight[0]));
  LClient.ProcessMessage(TTlsLibTestHandshakeDecoder.HandshakeMessage(LFlight[1]));
  CheckTrue(FailAlertOf(LClient.ProcessMessage(TTlsLibTestHandshakeDecoder.HandshakeMessage(LCertReq)), LAlert),
    'a client without a credential refuses it too');
end;

procedure TTestClientAuth.TestTls13ServerRejectsNonEmptyClientCertificateContext;
var
  LClient, LServer: IHandshakeMachine;
  LServerFlight, LClientFlight: TArray<TBytes>;
  LEffects: TArray<THandshakeEffect>;
  LCert: TTlsCertificate;
  LCertMsg: TBytes;
  LAlert: TTlsAlertDescription;
  LI: Int32;
begin
  // drive the client through the server's whole first flight so it answers with its real
  // Certificate, then re-encode that Certificate with a one-byte certificate_request_context:
  // the context echoes the (empty) CertificateRequest context in the main handshake
  // (RFC 9846 4.5.1), so the server aborts; decode_error is this library's choice of alert
  LClient := New13ClientMachine(True);
  LServer := New13ServerMachine(TClientAuthMode.Required);
  LServerFlight := AllSendHandshake(LServer.ProcessMessage(TTlsLibTestHandshakeDecoder.HandshakeMessage(
    FirstSendHandshake(LClient.Start))));
  LEffects := nil;
  for LI := 0 to High(LServerFlight) do
    LEffects := LClient.ProcessMessage(TTlsLibTestHandshakeDecoder.HandshakeMessage(LServerFlight[LI]));
  LClientFlight := AllSendHandshake(LEffects);
  CheckTrue(System.Length(LClientFlight) > 0, 'the client answered the server flight');
  CheckTrue(TTlsLibTestHandshakeDecoder.HandshakeMessage(LClientFlight[0]).TypeByte = Byte(Ord(TTlsHandshakeType.Certificate)),
    'the client flight starts with its Certificate');
  LCert := THandshakeMessages.DecodeCertificate(TTlsLibTestHandshakeDecoder.HandshakeMessage(LClientFlight[0]).Body);
  LCert.RequestContext := TBytes.Create($01);
  LCertMsg := THandshakeFraming.Frame(TTlsHandshakeType.Certificate,
    THandshakeMessages.EncodeCertificate(LCert));
  CheckTrue(FailAlertOf(LServer.ProcessMessage(TTlsLibTestHandshakeDecoder.HandshakeMessage(LCertMsg)), LAlert),
    'a non-empty client certificate_request_context aborts');
  CheckEquals(Int64(Ord(TTlsAlertDescription.DecodeError)), Int64(Ord(LAlert)),
    'the abort is decode_error');
end;

procedure TTestClientAuth.TestTls13ServerRejectsClientIntermediateExtension;
var
  LClient, LServer: IHandshakeMachine;
  LServerFlight, LClientFlight: TArray<TBytes>;
  LEffects: TArray<THandshakeEffect>;
  LCert: TTlsCertificate;
  LCertMsg: TBytes;
  LAlert: TTlsAlertDescription;
  LI: Int32;
begin
  // the CertificateRequest solicits no certificate-entry extension, so one on a client
  // intermediate entry is unsupported_extension just like one on the leaf (RFC 9846 4.5.1)
  LClient := New13ClientMachine(True);
  LServer := New13ServerMachine(TClientAuthMode.Required);
  LServerFlight := AllSendHandshake(LServer.ProcessMessage(TTlsLibTestHandshakeDecoder.HandshakeMessage(
    FirstSendHandshake(LClient.Start))));
  LEffects := nil;
  for LI := 0 to High(LServerFlight) do
    LEffects := LClient.ProcessMessage(TTlsLibTestHandshakeDecoder.HandshakeMessage(LServerFlight[LI]));
  LClientFlight := AllSendHandshake(LEffects);
  CheckTrue(System.Length(LClientFlight) > 0, 'the client answered the server flight');
  LCert := THandshakeMessages.DecodeCertificate(TTlsLibTestHandshakeDecoder.HandshakeMessage(LClientFlight[0]).Body);
  SetLength(LCert.Entries, System.Length(LCert.Entries) + 1);
  LCert.Entries[High(LCert.Entries)].CertData := LCert.Entries[0].CertData;
  LCert.Entries[High(LCert.Entries)].Extensions := DecodeHex('0004aaaa0000');
  LCertMsg := THandshakeFraming.Frame(TTlsHandshakeType.Certificate,
    THandshakeMessages.EncodeCertificate(LCert));
  CheckTrue(FailAlertOf(LServer.ProcessMessage(TTlsLibTestHandshakeDecoder.HandshakeMessage(LCertMsg)), LAlert),
    'an extension on a client intermediate entry aborts');
  CheckEquals(Int64(Ord(TTlsAlertDescription.UnsupportedExtension)), Int64(Ord(LAlert)),
    'the abort is unsupported_extension');
end;

procedure TTestClientAuth.TestTls13ClientRefusesPssSpkiServerLeaf;
var
  LClient, LServer: IHandshakeMachine;
  LFlight: TArray<TBytes>;
  LCert: TTlsCertificate;
  LCertMsg: TBytes;
  LAlert: TTlsAlertDescription;
  LI: Int32;
  LFailed: Boolean;
begin
  LClient := New13ClientMachine(False);
  LServer := New13ServerMachine(TClientAuthMode.None);
  LFlight := AllSendHandshake(LServer.ProcessMessage(TTlsLibTestHandshakeDecoder.HandshakeMessage(
    FirstSendHandshake(LClient.Start))));
  LFailed := False;
  LAlert := TTlsAlertDescription.CloseNotify;
  for LI := 0 to High(LFlight) do
    if TTlsLibTestHandshakeDecoder.HandshakeMessage(LFlight[LI]).TypeByte = Byte(Ord(TTlsHandshakeType.Certificate)) then
    begin
      // the real server Certificate with its leaf swapped for the id-RSASSA-PSS certificate
      LCert := THandshakeMessages.DecodeCertificate(
        TTlsLibTestHandshakeDecoder.HandshakeMessage(LFlight[LI]).Body);
      LCert.Entries[0].CertData :=
        TTlsLibTestCertificates.Field('Certs/KeyUsagePss.txt', 'rsapss_cert');
      LCertMsg := THandshakeFraming.Frame(TTlsHandshakeType.Certificate,
        THandshakeMessages.EncodeCertificate(LCert));
      LFailed := FailAlertOf(LClient.ProcessMessage(
        TTlsLibTestHandshakeDecoder.HandshakeMessage(LCertMsg)), LAlert);
      Break;
    end
    else
      LClient.ProcessMessage(TTlsLibTestHandshakeDecoder.HandshakeMessage(LFlight[LI]));
  CheckTrue(LFailed,'the client aborts on the id-RSASSA-PSS server leaf');
  CheckEquals(Int64(Ord(TTlsAlertDescription.UnsupportedCertificate)), Int64(Ord(LAlert)),
    'the abort is unsupported_certificate');
end;

procedure TTestClientAuth.TestTls13ServerRefusesPssSpkiClientLeaf;
var
  LClient, LServer: IHandshakeMachine;
  LServerFlight, LClientFlight: TArray<TBytes>;
  LEffects: TArray<THandshakeEffect>;
  LCert: TTlsCertificate;
  LCertMsg: TBytes;
  LAlert: TTlsAlertDescription;
  LI: Int32;
begin
  LClient := New13ClientMachine(True);
  LServer := New13ServerMachine(TClientAuthMode.Required);
  LServerFlight := AllSendHandshake(LServer.ProcessMessage(TTlsLibTestHandshakeDecoder.HandshakeMessage(
    FirstSendHandshake(LClient.Start))));
  LEffects := nil;
  for LI := 0 to High(LServerFlight) do
    LEffects := LClient.ProcessMessage(TTlsLibTestHandshakeDecoder.HandshakeMessage(LServerFlight[LI]));
  LClientFlight := AllSendHandshake(LEffects);
  CheckTrue(System.Length(LClientFlight) > 0, 'the client answered the server flight');
  LCert := THandshakeMessages.DecodeCertificate(
    TTlsLibTestHandshakeDecoder.HandshakeMessage(LClientFlight[0]).Body);
  LCert.Entries[0].CertData :=
    TTlsLibTestCertificates.Field('Certs/KeyUsagePss.txt', 'rsapss_cert');
  LCertMsg := THandshakeFraming.Frame(TTlsHandshakeType.Certificate,
    THandshakeMessages.EncodeCertificate(LCert));
  CheckTrue(FailAlertOf(LServer.ProcessMessage(TTlsLibTestHandshakeDecoder.HandshakeMessage(LCertMsg)), LAlert),
    'the server aborts on the id-RSASSA-PSS client leaf');
  CheckEquals(Int64(Ord(TTlsAlertDescription.UnsupportedCertificate)), Int64(Ord(LAlert)),
    'the abort is unsupported_certificate');
end;

procedure TTestClientAuth.TestTls12ClientRefusesPssSpkiServerLeaf;
var
  LClient, LServer: ITlsEngine;
  LFlight: TBytes;
begin
  LClient := New12Client(False);
  LServer := New12Server(TClientAuthMode.None);
  LClient.StartHandshake;
  Pump(LClient, LServer);
  LFlight := ReplaceHandshakeMessage(Drain(LServer), Byte(Ord(TTlsHandshakeType.Certificate)),
    THandshakeFraming.Frame(TTlsHandshakeType.Certificate,
    THandshakeMessages.EncodeCertificate12(TArray<TBytes>.Create(
      TTlsLibTestCertificates.Field('Certs/KeyUsagePss.txt', 'rsapss_cert')))));
  CheckTrue(System.Length(LFlight) > 0, 'the server flight carries a Certificate to replace');
  Feed(LClient, LFlight);
  CheckTrue(LClient.IsTerminal, 'the client aborts on the id-RSASSA-PSS server leaf');
  CheckEquals(Int64(Ord(TTlsAlertDescription.UnsupportedCertificate)),
    Int64(Ord(LClient.LastError.Alert.Description)), 'the abort is unsupported_certificate');
end;

procedure TTestClientAuth.TestTls12ServerRefusesPssSpkiClientLeaf;
var
  LClient, LServer: ITlsEngine;
  LFlight: TBytes;
begin
  LClient := New12Client(True);
  LServer := New12Server(TClientAuthMode.Required);
  LClient.StartHandshake;
  Pump(LClient, LServer);
  Pump(LServer, LClient);
  LFlight := ReplaceHandshakeMessage(Drain(LClient), Byte(Ord(TTlsHandshakeType.Certificate)),
    THandshakeFraming.Frame(TTlsHandshakeType.Certificate,
    THandshakeMessages.EncodeCertificate12(TArray<TBytes>.Create(
      TTlsLibTestCertificates.Field('Certs/KeyUsagePss.txt', 'rsapss_cert')))));
  CheckTrue(System.Length(LFlight) > 0, 'the client flight carries a Certificate to replace');
  Feed(LServer, LFlight);
  CheckTrue(LServer.IsTerminal, 'the server aborts on the id-RSASSA-PSS client leaf');
  CheckEquals(Int64(Ord(TTlsAlertDescription.UnsupportedCertificate)),
    Int64(Ord(LServer.LastError.Alert.Description)), 'the abort is unsupported_certificate');
end;

procedure TTestClientAuth.TestTls13ClientCertPinMatchCompletes;
var
  LClient, LServer: ITlsEngine;
begin
  // a server that pins the client leaf's SPKI accepts the matching client certificate: the inner
  // verifier validates the chain and the pin matches, so the mTLS handshake completes
  LClient := New13Client(True);
  LServer := New13ServerPinned(TClientAuthMode.Required,
    TArray<TBytes>.Create(
      TTlsLibTestCertificates.SpkiSha256(Crypto, Pkix,
        TTlsLibTestCertificates.Field('Certs/ClientAuthChain.txt', 'leaf_cert'))));
  Drive(LClient, LServer);
  CheckFalse(LClient.IsHandshaking or LServer.IsHandshaking,
    '1.3 mTLS with a matching client-cert pin completes');
  CheckFalse(LClient.IsTerminal or LServer.IsTerminal,
    '1.3 mTLS with a matching client-cert pin: no failure');
end;

procedure TTestClientAuth.TestTls13ClientCertPinMismatchAborts;
var
  LClient, LServer: ITlsEngine;
begin
  // a server that pins a key the client does not present must REJECT the client certificate
  // (bad_certificate), not silently accept it: a wrong 32-byte pin can never match the presented leaf
  LClient := New13Client(True);
  LServer := New13ServerPinned(TClientAuthMode.Required,
    TArray<TBytes>.Create(Filled($AB, 32)));
  Drive(LClient, LServer);
  CheckTrue(LServer.IsTerminal, '1.3 mTLS with a non-matching client-cert pin fails closed');
  CheckEquals(Int64(Ord(TTlsAlertDescription.BadCertificate)),
    Int64(Ord(LServer.LastError.Alert.Description)),
    'a client-cert pin mismatch is bad_certificate');
end;

procedure TTestClientAuth.TestClientCertificateIsCompressedInBothDirections;
var
  LClient, LServer: ITlsEngine;
  LClientCompressor, LServerCompressor: TMockCertificateCompressor;
  LClientDecompressor, LServerDecompressor: TMockCertificateDecompressor;
begin
  // each side holds a compressor and a decompressor for zlib: the server compresses its
  // Certificate for the client (the existing direction) and, now that its CertificateRequest
  // advertises compress_certificate, the client compresses its own for the server
  LClientCompressor := TMockCertificateCompressor.Create(
    TCertificateCompressionAlgorithms.Zlib, TMockCompressorMode.Normal);
  LServerCompressor := TMockCertificateCompressor.Create(
    TCertificateCompressionAlgorithms.Zlib, TMockCompressorMode.Normal);
  LClientDecompressor := TMockCertificateDecompressor.Create(
    TCertificateCompressionAlgorithms.Zlib, TMockDecompressorMode.Works);
  LServerDecompressor := TMockCertificateDecompressor.Create(
    TCertificateCompressionAlgorithms.Zlib, TMockDecompressorMode.Works);
  LClient := New13CompressionPair(
    TArray<ICertificateCompressor>.Create(LClientCompressor as ICertificateCompressor),
    TArray<ICertificateDecompressor>.Create(LClientDecompressor as ICertificateDecompressor),
    nil,
    TArray<ICertificateCompressor>.Create(LServerCompressor as ICertificateCompressor),
    TArray<ICertificateDecompressor>.Create(LServerDecompressor as ICertificateDecompressor),
    LServer);
  Drive(LClient, LServer);
  CheckFalse(LClient.IsTerminal or LServer.IsTerminal, 'the handshake completed');
  CheckEquals(1, LServerCompressor.Count, 'the server compressed its Certificate');
  CheckEquals(1, LClientDecompressor.Count, 'the client decompressed the server Certificate');
  CheckEquals(1, LClientCompressor.Count, 'the client compressed its own Certificate');
  CheckEquals(1, LServerDecompressor.Count, 'the server decompressed the client Certificate');
end;

procedure TTestClientAuth.TestEmptyClientCompressorsSendAPlainCertificate;
var
  LClient, LServer: ITlsEngine;
  LServerDecompressor: TMockCertificateDecompressor;
begin
  // an empty compressor set turns client-certificate compression off, whatever the server advertises
  LServerDecompressor := TMockCertificateDecompressor.Create(
    TCertificateCompressionAlgorithms.Zlib, TMockDecompressorMode.Works);
  LClient := New13CompressionPair(nil,
    TZlibCertificateCompression.DefaultDecompressors, nil,
    TZlibCertificateCompression.DefaultCompressors,
    TArray<ICertificateDecompressor>.Create(LServerDecompressor as ICertificateDecompressor),
    LServer);
  Drive(LClient, LServer);
  CheckFalse(LClient.IsTerminal or LServer.IsTerminal, 'the handshake completed');
  CheckEquals(0, LServerDecompressor.Count, 'the client sent a plain Certificate');
end;

procedure TTestClientAuth.TestServerAdvertisingNothingGetsAPlainCertificate;
var
  LClient, LServer: ITlsEngine;
  LClientCompressor: TMockCertificateCompressor;
begin
  // a server with no decompressors advertises nothing, so there is no common algorithm to use
  LClientCompressor := TMockCertificateCompressor.Create(
    TCertificateCompressionAlgorithms.Zlib, TMockCompressorMode.Normal);
  LClient := New13CompressionPair(
    TArray<ICertificateCompressor>.Create(LClientCompressor as ICertificateCompressor),
    TZlibCertificateCompression.DefaultDecompressors, nil,
    TZlibCertificateCompression.DefaultCompressors, nil, LServer);
  Drive(LClient, LServer);
  CheckFalse(LClient.IsTerminal or LServer.IsTerminal, 'the handshake completed');
  CheckEquals(0, LClientCompressor.Count, 'the client had nothing to compress for');
end;

procedure TTestClientAuth.TestClientCertificateCompressionIsMemoizedOnTheClient;
var
  LCache: ICertificateCompressionCache;
  LClient, LServer: ITlsEngine;
  LClientCompressor: TMockCertificateCompressor;
  LClientCompressorRef: ICertificateCompressor;
begin
  // two handshakes from one client config compress the same Certificate once through a shared cache
  LCache := TInMemoryCertificateCompressionCache.Create;
  LClientCompressor := TMockCertificateCompressor.Create(
    TCertificateCompressionAlgorithms.Zlib, TMockCompressorMode.Normal);
  LClientCompressorRef := LClientCompressor;
  LClient := New13CompressionPair(TArray<ICertificateCompressor>.Create(LClientCompressorRef),
    TZlibCertificateCompression.DefaultDecompressors, LCache,
    TZlibCertificateCompression.DefaultCompressors,
    TZlibCertificateCompression.DefaultDecompressors, LServer);
  Drive(LClient, LServer);
  CheckFalse(LClient.IsTerminal or LServer.IsTerminal, 'the first handshake completed');
  LClient := New13CompressionPair(TArray<ICertificateCompressor>.Create(LClientCompressorRef),
    TZlibCertificateCompression.DefaultDecompressors, LCache,
    TZlibCertificateCompression.DefaultCompressors,
    TZlibCertificateCompression.DefaultDecompressors, LServer);
  Drive(LClient, LServer);
  CheckFalse(LClient.IsTerminal or LServer.IsTerminal, 'the second handshake completed');
  CheckEquals(1, LClientCompressor.Count, 'the second handshake was served from the cache');
end;

procedure TTestClientAuth.TestDecliningClientCompressorSendsAPlainCertificate;
var
  LClient, LServer: ITlsEngine;
  LClientCompressor: TMockCertificateCompressor;
  LServerDecompressor: TMockCertificateDecompressor;
begin
  // a compressor that declines (False) leaves the Certificate uncompressed: compression is a MAY
  LClientCompressor := TMockCertificateCompressor.Create(
    TCertificateCompressionAlgorithms.Zlib, TMockCompressorMode.Decline);
  LServerDecompressor := TMockCertificateDecompressor.Create(
    TCertificateCompressionAlgorithms.Zlib, TMockDecompressorMode.Works);
  LClient := New13CompressionPair(
    TArray<ICertificateCompressor>.Create(LClientCompressor as ICertificateCompressor),
    TZlibCertificateCompression.DefaultDecompressors, nil,
    TZlibCertificateCompression.DefaultCompressors,
    TArray<ICertificateDecompressor>.Create(LServerDecompressor as ICertificateDecompressor),
    LServer);
  Drive(LClient, LServer);
  CheckFalse(LClient.IsTerminal or LServer.IsTerminal, 'the handshake completed');
  CheckEquals(1, LClientCompressor.Count, 'the compressor was asked');
  CheckEquals(0, LServerDecompressor.Count, 'and the plain Certificate needed no decompression');
end;

procedure TTestClientAuth.TestCompressorReportingSuccessWithNothingFailsTheHandshake;
var
  LClient, LServer: ITlsEngine;
begin
  // True with an empty result breaks the compressor contract (RFC 8879 4: <1..2^24-1>): that is a
  // loud internal_error, not a silent fall back to uncompressed
  LClient := New13CompressionPair(
    TArray<ICertificateCompressor>.Create(
    TMockCertificateCompressor.Create(TCertificateCompressionAlgorithms.Zlib,
    TMockCompressorMode.EmptySuccess) as ICertificateCompressor),
    TZlibCertificateCompression.DefaultDecompressors, nil,
    TZlibCertificateCompression.DefaultCompressors,
    TZlibCertificateCompression.DefaultDecompressors, LServer);
  Drive(LClient, LServer);
  CheckTrue(LClient.IsTerminal, 'the handshake failed on the broken compressor');
  CheckEquals(Int64(Ord(TTlsAlertDescription.InternalError)),
    Int64(Ord(LClient.LastError.Alert.Description)), 'as internal_error');
end;

procedure TTestClientAuth.TestRaisingCompressorIsNotSwallowed;
var
  LClient, LServer: ITlsEngine;
  LClientCompressor: TMockCertificateCompressor;
begin
  // an exception from a compressor is a bug or an unrecoverable condition: the engine does not
  // catch it and fall back, it fails the handshake
  LClientCompressor := TMockCertificateCompressor.Create(
    TCertificateCompressionAlgorithms.Zlib, TMockCompressorMode.Throws);
  LClient := New13CompressionPair(
    TArray<ICertificateCompressor>.Create(LClientCompressor as ICertificateCompressor),
    TZlibCertificateCompression.DefaultDecompressors, nil,
    TZlibCertificateCompression.DefaultCompressors,
    TZlibCertificateCompression.DefaultDecompressors, LServer);
  Drive(LClient, LServer);
  CheckTrue(LClient.IsTerminal, 'the handshake failed rather than continuing uncompressed');
  CheckEquals(1, LClientCompressor.Count, 'the compressor was reached once');
end;

procedure TTestClientAuth.TestFailingDecompressorIsBadCertificate;
var
  LClient, LServer: ITlsEngine;
begin
  // a decompressor that cannot decompress the client's input (False) is the RFC 8879 4 bad_certificate
  LClient := New13CompressionPair(TZlibCertificateCompression.DefaultCompressors,
    TZlibCertificateCompression.DefaultDecompressors, nil,
    TZlibCertificateCompression.DefaultCompressors,
    TArray<ICertificateDecompressor>.Create(
    TMockCertificateDecompressor.Create(TCertificateCompressionAlgorithms.Zlib,
    TMockDecompressorMode.Fails) as ICertificateDecompressor), LServer);
  Drive(LClient, LServer);
  CheckTrue(LServer.IsTerminal, 'the server aborted');
  CheckEquals(Int64(Ord(TTlsAlertDescription.BadCertificate)),
    Int64(Ord(LServer.LastError.Alert.Description)), 'with bad_certificate');
end;

procedure TTestClientAuth.TestRaisingDecompressorIsBadCertificate;
var
  LClient, LServer: ITlsEngine;
begin
  // a backend that raises its own exception on the peer's input is still bad_certificate, not
  // internal_error: the mapping lives in one place and an implementation need know nothing about TLS
  LClient := New13CompressionPair(TZlibCertificateCompression.DefaultCompressors,
    TZlibCertificateCompression.DefaultDecompressors, nil,
    TZlibCertificateCompression.DefaultCompressors,
    TArray<ICertificateDecompressor>.Create(
    TMockCertificateDecompressor.Create(TCertificateCompressionAlgorithms.Zlib,
    TMockDecompressorMode.Raises) as ICertificateDecompressor), LServer);
  Drive(LClient, LServer);
  CheckTrue(LServer.IsTerminal, 'the server aborted');
  CheckEquals(Int64(Ord(TTlsAlertDescription.BadCertificate)),
    Int64(Ord(LServer.LastError.Alert.Description)), 'with bad_certificate');
end;

procedure TTestClientAuth.TestWrongLengthDecompressionIsBadCertificate;
var
  LClient, LServer: ITlsEngine;
begin
  // a result whose length is not the declared one is bad_certificate (RFC 8879 4)
  LClient := New13CompressionPair(TZlibCertificateCompression.DefaultCompressors,
    TZlibCertificateCompression.DefaultDecompressors, nil,
    TZlibCertificateCompression.DefaultCompressors,
    TArray<ICertificateDecompressor>.Create(
    TMockCertificateDecompressor.Create(TCertificateCompressionAlgorithms.Zlib,
    TMockDecompressorMode.WrongLength) as ICertificateDecompressor),
    LServer);
  Drive(LClient, LServer);
  CheckTrue(LServer.IsTerminal, 'the server aborted');
  CheckEquals(Int64(Ord(TTlsAlertDescription.BadCertificate)),
    Int64(Ord(LServer.LastError.Alert.Description)), 'with bad_certificate');
end;

procedure TTestClientAuth.TestClientDecompressorContractBreachesAreBadCertificate;
var
  LModes: array[0..2] of TMockDecompressorMode;
  LI: Int32;
  LClient, LServer: ITlsEngine;
begin
  // the central mapping holds for the client receiving the server's Certificate just as for the
  // server receiving the client's: a False, a raise, or a wrong length is bad_certificate
  LModes[0] := TMockDecompressorMode.Fails;
  LModes[1] := TMockDecompressorMode.Raises;
  LModes[2] := TMockDecompressorMode.WrongLength;
  for LI := 0 to 2 do
  begin
    LClient := New13CompressionPair(TZlibCertificateCompression.DefaultCompressors,
      TArray<ICertificateDecompressor>.Create(
      TMockCertificateDecompressor.Create(TCertificateCompressionAlgorithms.Zlib,
      LModes[LI]) as ICertificateDecompressor), nil,
      TZlibCertificateCompression.DefaultCompressors,
      TZlibCertificateCompression.DefaultDecompressors, LServer);
    Drive(LClient, LServer);
    CheckTrue(LClient.IsTerminal, 'the client aborted');
    CheckEquals(Int64(Ord(TTlsAlertDescription.BadCertificate)),
      Int64(Ord(LClient.LastError.Alert.Description)), 'with bad_certificate');
  end;
end;

procedure TTestClientAuth.TestOversizeCompressionFallsBackToAPlainCertificate;
var
  LFramed: TBytes;
begin
  // a result past the 2^24-1 ceiling cannot be framed, so the Certificate goes out plain
  LFramed := TCertificateCompression.FrameCertificate(
    TArray<ICertificateCompressor>.Create(
    TMockCertificateCompressor.Create(TCertificateCompressionAlgorithms.Zlib,
    TMockCompressorMode.Oversize) as ICertificateCompressor),
    TArray<UInt16>.Create(TCertificateCompressionAlgorithms.Zlib), nil, Crypto,
    TBytes.Create($00, $00, $00, $00), True);
  CheckEquals(Int64(Ord(TTlsHandshakeType.Certificate)), Int64(LFramed[0]),
    'framed as a plain Certificate');
end;

function TTestClientAuth.CompressedClientCertificate: TBytes;
var
  LCert: TTlsCertificate;
  LMsg: TTlsCompressedCertificate;
  LBody: TBytes;
  LI: Int32;
begin
  LCert.RequestContext := nil;
  SetLength(LCert.Entries, System.Length(Credential.CertificateChain));
  for LI := 0 to High(Credential.CertificateChain) do
  begin
    LCert.Entries[LI].CertData := Credential.CertificateChain[LI];
    LCert.Entries[LI].Extensions := TBytes.Create($00, $00);
  end;
  LBody := THandshakeMessages.EncodeCertificate(LCert);
  LMsg.Algorithm := TCertificateCompressionAlgorithms.Zlib;
  LMsg.UncompressedLength := System.Length(LBody);
  CheckTrue(TZlibCertificateCompression.DefaultCompressors[0].TryCompress(LBody, LMsg.Compressed),
    'the fixture compresses');
  Result := THandshakeFraming.Frame(TTlsHandshakeType.CompressedCertificate,
    THandshakeMessages.EncodeCompressedCertificate(LMsg));
end;

procedure TTestClientAuth.TestUnsolicitedCompressedCertificateIsUnexpected;
var
  LClient, LServer: IHandshakeMachine;
  LServerFlight: TArray<TBytes>;
  LAlert: TTlsAlertDescription;
begin
  // a server with no decompressors advertised nothing in its CertificateRequest, so a
  // CompressedCertificate is unsolicited (RFC 8879 4)
  LClient := New13ClientMachine(True);
  LServer := New13ServerMachine(TClientAuthMode.Required);
  LServerFlight := AllSendHandshake(LServer.ProcessMessage(
    TTlsLibTestHandshakeDecoder.HandshakeMessage(FirstSendHandshake(LClient.Start))));
  CheckTrue(FailAlertOf(LServer.ProcessMessage(TTlsLibTestHandshakeDecoder.HandshakeMessage(
    CompressedClientCertificate)), LAlert), 'an unsolicited CompressedCertificate aborts');
  CheckEquals(Int64(Ord(TTlsAlertDescription.UnexpectedMessage)), Int64(Ord(LAlert)),
    'the abort is unexpected_message');
end;

procedure TTestClientAuth.TestCompressedCertificateWithoutClientAuthIsUnexpected;
var
  LClient, LServer: IHandshakeMachine;
  LServerFlight: TArray<TBytes>;
  LAlert: TTlsAlertDescription;
begin
  // a server that asked for no client certificate takes a CompressedCertificate no more than a
  // Certificate
  LClient := New13ClientMachine(False);
  LServer := New13ServerMachine(TClientAuthMode.None);
  LServerFlight := AllSendHandshake(LServer.ProcessMessage(
    TTlsLibTestHandshakeDecoder.HandshakeMessage(FirstSendHandshake(LClient.Start))));
  CheckTrue(FailAlertOf(LServer.ProcessMessage(TTlsLibTestHandshakeDecoder.HandshakeMessage(
    CompressedClientCertificate)), LAlert), 'a CompressedCertificate with no client auth aborts');
  CheckEquals(Int64(Ord(TTlsAlertDescription.UnexpectedMessage)), Int64(Ord(LAlert)),
    'the abort is unexpected_message');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestClientAuth);
{$ELSE}
  RegisterTest(TTestClientAuth.Suite);
{$ENDIF FPC}

end.
