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
  TlpTrustTypes,
  TlpCertificateVerify,
  TlpTlsAlert,
  TlpTlsLibExceptions,
  TlpServerName,
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
    function PeerVerifier: TCertificateVerifier;
    function New13Client(AWithCredential: Boolean): ITlsEngine;
    function New13Server(AMode: TClientAuthMode): ITlsEngine;
    function New13ClientMachine(AWithCredential: Boolean): IHandshakeMachine;
    function New13ServerMachine(AMode: TClientAuthMode): IHandshakeMachine;
    function MsgFrom(const AFramed: TBytes): TTlsHandshakeMessage;
    function FirstSendHandshake(const AEffects: TArray<THandshakeEffect>): TBytes;
    function AllSendHandshake(const AEffects: TArray<THandshakeEffect>): TArray<TBytes>;
    function FailAlertOf(const AEffects: TArray<THandshakeEffect>;
      out AAlert: TTlsAlertDescription): Boolean;
    function New12Client(AWithCredential: Boolean): ITlsEngine;
    function New12Server(AMode: TClientAuthMode): ITlsEngine;
    function Drain(const AEngine: ITlsEngine): TBytes;
    procedure Feed(const AEngine: ITlsEngine; const AWire: TBytes);
    // rewrites the signature scheme of the first plaintext CertificateVerify (handshake type 15)
    // in a wire flight, to forge a client CertificateVerify under an unadvertised scheme
    procedure PatchFirstCertVerifyScheme(var AWire: TBytes; AScheme: UInt16);
    // inserts a duplicate of the first CertificateRequest (handshake type 13) record into a wire
    // flight, right after the original, to drive a second CertificateRequest in the same phase
    function DuplicateCertificateRequest(const AWire: TBytes): TBytes;
    procedure Pump(const ASrc, ADst: ITlsEngine);
    procedure Drive(const AClient, AServer: ITlsEngine);
  published
    procedure TestTls13RequiredClientAuthCompletes;
    procedure TestTls13RequiredClientAuthMissingCertAborts;
    procedure TestTls13RequestedClientAuthWithoutCertCompletes;
    procedure TestTls12RequiredClientAuthCompletes;
    procedure TestTls12RequiredClientAuthMissingCertAborts;
    procedure TestTls12RequestedClientAuthWithoutCertCompletes;
    procedure TestVerifyClientChainNilVerifierFailsClosed;
    procedure TestTls13NilClientVerifierWithCertAborts;
    procedure TestTls12ServerRejectsUnrequestedClientCertVerifyScheme;
    procedure TestTls12ClientRejectsSecondCertificateRequest;
    procedure TestTls13CertificateRequestWithoutSignatureAlgorithmsAborts;
  end;

implementation

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
  LCerts := LoadVectorFields('Certs/ClientAuthChain.txt');
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
  LCerts := LoadVectorFields('Certs/ClientAuthChain.txt');
  try
    Result.CertificateChain := TArray<TBytes>.Create(
      DecodeHex(LCerts.Values['leaf_cert']));
    Result.PrivateKey := Crypto.Signing.ImportSigningKey(DecodeHex(LCerts.Values['leaf_key']));
  finally
    LCerts.Free;
  end;
end;

function TTestClientAuth.PeerVerifier: TCertificateVerifier;
begin
  // trusts the test root; hostname identity is not applied to a peer certificate
  Result := TCertificateVerifier.Create(Pkix, TSystemClock.Create as ITlsClock,
    TTrustAnchorStore.Create(TArray<TBytes>.Create(RootCert)) as ITrustAnchorStore,
    False);
end;

function TTestClientAuth.New13Client(AWithCredential: Boolean): ITlsEngine;
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
  Result := TTlsEngine.CreateConfigured(
    TTls13ClientStateMachine.Create(LParams) as IHandshakeMachine, Crypto);
end;

function TTestClientAuth.New13Server(AMode: TClientAuthMode): ITlsEngine;
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

function TTestClientAuth.MsgFrom(const AFramed: TBytes): TTlsHandshakeMessage;
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

function TTestClientAuth.FirstSendHandshake(
  const AEffects: TArray<THandshakeEffect>): TBytes;
var
  LEffect: THandshakeEffect;
begin
  Result := nil;
  for LEffect in AEffects do
    if LEffect.Kind = THandshakeEffectKind.SendHandshake then
      Exit(LEffect.Bytes);
end;

function TTestClientAuth.AllSendHandshake(
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

function TTestClientAuth.FailAlertOf(const AEffects: TArray<THandshakeEffect>;
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

function TTestClientAuth.New12Client(AWithCredential: Boolean): ITlsEngine;
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
  // curve (RFC 8422 5.1), so it lists X25519 and Secp256r1 (the P-256 certificate curve)
  LParams.OfferedGroups := TArray<UInt16>.Create(TNamedGroupCatalog.X25519,
    TNamedGroupCatalog.Secp256r1);
  LParams.OfferedSchemes := TArray<UInt16>.Create(TSignatureSchemes.EcdsaSecp256r1Sha256);
  LParams.OfferedVersions := TArray<UInt16>.Create(TlsWireVersionTls12);
  LParams.ClientRandom := Filled($11, 32);
  LParams.OfferExtendedMasterSecret := True;
  LParams.CertificateVerifier := PeerVerifier;
  LParams.ExpectedServerName := TServerName.DnsName('localhost');
  if AWithCredential then
    LParams.ClientCredential := Credential;
  Result := TTlsEngine.CreateConfigured(
    TTls12ClientStateMachine.Create(LParams) as IHandshakeMachine, Crypto);
end;

function TTestClientAuth.New12Server(AMode: TClientAuthMode): ITlsEngine;
var
  LParams: TServer12HandshakeParams;
begin
  LParams := Default(TServer12HandshakeParams);
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

procedure TTestClientAuth.PatchFirstCertVerifyScheme(var AWire: TBytes;
  AScheme: UInt16);
var
  LPos, LRecLen, LInner, LMsgLen: Int32;
begin
  LPos := 0;
  while LPos + 5 <= System.Length(AWire) do
  begin
    LRecLen := (AWire[LPos + 3] shl 8) or AWire[LPos + 4];
    if AWire[LPos] = 22 then // handshake record (plaintext, before the client ChangeCipherSpec)
    begin
      LInner := LPos + 5;
      while LInner + 4 <= LPos + 5 + LRecLen do
      begin
        LMsgLen := (AWire[LInner + 1] shl 16) or (AWire[LInner + 2] shl 8) or
          AWire[LInner + 3];
        if AWire[LInner] = 15 then // CertificateVerify: body starts with the 2-byte scheme
        begin
          AWire[LInner + 4] := Byte(AScheme shr 8);
          AWire[LInner + 5] := Byte(AScheme and $FF);
          Exit;
        end;
        LInner := LInner + 4 + LMsgLen;
      end;
    end;
    LPos := LPos + 5 + LRecLen;
  end;
end;

function TTestClientAuth.DuplicateCertificateRequest(const AWire: TBytes): TBytes;
var
  LPos, LRecLen, LInner, LMsgLen: Int32;
  LMsg, LRecord: TBytes;
begin
  LPos := 0;
  while LPos + 5 <= System.Length(AWire) do
  begin
    LRecLen := (AWire[LPos + 3] shl 8) or AWire[LPos + 4];
    if AWire[LPos] = 22 then // handshake record (plaintext, before any ChangeCipherSpec)
    begin
      LInner := LPos + 5;
      while LInner + 4 <= LPos + 5 + LRecLen do
      begin
        LMsgLen := (AWire[LInner + 1] shl 16) or (AWire[LInner + 2] shl 8) or
          AWire[LInner + 3];
        if AWire[LInner] = 13 then // CertificateRequest
        begin
          LMsg := System.Copy(AWire, LInner, 4 + LMsgLen);
          LRecord := ConcatBytes(TBytes.Create(22, 3, 3, Byte(System.Length(LMsg) shr 8),
            Byte(System.Length(LMsg) and $FF)), LMsg);
          // original wire up to and including this record, then the duplicate, then the rest
          Result := ConcatBytes(ConcatBytes(
            System.Copy(AWire, 0, LPos + 5 + LRecLen), LRecord),
            System.Copy(AWire, LPos + 5 + LRecLen,
            System.Length(AWire) - (LPos + 5 + LRecLen)));
          Exit;
        end;
        LInner := LInner + 4 + LMsgLen;
      end;
    end;
    LPos := LPos + 5 + LRecLen;
  end;
  Result := System.Copy(AWire);
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
  // a CertificateRequest may appear at most once (RFC 5246 7.4.4); duplicating the server's real
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
  // a TLS 1.3 CertificateRequest MUST carry signature_algorithms (RFC 8446 4.3.2); drive the
  // client to WaitCertificate, then feed a CertificateRequest whose extensions omit it
  LClient := New13ClientMachine(True);
  LServer := New13ServerMachine(TClientAuthMode.Required);
  LFlight := AllSendHandshake(LServer.ProcessMessage(MsgFrom(FirstSendHandshake(LClient.Start))));
  LClient.ProcessMessage(MsgFrom(LFlight[0])); // ServerHello
  LClient.ProcessMessage(MsgFrom(LFlight[1])); // EncryptedExtensions
  LReq.RequestContext := nil;
  LReq.Extensions := TBytes.Create($00, $00); // a present-but-empty extensions vector
  LCertReq := THandshakeFraming.Frame(TTlsHandshakeType.CertificateRequest,
    THandshakeMessages.EncodeCertificateRequest13(LReq));
  CheckTrue(FailAlertOf(LClient.ProcessMessage(MsgFrom(LCertReq)), LAlert),
    'a CertificateRequest without signature_algorithms aborts');
  CheckEquals(Int64(Ord(TTlsAlertDescription.MissingExtension)), Int64(Ord(LAlert)),
    'the abort is missing_extension');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestClientAuth);
{$ELSE}
  RegisterTest(TTestClientAuth.Suite);
{$ENDIF FPC}

end.
