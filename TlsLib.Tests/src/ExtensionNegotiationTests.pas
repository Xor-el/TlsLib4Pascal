{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ExtensionNegotiationTests;

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
  TlpCryptoAlgorithms,
  TlpINamedGroup,
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
  TlpExtensionContext,
  TlpITlsExtension,
  TlpExtensionBlockCodec,
  TlpTlsLibExceptions,
  TlpGrease,
  TlpCertificateCompression,
  TlpICertificateCompression,
  TlpZlibCertificateCompression,
  TlpICertificateTrust,
  TlpCertificateVerifier,
  TlpSecretBuffer,
  TlpTlsCredential,
  TlpCredentialResolvers,
  TlpTls13ClientStateMachine,
  TlpTls13ServerStateMachine,
  TlsLibTestBase;

type
  TTestExtensionNegotiation = class(TTlsLibAlgorithmTestCase)
  private
    function TestRootCertificate: TBytes;
    function ServerCredential: TTlsCredential;
    function NewClient(const AAlpn: TArray<string>; ARecordSizeLimit: Int32): ITlsEngine;
    function NewServer(const AAlpn: TArray<string>; ARecordSizeLimit: Int32): ITlsEngine;
    function Drain(const AEngine: ITlsEngine): TBytes;
    procedure Feed(const AEngine: ITlsEngine; const AWire: TBytes);
    procedure Pump(const ASrc, ADst: ITlsEngine);
    function ReadAllApp(const AEngine: ITlsEngine): TBytes;
    procedure Handshake(const AClient, AServer: ITlsEngine);
    function MaxAppRecordLength(const AWire: TBytes): Int32;
    function AppRecordCount(const AWire: TBytes): Int32;
    function NewClientMachine(const AAlpn: TArray<string>): IHandshakeMachine;
    function NewClientMachineWith(const AAlpn: TArray<string>;
      const ADecompressors: TArray<ICertificateDecompressor>): IHandshakeMachine;
    function NewServerMachine(const AAlpn: TArray<string>): IHandshakeMachine;
    function NewServerMachineWith(const AChain: TArray<TBytes>;
      const ACompressors: TArray<ICertificateCompressor>): IHandshakeMachine;
    function CredentialWithChain(const AChain: TArray<TBytes>): TTlsCredential;
    function DriveServerCertMessage(const AClient,
      AServer: IHandshakeMachine): TTlsHandshakeMessage;
    function PlaintextCertBody(const AChain: TArray<TBytes>): TBytes;
    function CompressibleChain: TArray<TBytes>;
    function IncompressibleChain: TArray<TBytes>;
    function ZlibCompress(const AData: TBytes): TBytes;
    function MsgFrom(const AFramed: TBytes): TTlsHandshakeMessage;
    function FirstSendHandshake(const AEffects: TArray<THandshakeEffect>): TBytes;
    function AllSendHandshake(const AEffects: TArray<THandshakeEffect>): TArray<TBytes>;
    function FailAlertOf(const AEffects: TArray<THandshakeEffect>;
      out AAlert: TTlsAlertDescription): Boolean;
    function BuildEncryptedExtensionsWithAlpn(const AProtocol: string): TBytes;
    function NewGreasingClient: ITlsEngine;
    function ServerHelloFrom(const AWire: TBytes): TTlsServerHello;
    function DriveClientToWaitCertificate(
      out AServerFlight: TArray<TBytes>): IHandshakeMachine;
    function CompressedCertificateOf(AAlgorithm: UInt16;
      AUncompressedLength: Int32; const ACompressed: TBytes): TBytes;
  published
    procedure TestAlpnNegotiatesAndSurfaces;
    procedure TestAlpnNoOverlapAborts;
    procedure TestNoAlpnConfiguredSurfacesEmpty;
    procedure TestClientRejectsUnofferedAlpnEcho;
    procedure TestRecordSizeLimitCapsOutboundRecords;
    procedure TestServerRejectsRecordSizeLimitBelowMinimum;
    procedure TestGreaseValueClassification;
    procedure TestClientGreaseToleratedAndNeverSelected;
    procedure TestUnknownHandshakeTypeUnexpected;
    procedure TestCertificateVerifyBeforeCertificateUnexpected;
    procedure TestClientAcceptsCompressedCertificate;
    procedure TestClientRejectsCompressedCertificateBomb;
    procedure TestClientRejectsUnadvertisedCompressionAlgorithm;
    procedure TestServerEmitsCompressedCertificate;
    procedure TestServerSkipsCompressionWhenNotSmaller;
    procedure TestCertificateCompressionIsInjectable;
    procedure TestEcPointFormatsRoundTrip;
    procedure TestEcPointFormatsWithoutUncompressedRejected;
    procedure TestAlpnServerHelloSelectionRoundTrip;
    procedure TestAlpnServerHelloEmptyProtocolRejected;
  end;

implementation

const
  // a private RFC 8879 codepoint standing in for a non-built-in backend
  CustomCertCompressionAlgo = UInt16($FF01);

type
  // a stand-in compression backend under a private codepoint: it reuses zlib bytes,
  // so a green test proves the seam dispatches by injected algorithm, not a fixed path
  TCustomCertCompressor = class(TInterfacedObject, ICertificateCompressor)
  public
    function Algorithm: UInt16;
    function Compress(const AData: TBytes): TBytes;
  end;

  TCustomCertDecompressor = class(TInterfacedObject, ICertificateDecompressor)
  public
    function Algorithm: UInt16;
    function Decompress(const ACompressed: TBytes; AMaxLength: Int32): TBytes;
  end;

function TCustomCertCompressor.Algorithm: UInt16;
begin
  Result := CustomCertCompressionAlgo;
end;

function TCustomCertCompressor.Compress(const AData: TBytes): TBytes;
var
  LZlib: TArray<ICertificateCompressor>;
begin
  LZlib := TZlibCertificateCompression.DefaultCompressors;
  Result := LZlib[0].Compress(AData);
end;

function TCustomCertDecompressor.Algorithm: UInt16;
begin
  Result := CustomCertCompressionAlgo;
end;

function TCustomCertDecompressor.Decompress(const ACompressed: TBytes;
  AMaxLength: Int32): TBytes;
var
  LZlib: TArray<ICertificateDecompressor>;
begin
  LZlib := TZlibCertificateCompression.DefaultDecompressors;
  Result := LZlib[0].Decompress(ACompressed, AMaxLength);
end;

{ TTestExtensionNegotiation }

function TTestExtensionNegotiation.ZlibCompress(const AData: TBytes): TBytes;
var
  LCompressors: TArray<ICertificateCompressor>;
begin
  // compress a Certificate body with the built-in zlib compressor
  LCompressors := TZlibCertificateCompression.DefaultCompressors;
  Result := LCompressors[0].Compress(AData);
end;

function TTestExtensionNegotiation.TestRootCertificate: TBytes;
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

function TTestExtensionNegotiation.ServerCredential: TTlsCredential;
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

function TTestExtensionNegotiation.NewClient(const AAlpn: TArray<string>;
  ARecordSizeLimit: Int32): ITlsEngine;
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
  LParams.AlpnProtocols := AAlpn;
  LParams.RecordSizeLimit := ARecordSizeLimit;
  LParams.ClientRandom := DecodeHex(StringOfChar('1', 64));
  LParams.LegacySessionId := DecodeHex(StringOfChar('3', 64));
  LParams.CertificateVerifier := TCertificateVerifier.Create(Provider, TSystemClock.Create as ITlsClock,
    TTrustAnchorStore.Create(TArray<TBytes>.Create(TestRootCertificate)) as ITrustAnchorStore,
    True) as ICertificateVerifier;
  LParams.ExpectedHostName := 'localhost';
  Result := TTlsEngine.CreateConfigured(
    TTls13ClientStateMachine.Create(LParams) as IHandshakeMachine, Provider);
end;

function TTestExtensionNegotiation.NewServer(const AAlpn: TArray<string>;
  ARecordSizeLimit: Int32): ITlsEngine;
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
  LParams.ServerRandom := DecodeHex(StringOfChar('2', 64));
  LParams.AlpnProtocols := AAlpn;
  LParams.RecordSizeLimit := ARecordSizeLimit;
  LParams.CredentialResolver := TSniCredentialResolver.ForCredential(ServerCredential);
  Result := TTlsEngine.CreateConfigured(
    TTls13ServerStateMachine.Create(LParams) as IHandshakeMachine, Provider);
end;

function TTestExtensionNegotiation.Drain(const AEngine: ITlsEngine): TBytes;
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

procedure TTestExtensionNegotiation.Feed(const AEngine: ITlsEngine;
  const AWire: TBytes);
begin
  if System.Length(AWire) > 0 then
    AEngine.ProcessInput(AWire, 0, System.Length(AWire));
end;

procedure TTestExtensionNegotiation.Pump(const ASrc, ADst: ITlsEngine);
begin
  Feed(ADst, Drain(ASrc));
end;

function TTestExtensionNegotiation.ReadAllApp(const AEngine: ITlsEngine): TBytes;
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

procedure TTestExtensionNegotiation.Handshake(const AClient, AServer: ITlsEngine);
var
  LIterations: Int32;
begin
  AClient.StartHandshake;
  LIterations := 0;
  while (AClient.IsHandshaking or AServer.IsHandshaking) and (LIterations < 16) do
  begin
    Pump(AClient, AServer);
    Pump(AServer, AClient);
    Inc(LIterations);
  end;
end;

function TTestExtensionNegotiation.MaxAppRecordLength(const AWire: TBytes): Int32;
var
  LPos, LLen: Int32;
begin
  Result := 0;
  LPos := 0;
  while LPos + 5 <= System.Length(AWire) do
  begin
    LLen := (AWire[LPos + 3] shl 8) or AWire[LPos + 4];
    if (AWire[LPos] = 23) and (LLen > Result) then // application_data
      Result := LLen;
    Inc(LPos, 5 + LLen);
  end;
end;

function TTestExtensionNegotiation.AppRecordCount(const AWire: TBytes): Int32;
var
  LPos, LLen: Int32;
begin
  Result := 0;
  LPos := 0;
  while LPos + 5 <= System.Length(AWire) do
  begin
    LLen := (AWire[LPos + 3] shl 8) or AWire[LPos + 4];
    if AWire[LPos] = 23 then
      Inc(Result);
    Inc(LPos, 5 + LLen);
  end;
end;

function TTestExtensionNegotiation.NewClientMachine(
  const AAlpn: TArray<string>): IHandshakeMachine;
begin
  Result := NewClientMachineWith(AAlpn, TZlibCertificateCompression.DefaultDecompressors);
end;

function TTestExtensionNegotiation.NewClientMachineWith(
  const AAlpn: TArray<string>;
  const ADecompressors: TArray<ICertificateDecompressor>): IHandshakeMachine;
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
  LParams.AlpnProtocols := AAlpn;
  LParams.ClientRandom := DecodeHex(StringOfChar('1', 64));
  LParams.LegacySessionId := DecodeHex(StringOfChar('3', 64));
  LParams.CertificateVerifier := TCertificateVerifier.Create(Provider, TSystemClock.Create as ITlsClock,
    TTrustAnchorStore.Create(TArray<TBytes>.Create(TestRootCertificate)) as ITrustAnchorStore,
    True) as ICertificateVerifier;
  LParams.CertificateDecompressors := ADecompressors;
  LParams.ExpectedHostName := 'localhost';
  Result := TTls13ClientStateMachine.Create(LParams) as IHandshakeMachine;
end;

function TTestExtensionNegotiation.NewServerMachine(
  const AAlpn: TArray<string>): IHandshakeMachine;
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
  LParams.ServerRandom := DecodeHex(StringOfChar('2', 64));
  LParams.AlpnProtocols := AAlpn;
  LParams.CredentialResolver := TSniCredentialResolver.ForCredential(ServerCredential);
  Result := TTls13ServerStateMachine.Create(LParams) as IHandshakeMachine;
end;

function TTestExtensionNegotiation.NewServerMachineWith(
  const AChain: TArray<TBytes>;
  const ACompressors: TArray<ICertificateCompressor>): IHandshakeMachine;
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
  LParams.ServerRandom := DecodeHex(StringOfChar('2', 64));
  LParams.CertificateCompressors := ACompressors;
  LParams.CredentialResolver := TSniCredentialResolver.ForCredential(CredentialWithChain(AChain));
  Result := TTls13ServerStateMachine.Create(LParams) as IHandshakeMachine;
end;

function TTestExtensionNegotiation.CredentialWithChain(
  const AChain: TArray<TBytes>): TTlsCredential;
begin
  // keep the real signing key, swap the certificate chain the Certificate carries
  Result := ServerCredential;
  Result.CertificateChain := AChain;
end;

function TTestExtensionNegotiation.DriveServerCertMessage(const AClient,
  AServer: IHandshakeMachine): TTlsHandshakeMessage;
var
  LFlight: TArray<TBytes>;
begin
  // the encrypted flight is [ServerHello, EncryptedExtensions, Certificate, ...]
  LFlight := AllSendHandshake(AServer.ProcessMessage(MsgFrom(
    FirstSendHandshake(AClient.Start))));
  Result := MsgFrom(LFlight[2]);
end;

function TTestExtensionNegotiation.PlaintextCertBody(
  const AChain: TArray<TBytes>): TBytes;
begin
  // a server with no compressors always sends the uncompressed Certificate body
  Result := DriveServerCertMessage(NewClientMachine(nil),
    NewServerMachineWith(AChain, nil)).Body;
end;

function TTestExtensionNegotiation.CompressibleChain: TArray<TBytes>;
var
  LData: TBytes;
  LI: Int32;
begin
  // a full-byte permutation (high entropy per cycle) repeated many times: it shrinks
  // well via the repeat, yet stays under the 100x ratio a decompression bomb would hit
  LData := nil;
  SetLength(LData, 4096);
  for LI := 0 to System.Length(LData) - 1 do
    LData[LI] := Byte((LI * 31 + 7) and $FF);
  Result := TArray<TBytes>.Create(LData);
end;

function TTestExtensionNegotiation.IncompressibleChain: TArray<TBytes>;
begin
  // 32 high-entropy bytes: zlib framing makes the output larger, not smaller
  Result := TArray<TBytes>.Create(
    DecodeHex('9f1c7a4e0b62d3851fae09c7b24d6f80e5a31c9d7042bf68ac15e3902d7c4b6a'));
end;

function TTestExtensionNegotiation.MsgFrom(
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

function TTestExtensionNegotiation.FirstSendHandshake(
  const AEffects: TArray<THandshakeEffect>): TBytes;
var
  LEffect: THandshakeEffect;
begin
  Result := nil;
  for LEffect in AEffects do
    if LEffect.Kind = THandshakeEffectKind.SendHandshake then
      Exit(LEffect.Bytes);
end;

function TTestExtensionNegotiation.AllSendHandshake(
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

function TTestExtensionNegotiation.FailAlertOf(
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

function TTestExtensionNegotiation.BuildEncryptedExtensionsWithAlpn(
  const AProtocol: string): TBytes;
var
  LCodec: IExtensionBlockCodec;
  LContext: TExtensionContext;
begin
  LCodec := TExtensionBlockCodec.Create(TCoreExtensions.CreateDefaultRegistry)
    as IExtensionBlockCodec;
  LContext := TExtensionContext.Create;
  try
    LContext.SelectedAlpn := AProtocol;
    Result := THandshakeFraming.Frame(TTlsHandshakeType.EncryptedExtensions,
      THandshakeMessages.EncodeEncryptedExtensions(LCodec.ProduceBlock(LContext,
      TTlsExtensionContextKind.EncryptedExtensions)));
  finally
    LContext.Free;
  end;
end;

procedure TTestExtensionNegotiation.TestClientRejectsUnofferedAlpnEcho;
var
  LClient, LServer: IHandshakeMachine;
  LClientHello, LServerHello: TBytes;
  LAlert: TTlsAlertDescription;
begin
  // drive a real ClientHello/ServerHello exchange so the client reaches
  // EncryptedExtensions with handshake keys, then feed it a crafted EE whose ALPN
  // selection (http/1.1) the client never offered (it offered only h2)
  LClient := NewClientMachine(TArray<string>.Create('h2'));
  LServer := NewServerMachine(TArray<string>.Create('h2'));
  LClientHello := FirstSendHandshake(LClient.Start);
  LServerHello := FirstSendHandshake(LServer.ProcessMessage(MsgFrom(LClientHello)));
  LClient.ProcessMessage(MsgFrom(LServerHello));

  CheckTrue(FailAlertOf(LClient.ProcessMessage(
    MsgFrom(BuildEncryptedExtensionsWithAlpn('http/1.1'))), LAlert),
    'a server ALPN selection the client did not offer aborts');
  CheckTrue(LAlert = TTlsAlertDescription.IllegalParameter,
    'an unoffered ALPN echo is illegal_parameter');
end;

procedure TTestExtensionNegotiation.TestUnknownHandshakeTypeUnexpected;
var
  LClient: IHandshakeMachine;
  LAlert: TTlsAlertDescription;
begin
  // a client awaiting ServerHello receives an unknown handshake type (0x63, len 0)
  LClient := NewClientMachine(nil);
  LClient.Start;
  CheckTrue(FailAlertOf(LClient.ProcessMessage(MsgFrom(DecodeHex('63000000'))), LAlert),
    'an unknown handshake type aborts');
  CheckTrue(LAlert = TTlsAlertDescription.UnexpectedMessage,
    'an unknown handshake type is unexpected_message');
end;

procedure TTestExtensionNegotiation.TestCertificateVerifyBeforeCertificateUnexpected;
var
  LClient, LServer: IHandshakeMachine;
  LFlight: TArray<TBytes>;
  LAlert: TTlsAlertDescription;
begin
  // drive the client through ServerHello + EncryptedExtensions to WaitCertificate,
  // then deliver CertificateVerify out of order (before Certificate)
  LClient := NewClientMachine(nil);
  LServer := NewServerMachine(nil);
  LFlight := AllSendHandshake(LServer.ProcessMessage(MsgFrom(
    FirstSendHandshake(LClient.Start))));
  // LFlight = [ServerHello, EncryptedExtensions, Certificate, CertificateVerify, Finished]
  LClient.ProcessMessage(MsgFrom(LFlight[0])); // ServerHello
  LClient.ProcessMessage(MsgFrom(LFlight[1])); // EncryptedExtensions
  CheckTrue(FailAlertOf(LClient.ProcessMessage(MsgFrom(LFlight[3])), LAlert),
    'CertificateVerify before Certificate aborts');
  CheckTrue(LAlert = TTlsAlertDescription.UnexpectedMessage,
    'an out-of-order CertificateVerify is unexpected_message');
end;

function TTestExtensionNegotiation.DriveClientToWaitCertificate(
  out AServerFlight: TArray<TBytes>): IHandshakeMachine;
var
  LServer: IHandshakeMachine;
begin
  // real ClientHello/ServerHello exchange, then feed ServerHello + EncryptedExtensions
  Result := NewClientMachine(nil);
  LServer := NewServerMachine(nil);
  AServerFlight := AllSendHandshake(LServer.ProcessMessage(MsgFrom(
    FirstSendHandshake(Result.Start))));
  Result.ProcessMessage(MsgFrom(AServerFlight[0])); // ServerHello
  Result.ProcessMessage(MsgFrom(AServerFlight[1])); // EncryptedExtensions
end;

function TTestExtensionNegotiation.CompressedCertificateOf(AAlgorithm: UInt16;
  AUncompressedLength: Int32; const ACompressed: TBytes): TBytes;
var
  LMsg: TTlsCompressedCertificate;
begin
  LMsg.Algorithm := AAlgorithm;
  LMsg.UncompressedLength := AUncompressedLength;
  LMsg.Compressed := ACompressed;
  Result := THandshakeFraming.Frame(TTlsHandshakeType.CompressedCertificate,
    THandshakeMessages.EncodeCompressedCertificate(LMsg));
end;

procedure TTestExtensionNegotiation.TestClientAcceptsCompressedCertificate;
var
  LClient: IHandshakeMachine;
  LFlight: TArray<TBytes>;
  LCertBody, LCompressed, LCompMsg: TBytes;
  LAlert: TTlsAlertDescription;
begin
  LClient := DriveClientToWaitCertificate(LFlight);
  // compress the server's real Certificate message and deliver it compressed
  LCertBody := MsgFrom(LFlight[2]).Body;
  LCompressed := ZlibCompress(LCertBody);
  LCompMsg := CompressedCertificateOf(TCertificateCompressionAlgorithms.Zlib,
    System.Length(LCertBody), LCompressed);
  // the client decompresses and trust-verifies the recovered chain (no failure)
  CheckFalse(FailAlertOf(LClient.ProcessMessage(MsgFrom(LCompMsg)), LAlert),
    'a valid compressed certificate is accepted');
end;

procedure TTestExtensionNegotiation.TestClientRejectsCompressedCertificateBomb;
var
  LClient: IHandshakeMachine;
  LFlight: TArray<TBytes>;
  LZeros, LCompressed, LCompMsg: TBytes;
  LAlert: TTlsAlertDescription;
begin
  LClient := DriveClientToWaitCertificate(LFlight);
  // a tiny compressed body declaring a huge expansion is a bomb
  LZeros := nil;
  SetLength(LZeros, 60000);
  FillChar(LZeros[0], 60000, 0);
  LCompressed := ZlibCompress(LZeros);
  LCompMsg := CompressedCertificateOf(TCertificateCompressionAlgorithms.Zlib, 60000, LCompressed);
  CheckTrue(FailAlertOf(LClient.ProcessMessage(MsgFrom(LCompMsg)), LAlert),
    'a compressed-certificate bomb aborts');
  CheckTrue(LAlert = TTlsAlertDescription.BadCertificate,
    'a compressed-certificate bomb is bad_certificate');
end;

procedure TTestExtensionNegotiation.TestClientRejectsUnadvertisedCompressionAlgorithm;
var
  LClient: IHandshakeMachine;
  LFlight: TArray<TBytes>;
  LCompMsg: TBytes;
  LAlert: TTlsAlertDescription;
begin
  LClient := DriveClientToWaitCertificate(LFlight);
  // brotli (2) was never advertised by the client
  LCompMsg := CompressedCertificateOf(2, 100, DecodeHex('00010203'));
  CheckTrue(FailAlertOf(LClient.ProcessMessage(MsgFrom(LCompMsg)), LAlert),
    'an unadvertised compression algorithm aborts');
  CheckTrue(LAlert = TTlsAlertDescription.BadCertificate,
    'an unadvertised compression algorithm is bad_certificate');
end;

procedure TTestExtensionNegotiation.TestServerEmitsCompressedCertificate;
var
  LCertMsg: TTlsHandshakeMessage;
  LDecoded: TTlsCompressedCertificate;
  LRecovered: TBytes;
begin
  // the client advertises zlib, the server holds zlib and a compressible chain, so
  // the Certificate flight arrives as a CompressedCertificate
  LCertMsg := DriveServerCertMessage(NewClientMachine(nil),
    NewServerMachineWith(CompressibleChain, TZlibCertificateCompression.DefaultCompressors));
  CheckTrue(LCertMsg.TypeByte = Byte(Ord(TTlsHandshakeType.CompressedCertificate)),
    'the server sends a CompressedCertificate when the client advertised a match');
  LDecoded := THandshakeMessages.DecodeCompressedCertificate(LCertMsg.Body);
  CheckTrue(LDecoded.Algorithm = TCertificateCompressionAlgorithms.Zlib,
    'the emitted algorithm is zlib');
  LRecovered := TCertificateCompression.Decompress(
    TZlibCertificateCompression.DefaultDecompressors, LDecoded.Algorithm,
    LDecoded.Compressed, LDecoded.UncompressedLength);
  CheckEqualBytes('the compressed body decompresses to the plaintext Certificate',
    PlaintextCertBody(CompressibleChain), LRecovered);
end;

procedure TTestExtensionNegotiation.TestServerSkipsCompressionWhenNotSmaller;
var
  LCertMsg: TTlsHandshakeMessage;
begin
  // a tiny high-entropy chain does not shrink, so the only-if-smaller guard keeps the
  // plaintext Certificate even though both ends support compression
  LCertMsg := DriveServerCertMessage(NewClientMachine(nil),
    NewServerMachineWith(IncompressibleChain, TZlibCertificateCompression.DefaultCompressors));
  CheckTrue(LCertMsg.TypeByte = Byte(Ord(TTlsHandshakeType.Certificate)),
    'an incompressible certificate is sent uncompressed');
end;

procedure TTestExtensionNegotiation.TestCertificateCompressionIsInjectable;
var
  LCertMsg: TTlsHandshakeMessage;
  LDecoded: TTlsCompressedCertificate;
  LRecovered: TBytes;
begin
  // a custom (non-zlib codepoint) backend injected on both ends is honored end to end
  LCertMsg := DriveServerCertMessage(
    NewClientMachineWith(nil, TArray<ICertificateDecompressor>.Create(
      TCustomCertDecompressor.Create as ICertificateDecompressor)),
    NewServerMachineWith(CompressibleChain, TArray<ICertificateCompressor>.Create(
      TCustomCertCompressor.Create as ICertificateCompressor)));
  CheckTrue(LCertMsg.TypeByte = Byte(Ord(TTlsHandshakeType.CompressedCertificate)),
    'the server compresses with the injected backend');
  LDecoded := THandshakeMessages.DecodeCompressedCertificate(LCertMsg.Body);
  CheckTrue(LDecoded.Algorithm = CustomCertCompressionAlgo,
    'the emitted algorithm is the injected codepoint');
  LRecovered := TCertificateCompression.Decompress(
    TArray<ICertificateDecompressor>.Create(
    TCustomCertDecompressor.Create as ICertificateDecompressor),
    LDecoded.Algorithm, LDecoded.Compressed, LDecoded.UncompressedLength);
  CheckEqualBytes('the injected backend round-trips the plaintext Certificate',
    PlaintextCertBody(CompressibleChain), LRecovered);
end;

procedure TTestExtensionNegotiation.TestAlpnNegotiatesAndSurfaces;
var
  LClient, LServer: ITlsEngine;
begin
  // client offers h2 then http/1.1; the server prefers http/1.1, so its first match
  // is http/1.1 and both sides surface it
  LClient := NewClient(TArray<string>.Create('h2', 'http/1.1'), 0);
  LServer := NewServer(TArray<string>.Create('http/1.1', 'h2'), 0);
  Handshake(LClient, LServer);
  CheckFalse(LClient.IsTerminal, 'the client completed');
  CheckFalse(LServer.IsTerminal, 'the server completed');
  CheckEquals('http/1.1', LServer.NegotiatedAlpnProtocol, 'server surfaces the selection');
  CheckEquals('http/1.1', LClient.NegotiatedAlpnProtocol, 'client surfaces the selection');
end;

procedure TTestExtensionNegotiation.TestAlpnNoOverlapAborts;
var
  LClient, LServer: ITlsEngine;
begin
  // the server is configured with a list, the client offers only a disjoint one
  LClient := NewClient(TArray<string>.Create('h2'), 0);
  LServer := NewServer(TArray<string>.Create('http/1.1'), 0);
  Handshake(LClient, LServer);
  CheckTrue(LServer.IsTerminal, 'the server aborts on no ALPN overlap');
  CheckEquals(Ord(TTlsAlertDescription.NoApplicationProtocol),
    Ord(LServer.LastError.Alert.Description), 'it is no_application_protocol');
end;

procedure TTestExtensionNegotiation.TestNoAlpnConfiguredSurfacesEmpty;
var
  LClient, LServer: ITlsEngine;
begin
  LClient := NewClient(nil, 0);
  LServer := NewServer(nil, 0);
  Handshake(LClient, LServer);
  CheckFalse(LClient.IsTerminal, 'the handshake is unaffected by absent ALPN');
  CheckFalse(LServer.IsTerminal, 'the handshake is unaffected by absent ALPN');
  CheckEquals('', LClient.NegotiatedAlpnProtocol, 'no ALPN negotiated');
  CheckEquals('', LServer.NegotiatedAlpnProtocol, 'no ALPN negotiated');
end;

procedure TTestExtensionNegotiation.TestRecordSizeLimitCapsOutboundRecords;
var
  LClient, LServer: ITlsEngine;
  LPayload, LWire, LReceived: TBytes;
  LI: Int32;
begin
  // both advertise a 512-byte record_size_limit; a 2000-byte write must fragment into
  // several records, none exceeding the negotiated plaintext cap on the wire
  LClient := NewClient(nil, 512);
  LServer := NewServer(nil, 512);
  Handshake(LClient, LServer);
  CheckFalse(LClient.IsTerminal or LServer.IsTerminal, 'the handshake completed');

  LPayload := nil;
  SetLength(LPayload, 2000);
  for LI := 0 to System.Length(LPayload) - 1 do
    LPayload[LI] := Byte(LI and $FF);
  LClient.Write(LPayload, 0, System.Length(LPayload));
  LWire := Drain(LClient);
  // 512-byte plaintext cap => content <= 511, ciphertext <= 511 + 1 type + 16 tag = 528
  CheckTrue(MaxAppRecordLength(LWire) <= 528, 'no record exceeds the negotiated cap');
  CheckTrue(AppRecordCount(LWire) > 1, 'the oversize write fragmented into several records');

  Feed(LServer, LWire);
  LReceived := ReadAllApp(LServer);
  CheckEqualBytes('the server reassembles the fragmented payload', LPayload, LReceived);
end;

procedure TTestExtensionNegotiation.TestServerRejectsRecordSizeLimitBelowMinimum;
var
  LClient, LServer: ITlsEngine;
begin
  // a record_size_limit below 64 is illegal (RFC 8449 4)
  LClient := NewClient(nil, 32);
  LServer := NewServer(nil, 0);
  Handshake(LClient, LServer);
  CheckTrue(LServer.IsTerminal, 'the server rejects a below-minimum record_size_limit');
  CheckEquals(Ord(TTlsAlertDescription.IllegalParameter),
    Ord(LServer.LastError.Alert.Description), 'it is illegal_parameter');
end;

function TTestExtensionNegotiation.NewGreasingClient: ITlsEngine;
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
  LParams.Grease := True;
  LParams.ClientRandom := DecodeHex(StringOfChar('1', 64));
  LParams.LegacySessionId := DecodeHex(StringOfChar('3', 64));
  LParams.CertificateVerifier := TCertificateVerifier.Create(Provider, TSystemClock.Create as ITlsClock,
    TTrustAnchorStore.Create(TArray<TBytes>.Create(TestRootCertificate)) as ITrustAnchorStore,
    True) as ICertificateVerifier;
  LParams.ExpectedHostName := 'localhost';
  Result := TTlsEngine.CreateConfigured(
    TTls13ClientStateMachine.Create(LParams) as IHandshakeMachine, Provider);
end;

function TTestExtensionNegotiation.ServerHelloFrom(
  const AWire: TBytes): TTlsServerHello;
var
  LPos, LLen: Int32;
begin
  Result := Default(TTlsServerHello);
  LPos := 0;
  // the first handshake record (type 22) carries the plaintext ServerHello
  while LPos + 5 <= System.Length(AWire) do
  begin
    LLen := (AWire[LPos + 3] shl 8) or AWire[LPos + 4];
    if AWire[LPos] = 22 then
    begin
      Result := THandshakeMessages.DecodeServerHello(
        MsgFrom(System.Copy(AWire, LPos + 5, LLen)).Body);
      Exit;
    end;
    Inc(LPos, 5 + LLen);
  end;
end;

procedure TTestExtensionNegotiation.TestGreaseValueClassification;
var
  LI: Int32;
begin
  // all 16 GREASE codepoints classify as GREASE; real codepoints do not
  for LI := 0 to 15 do
    CheckTrue(TGrease.IsGrease(TGrease.ValueAt(LI)), 'GREASE value classified');
  CheckFalse(TGrease.IsGrease(TCipherSuites13.Aes128GcmSha256), 'a real suite is not GREASE');
  CheckFalse(TGrease.IsGrease(TNamedGroupCatalog.X25519), 'a real group is not GREASE');
  CheckFalse(TGrease.IsGrease($0304), 'the TLS 1.3 version is not GREASE');
end;

procedure TTestExtensionNegotiation.TestClientGreaseToleratedAndNeverSelected;
var
  LClient, LServer: ITlsEngine;
  LServerHello: TTlsServerHello;
  LContext: TExtensionContext;
  LCodec: IExtensionBlockCodec;
  LIterations: Int32;
begin
  LClient := NewGreasingClient;
  LServer := NewServer(nil, 0);

  LClient.StartHandshake;
  // capture the server's first flight to prove nothing GREASE was selected
  Feed(LServer, Drain(LClient));
  LServerHello := ServerHelloFrom(Drain(LServer));
  CheckFalse(TGrease.IsGrease(LServerHello.CipherSuite),
    'the server did not select a GREASE cipher suite');
  LContext := TExtensionContext.Create;
  try
    LContext.MarkOffered(TExtensionTypes.SupportedVersions);
    LContext.MarkOffered(TExtensionTypes.KeyShare);
    LCodec := TExtensionBlockCodec.Create(TCoreExtensions.CreateDefaultRegistry)
      as IExtensionBlockCodec;
    LCodec.ConsumeBlock(LContext, TTlsExtensionContextKind.ServerHello,
      LServerHello.Extensions);
    CheckFalse(TGrease.IsGrease(LContext.SelectedKeyShare.Group),
      'the server did not select a GREASE group');
  finally
    LContext.Free;
  end;

  // and the GREASE-laden handshake still completes end to end
  LClient := NewGreasingClient;
  LServer := NewServer(nil, 0);
  LClient.StartHandshake;
  LIterations := 0;
  while (LClient.IsHandshaking or LServer.IsHandshaking) and (LIterations < 16) do
  begin
    Pump(LClient, LServer);
    Pump(LServer, LClient);
    Inc(LIterations);
  end;
  CheckFalse(LClient.IsTerminal, 'the client completed with GREASE');
  CheckFalse(LServer.IsTerminal, 'the server tolerated the GREASE');
  CheckFalse(LClient.IsHandshaking or LServer.IsHandshaking, 'the handshake finished');
end;

procedure TTestExtensionNegotiation.TestEcPointFormatsRoundTrip;
var
  LExt: ITlsExtension;
  LSrc, LDst: TExtensionContext;
  LBody: TBytes;
begin
  // ec_point_formats (RFC 8422): omitted unless offered, then lists uncompressed(0)
  LExt := TEcPointFormatsExtension.Create as ITlsExtension;
  LSrc := TExtensionContext.Create;
  LDst := TExtensionContext.Create;
  try
    CheckFalse(LExt.Produce(LSrc, LBody),
      'ec_point_formats is omitted when not offered');
    LSrc.EcPointFormatsOffered := True;
    CheckTrue(LExt.Produce(LSrc, LBody),
      'ec_point_formats is produced when offered');
    LExt.Consume(LDst, LBody);
    CheckTrue(LDst.EcPointFormatsOffered,
      'the peer point-format list round-trips through the codec');
  finally
    LSrc.Free;
    LDst.Free;
  end;
end;

procedure TTestExtensionNegotiation.TestEcPointFormatsWithoutUncompressedRejected;
var
  LExt: ITlsExtension;
  LDst: TExtensionContext;
  LRejected: Boolean;
begin
  LExt := TEcPointFormatsExtension.Create as ITlsExtension;
  LDst := TExtensionContext.Create;
  LRejected := False;
  try
    // a format list of only ansiX962_compressed_prime(1), no uncompressed(0)
    try
      LExt.Consume(LDst, TBytes.Create($01, $01));
    except
      on E: EDecodeErrorTlsLibException do
        LRejected := True;
    end;
    CheckTrue(LRejected,
      'a point-format list without uncompressed is rejected (decode_error)');
  finally
    LDst.Free;
  end;
end;

procedure TTestExtensionNegotiation.TestAlpnServerHelloSelectionRoundTrip;
var
  LExt: ITlsExtension;
  LDst: TExtensionContext;
begin
  // a TLS 1.2 ServerHello carries the single selected protocol, as EncryptedExtensions
  // does in 1.3; a ProtocolNameList of one entry "h2" = [00 03] [02 68 32]
  LExt := TAlpnExtension.Create as ITlsExtension;
  LDst := TExtensionContext.Create;
  try
    LDst.MessageContext := TTlsExtensionContextKind.ServerHello;
    LExt.Consume(LDst, TBytes.Create($00, $03, $02, $68, $32));
    CheckEquals('h2', LDst.SelectedAlpn,
      'the server''s ServerHello ALPN selection round-trips');
  finally
    LDst.Free;
  end;
end;

procedure TTestExtensionNegotiation.TestAlpnServerHelloEmptyProtocolRejected;
var
  LExt: ITlsExtension;
  LDst: TExtensionContext;
  LRejected: Boolean;
begin
  // an empty selected protocol name is malformed (RFC 7301 3.1); a list of one
  // zero-length entry = [00 01] [00]
  LExt := TAlpnExtension.Create as ITlsExtension;
  LDst := TExtensionContext.Create;
  LRejected := False;
  try
    LDst.MessageContext := TTlsExtensionContextKind.ServerHello;
    try
      LExt.Consume(LDst, TBytes.Create($00, $01, $00));
    except
      on E: EDecodeErrorTlsLibException do
        LRejected := True;
    end;
    CheckTrue(LRejected,
      'an empty ServerHello ALPN protocol is rejected (decode_error)');
  finally
    LDst.Free;
  end;
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestExtensionNegotiation);
{$ELSE}
  RegisterTest(TTestExtensionNegotiation.Suite);
{$ENDIF FPC}

end.
