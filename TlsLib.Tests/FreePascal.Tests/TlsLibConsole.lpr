program TlsLibConsole;

{$mode objfpc}{$H+}

uses
  {$IFDEF UNIX}cthreads, cwstring,{$ENDIF}
  consoletestrunner,
  TlsLibTestResourceLoader,
  TlsLibTestProviders,
  TlsLibTestHandshakeDecoder,
  TlsLibTestBase,
  MockRandom,
  MockClock,
  MockKeyLog,
  MockCryptoProvider,
  MockHttpFetcher,
  SpyRevocationProvider,
  MockSink,
  MockRecordInstaller,
  MockTransport,
  SecretTests,
  AlertTests,
  ExceptionTests,
  WireCodecTests,
  ProviderTests,
  NamedGroupTests,
  ChainAlgorithmPolicyTests,
  MockTests,
  RecordHeaderTests,
  RecordProtectionTests,
  RecordLayerTests,
  AlertProtocolTests,
  EngineSkeletonTests,
  HkdfLabelTests,
  Tls13KeyScheduleTests,
  KeyLogTests,
  Tls12KeyScheduleTests,
  ScheduleInstallTests,
  HandshakeMessageTests,
  TranscriptHashTests,
  HandshakeMessagesTests,
  HandshakeDriverTests,
  Tls13ClientReplayTests,
  Tls13ServerReplayTests,
  HelloRetryRequestTests,
  ExtensionNegotiationTests,
  ResourceLimitTests,
  SessionStoreTests,
  CertificateCompressionCacheTests,
  DataEncodingTests,
  MockSessionStores,
  ClientSessionPolicyTests,
  Tls13ResumptionTests,
  Tls13LoopbackTests,
  Tls12LoopbackTests,
  TlsStreamLoopbackTests,
  Tls12ResumptionTests,
  ConfigResumptionTests,
  Tls13KeyUpdateTests,
  Tls12DualVersionTests,
  ClientAuthTests,
  SignatureTests,
  CredentialImportTests,
  Pkcs12ImportTests,
  EndpointIdentityTests,
  PemTests,
  CertificateVerifierTests,
  OcspStaplingTests,
  CertificateCheckTests,
  HpkeProviderTests,
  EchConfigTests,
  EchExtensionTests,
  EchOuterExtensionsTests,
  EchConfirmationTests,
  EchClientTests,
  EchClientEngineTests,
  AsyncVerdictTests,
  LiveRevocationTests,
  ServerSideLiveRevocationTests,
  ConfigBuilderTests,
  TrustCompositionTests,
  SystemTrustTests,
  WindowsSystemCryptoTests,
  AppleAlertMapTests,
  RootGenKeyingTests,
  EchToolingTests,
  BundleTrustTests,
  PresetTests,
  ExtensionVectorTests,
  ExtensionCodecTests,
  NegotiationTests,
  TlsConnectionTests
;

type
  TTlsLibConsoleTestRunner = class(TTestRunner)
  protected
    procedure AppendLongOpts; override;
    procedure WriteCustomHelp; override;
  end;

procedure TTlsLibConsoleTestRunner.AppendLongOpts;
begin
  inherited AppendLongOpts;
  // fpcunit rejects unregistered options
  LongOpts.Add(TTlsLibTestProviders.CryptoFlag + ':');
  LongOpts.Add(TTlsLibTestProviders.PkixFlag + ':');
end;

procedure TTlsLibConsoleTestRunner.WriteCustomHelp;
begin
  Writeln('  --', TTlsLibTestProviders.CryptoFlag, '=portable|os   crypto provider');
  Writeln('  --', TTlsLibTestProviders.PkixFlag, '=portable   PKIX provider');
end;

var
  Application: TTlsLibConsoleTestRunner;

begin
  DefaultRunAllTests := True;
  DefaultFormat := TFormat.fPlain;
  Application := TTlsLibConsoleTestRunner.Create(nil);
  Application.Initialize;
  // stderr keeps --format=xml output clean
  Writeln(StdErr, 'providers: ', TTlsLibTestProviders.Describe);
  Application.Run;
  Application.Free;
end.
