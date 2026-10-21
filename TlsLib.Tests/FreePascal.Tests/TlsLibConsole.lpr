program TlsLibConsole;

{$mode objfpc}{$H+}

uses
  {$IFDEF UNIX}cthreads, cwstring,{$ENDIF}
  SysUtils,
  fpcunit,
  consoletestrunner,
  TlsLibTestResourceLoader,
  TlsLibTestProviders,
  TlsLibTestHandshakeDecoder,
  TlsLibTestBase,
  TlsLibTestCertificates,
  TlsLibHandshakeTestBase,
  MockRandom,
  MockClock,
  MockKeyLog,
  MockCryptoProvider,
  MockSystemCrypto,
  MockCredentialResolvers,
  MockHttpFetcher,
  MockPkixProvider,
  MockSink,
  MockPlatformChainEngine,
  MockVerifyHooks,
  MockRecordInstaller,
  MockTransport,
  MockCertificateVerifiers,
  MockCertificateCompression,
  MockNamedGroups,
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
  Tls12PskTests,
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
  Pkcs12IdentityTests,
  ArrayUtilitiesTests,
  SystemCryptoHelperTests,
  EndpointIdentityTests,
  PemTests,
  DynamicLibraryTests,
  SocketHttpFetcherTests,
  SocketHttpExchangeTests,
  NetSocketTests,
  SystemTimeUtilitiesTests,
  IpLiteralTests,
  HttpUrlTests,
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
  NativeCryptoProviderTests,
  MockCompliance,
  ComplianceRulesTests,
  ComplianceProviderTests,
  CompliancePolicyTests,
  ComplianceLoopbackTests,
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

const
  RepeatFlag = 'repeat';

type
  TTlsLibConsoleTestRunner = class(TTestRunner)
  protected
    procedure AppendLongOpts; override;
    procedure WriteCustomHelp; override;
    procedure DoTestRun(ATest: TTest); override;
  end;

procedure TTlsLibConsoleTestRunner.AppendLongOpts;
begin
  inherited AppendLongOpts;
  // fpcunit rejects unregistered options
  LongOpts.Add(TTlsLibTestProviders.CryptoFlag + ':');
  LongOpts.Add(TTlsLibTestProviders.PkixFlag + ':');
  LongOpts.Add(RepeatFlag + ':');
end;

procedure TTlsLibConsoleTestRunner.WriteCustomHelp;
begin
  Writeln('  --', TTlsLibTestProviders.CryptoFlag, '=portable|os   crypto provider');
  Writeln('  --', TTlsLibTestProviders.PkixFlag, '=portable   PKIX provider');
  Writeln('  env TLSLIB_TEST_NETWORK=true   also run the tests that need live DNS');
  Writeln('  --', RepeatFlag, '=N   run the suite N times in this process; fails if any pass fails (a report file keeps the last pass)');
end;

procedure TTlsLibConsoleTestRunner.DoTestRun(ATest: TTest);
var
  LPasses, LPass, LExitCode: Integer;
begin
  LPasses := 1;
  if HasOption(RepeatFlag) then
    LPasses := StrToIntDef(GetOptionValue(RepeatFlag), 1);
  if LPasses < 1 then
    LPasses := 1;
  LExitCode := 0;
  for LPass := 1 to LPasses do
  begin
    if LPasses > 1 then
      Writeln(StdErr, 'run ', LPass, '/', LPasses);
    inherited DoTestRun(ATest);
    LExitCode := LExitCode or ExitCode;
  end;
  ExitCode := LExitCode;
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
