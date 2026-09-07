program TlsLibConsole;

{$mode objfpc}{$H+}

uses
  {$IFDEF UNIX}cthreads, cwstring,{$ENDIF}
  consoletestrunner,
  TlsLibTestResourceLoader,
  TlsLibTestBase,
  MockRandom,
  MockCryptoProvider,
  SecretTests,
  AlertTests,
  ExceptionTests,
  WireCodecTests,
  ProviderTests,
  NamedGroupTests,
  MockTests,
  RecordHeaderTests,
  RecordProtectionTests,
  RecordLayerTests,
  AlertProtocolTests,
  EngineSkeletonTests,
  HkdfLabelTests,
  Tls13KeyScheduleTests,
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
  ConfigBuilderTests,
  TrustCompositionTests,
  SystemTrustTests,
  AppleAlertMapTests,
  RootGenKeyingTests,
  EchToolingTests,
  BundleTrustTests,
  PresetTests,
  ExtensionCodecTests,
  NegotiationTests
;

type
  TTlsLibConsoleTestRunner = class(TTestRunner)
  protected
    // override protected methods of TTestRunner to customize behaviour
  end;

var
  Application: TTlsLibConsoleTestRunner;

begin
  DefaultRunAllTests := True;
  DefaultFormat := TFormat.fPlain;
  Application := TTlsLibConsoleTestRunner.Create(nil);
  Application.Initialize;
  Application.Run;
  Application.Free;
end.
