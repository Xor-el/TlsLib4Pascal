library TlsLibAndroidTests;

{$mode objfpc}{$H+}

uses
  cthreads,
  cwstring,
  SysUtils,
  Classes,
  jni,
  fphttpclient,
  fpcunit,
  testregistry,
  FpcUnitTestInsight,
  TestInsightClient,
  TestInsightProtocol,
  jsonparser,
  TlpAndroidSystemTrust,
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
  TlsConnectionTests;

const
  SettingsFile = 'TestInsightSettings.ini';
  MaxBatchResults = 100;
  MaxBatchMs = 1000;

{$linklib log}
function android_log_write(APriority: LongInt; ATag, AText: PAnsiChar): LongInt; cdecl;
  external 'log' name '__android_log_write';

type
  // logs each start, skip, failure and error to logcat so a run can be read without the IDE
  TLogcatListener = class(TInterfacedObject, ITestListener)
  public
    procedure AddFailure(ATest: TTest; AFailure: TTestFailure);
    procedure AddError(ATest: TTest; AError: TTestFailure);
    procedure StartTest(ATest: TTest);
    procedure EndTest(ATest: TTest);
    procedure StartTestSuite(ATestSuite: TTestSuite);
    procedure EndTestSuite(ATestSuite: TTestSuite);
  end;

procedure TLogcatListener.AddFailure(ATest: TTest; AFailure: TTestFailure);
begin
  if AFailure.IsIgnoredTest then
    android_log_write(4, 'TlsLibTests', PAnsiChar(AnsiString('SKIP ' + ATest.TestSuiteName + '.' +
      ATest.TestName + ': ' + AFailure.ExceptionMessage)))
  else
    android_log_write(5, 'TlsLibTests', PAnsiChar(AnsiString('FAIL ' + ATest.TestSuiteName + '.' +
      ATest.TestName + ': ' + AFailure.ExceptionMessage)));
end;

procedure TLogcatListener.AddError(ATest: TTest; AError: TTestFailure);
begin
  android_log_write(6, 'TlsLibTests', PAnsiChar(AnsiString('ERROR ' + ATest.TestSuiteName + '.' +
    ATest.TestName + ': ' + AError.ExceptionClassName + ': ' + AError.ExceptionMessage)));
end;

procedure TLogcatListener.StartTest(ATest: TTest);
begin
  android_log_write(4, 'TlsLibTests', PAnsiChar(AnsiString('START ' + ATest.TestSuiteName + '.' + ATest.TestName)));
end;

procedure TLogcatListener.EndTest(ATest: TTest);
begin
end;

procedure TLogcatListener.StartTestSuite(ATestSuite: TTestSuite);
begin
end;

procedure TLogcatListener.EndTestSuite(ATestSuite: TTestSuite);
begin
end;

type
  TBlockingTestInsightClient = class(TAbstractTestInsightClient)
  private
    FHttp: TFPHTTPClient;
    FInError: Boolean;
    FLastError: string;
    FBatch: string;
    FBatchCount: Int32;
    FBatchSentAt: QWord;
    procedure Send(const AUrl, AContent: string);
    procedure FlushResults;
  protected
    function GetHasError: Boolean; override;
    function GetLastErrorMessage: string; override;
    procedure ServerPost(aURL: string; const aContent: string = ''); override;
    function ServerGet(aURL: string): string; override;
    procedure ServerDelete(aURL: string); override;
  public
    constructor Create(const aBaseURL: string); override;
    destructor Destroy; override;
  end;

constructor TBlockingTestInsightClient.Create(const aBaseURL: string);
begin
  inherited Create(aBaseURL);
  FHttp := TFPHTTPClient.Create(nil);
  FHttp.ConnectTimeout := 0;
  // a server that goes away mid-run must not hang the run for ever
  FHttp.IOTimeout := 30000;
  FBatchSentAt := GetTickCount64;
end;

destructor TBlockingTestInsightClient.Destroy;
begin
  FlushResults;
  FHttp.Free;
  inherited Destroy;
end;

function TBlockingTestInsightClient.GetHasError: Boolean;
begin
  Result := FInError;
end;

function TBlockingTestInsightClient.GetLastErrorMessage: string;
begin
  Result := FLastError;
end;

procedure TBlockingTestInsightClient.FlushResults;
begin
  if FBatch = '' then
    Exit;
  Send(pathResults, '[' + FBatch + ']');
  FBatch := '';
  FBatchCount := 0;
  FBatchSentAt := GetTickCount64;
end;

// a request per test stops the IDE repainting
procedure TBlockingTestInsightClient.ServerPost(aURL: string; const aContent: string);
begin
  if (aURL <> pathResults) or (Length(aContent) <= 2) then
  begin
    FlushResults;
    Send(aURL, aContent);
    Exit;
  end;
  if FBatch <> '' then
    FBatch := FBatch + ',';
  FBatch := FBatch + Copy(aContent, 2, Length(aContent) - 2);
  Inc(FBatchCount);
  if (FBatchCount >= MaxBatchResults) or (GetTickCount64 - FBatchSentAt >= MaxBatchMs) then
    FlushResults;
end;

procedure TBlockingTestInsightClient.Send(const AUrl, AContent: string);
var
  LBody, LResponse: TStringStream;
begin
  LBody := nil;
  LResponse := TStringStream.Create('');
  try
    if AContent <> '' then
      LBody := TStringStream.Create(AContent);
    FHttp.RequestBody := LBody;
    try
      FHttp.AddHeader('Content-Type', 'application/json');
      FHttp.Post(ConcatURL(AUrl), LResponse);
      FInError := False;
      FLastError := '';
    except
      on E: Exception do
      begin
        FInError := True;
        FLastError := E.ClassName + ': ' + E.Message;
      end;
    end;
  finally
    FHttp.RequestBody := nil;
    LResponse.Free;
    LBody.Free;
  end;
end;

function TBlockingTestInsightClient.ServerGet(aURL: string): string;
var
  LResponse: TStringStream;
begin
  Result := '';
  LResponse := TStringStream.Create('');
  try
    try
      FHttp.Get(ConcatURL(aURL), LResponse);
      Result := LResponse.DataString;
      FInError := False;
      FLastError := '';
    except
      on E: Exception do
      begin
        FInError := True;
        FLastError := E.ClassName + ': ' + E.Message;
      end;
    end;
  finally
    LResponse.Free;
  end;
end;

procedure TBlockingTestInsightClient.ServerDelete(aURL: string);
begin
  try
    FHttp.Delete(ConcatURL(aURL));
    FInError := False;
    FLastError := '';
  except
    on E: Exception do
    begin
      FInError := True;
      FLastError := E.ClassName + ': ' + E.Message;
    end;
  end;
end;

procedure SkipOutside(AResult: TTestResult; ASuite: TTest; AAllowed: TList; AInside: Boolean);
var
  LI: Int32;
  LTest: TTest;
  LInside: Boolean;
begin
  for LI := 0 to ASuite.GetChildTestCount - 1 do
  begin
    LTest := ASuite.GetChildTest(LI);
    LInside := AInside or (AAllowed.IndexOf(LTest) >= 0);
    if LTest is TTestCase then
    begin
      if not LInside then
        AResult.AddToSkipList(LTest as TTestCase);
    end
    else
      SkipOutside(AResult, LTest, AAllowed, LInside);
  end;
end;

// the Suite setting names suites or tests, comma separated
function FindAllowed(const ANames: string): TList;
var
  LNames: TStringList;
  LI: Int32;
  LTest: TTest;
begin
  Result := TList.Create;
  LNames := TStringList.Create;
  try
    LNames.CommaText := ANames;
    for LI := 0 to LNames.Count - 1 do
    begin
      LTest := GetTestRegistry.FindTest(LNames[LI]);
      if LTest <> nil then
        Result.Add(LTest);
    end;
  finally
    LNames.Free;
  end;
end;

function JavaToString(AEnv: PJNIEnv; AValue: jstring): string;
var
  LChars: PAnsiChar;
begin
  Result := '';
  if AValue = nil then
    Exit;
  LChars := AEnv^^.GetStringUTFChars(AEnv, AValue, nil);
  if LChars = nil then
    Exit;
  try
    Result := LChars;
  finally
    AEnv^^.ReleaseStringUTFChars(AEnv, AValue, LChars);
  end;
end;

function NativeRun(AEnv: PJNIEnv; AThis: jobject; ABaseUrl, AWorkDir: jstring): jint; cdecl;
var
  LClient: TBlockingTestInsightClient;
  LListener: ITestListener;
  LResult: TTestResult;
  LLogListener: ITestListener;
  LAllowed: TList;
  LError: AnsiString;
begin
  Result := 0;
  try
    SetCurrentDir(JavaToString(AEnv, AWorkDir));
    LClient := TBlockingTestInsightClient.Create(JavaToString(AEnv, ABaseUrl));
    try
      LClient.GetServerOptions;
      if LClient.HasError then
      begin
        LError := LClient.LastErrorMessage;
        AEnv^^.ThrowNew(AEnv, AEnv^^.FindClass(AEnv, 'java/lang/RuntimeException'), PAnsiChar(LError));
        Exit;
      end;
      if FileExists(SettingsFile) then
        LClient.LoadConfig(SettingsFile);
      LListener := TTestInsightListener.Create(LClient, GetTestRegistry) as ITestListener;
      // the IDE asks for the test list alone when it only wants to discover
      if not LClient.Options.ExecuteTests then
        Exit;
      LResult := TTestResult.Create;
      try
        if LClient.Options.TestSuite <> '' then
        begin
          LAllowed := FindAllowed(LClient.Options.TestSuite);
          try
            SkipOutside(LResult, GetTestRegistry, LAllowed, False);
          finally
            LAllowed.Free;
          end;
        end;
        LResult.AddListener(LListener);
        LLogListener := TLogcatListener.Create as ITestListener;
        LResult.AddListener(LLogListener);
        GetTestRegistry.Run(LResult);
      finally
        LResult.Free;
      end;
    finally
      LClient.Free;
    end;
  except
    on E: Exception do
    begin
      android_log_write(6, 'TlsLibTests', PAnsiChar(AnsiString('run failed: ' + E.ClassName + ': ' + E.Message)));
      Result := 1;
    end;
  end;
end;

function JNI_OnLoad(AVm: PJavaVM; AReserved: Pointer): jint; cdecl;
const
  HostClass = 'org/tlslib/tests/MainActivity';
var
  LEnv: PJNIEnv;
  LMethod: JNINativeMethod;
begin
  Result := JNI_ERR;
  if AVm^^.GetEnv(AVm, @LEnv, JNI_VERSION_1_6) <> JNI_OK then
    Exit;
  TlsLibAndroidInitTrust(AVm);
  LMethod.name := 'nativeRun';
  LMethod.signature := '(Ljava/lang/String;Ljava/lang/String;)I';
  LMethod.fnPtr := @NativeRun;
  if LEnv^^.RegisterNatives(LEnv, LEnv^^.FindClass(LEnv, HostClass), @LMethod, 1) <> JNI_OK then
    Exit;
  Result := JNI_VERSION_1_6;
end;

exports
  JNI_OnLoad;

begin
end.
