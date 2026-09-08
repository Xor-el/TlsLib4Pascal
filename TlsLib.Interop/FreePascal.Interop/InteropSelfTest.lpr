program InteropSelfTest;

{$MODE DELPHI}{$H+}

// A no-external-deps smoke that drives real TLS handshakes between our own client and
// server engines over a loopback TCP socket, exchanges application data both ways, and
// closes cleanly - across TLS 1.3, hardened TLS 1.2, and mutual-TLS scenarios. It proves
// the socket transport + pump + engine composition end to end (the same glue the BoGo
// shim uses), so CI can gate it on every leg without Go or openssl.

uses
  {$IFDEF UNIX}cthreads,{$ENDIF}
  SysUtils,
  Classes,
  TlpTlsVersion,
  TlpTlsCredential,
  TlpICryptoProvider,
  TlpITlsEngine,
  InteropSocket,
  InteropEngine,
  InteropCredentials,
  InteropPump,
  InteropUtils,
  TlsFuzzerRunner;

type
  /// <summary>One end-to-end scenario: the offered versions and whether it is mutual TLS.</summary>
  TScenario = record
    Name: string;
    Versions: TArray<UInt16>;
    MutualTls: Boolean;
  end;

  TServerThread = class(TThread)
  strict private
    FListener: TInteropListener;
    FCredentialFile: string;
    FScenario: TScenario;
    FError: string;
  protected
    procedure Execute; override;
  public
    constructor Create(AListener: TInteropListener; const ACredentialFile: string;
      const AScenario: TScenario);
    property Error: string read FError;
  end;

constructor TServerThread.Create(AListener: TInteropListener;
  const ACredentialFile: string; const AScenario: TScenario);
begin
  inherited Create(False);
  FreeOnTerminate := False;
  FListener := AListener;
  FCredentialFile := ACredentialFile;
  FScenario := AScenario;
end;

procedure TServerThread.Execute;
var
  LSocket: TInteropSocket;
  LProvider: ICryptoProvider;
  LOptions: TInteropEngineOptions;
  LEngine: ITlsEngine;
  LResult: TInteropResult;
begin
  FError := '';
  LSocket := nil;
  try
    LSocket := FListener.Accept;
    LProvider := TInteropEngine.DefaultProvider;
    LOptions := Default(TInteropEngineOptions);
    LOptions.Role := TInteropRole.Server;
    LOptions.SupportedVersions := FScenario.Versions;
    LOptions.HasCredential := True;
    LOptions.Credential :=
      TInteropCredentials.ServerCredentialFromFieldFile(LProvider, FCredentialFile);
    if FScenario.MutualTls then
    begin
      // request and verify the client certificate against the client-auth (dual-EKU) root:
      // a TLS client certificate must carry the clientAuth extendedKeyUsage
      LOptions.ClientAuth := TClientAuthMode.Required;
      LOptions.Trust := TInteropCredentials.TrustFromFieldFile(LProvider,
        ExtractFilePath(FCredentialFile) + 'ClientAuthChain.txt');
    end;
    LEngine := TInteropEngine.Build(LProvider, LOptions);

    LResult := TInteropPump.DriveHandshake(LEngine, LSocket);
    if LResult.Status <> TInteropStatus.Ok then
    begin
      FError := 'server handshake failed: ' + LResult.Detail;
      Exit;
    end;
    // echo every application record back verbatim until the peer closes
    repeat
      LResult := TInteropPump.PumpAppData(LEngine, LSocket);
      if System.Length(LResult.Data) > 0 then
        TInteropPump.WriteAppData(LEngine, LSocket, LResult.Data);
    until LResult.Status <> TInteropStatus.Ok;
    if LResult.Status = TInteropStatus.PeerClosed then
      TInteropPump.Close(LEngine, LSocket)
    else if LResult.Status <> TInteropStatus.TransportEof then
      FError := 'server data phase ended abnormally: ' + LResult.Detail;
  except
    on E: Exception do
      FError := 'server exception: ' + E.Message;
  end;
  LSocket.Free;
end;

function StrBytes(const AText: string): TBytes;
begin
  Result := TEncoding.UTF8.GetBytes(AText);
end;

function BytesEqual(const A, B: TBytes): Boolean;
begin
  Result := (System.Length(A) = System.Length(B)) and
    ((System.Length(A) = 0) or CompareMem(@A[0], @B[0], System.Length(A)));
end;

function RunClient(APort: Word; const ACredentialFile: string;
  const AScenario: TScenario): string;
var
  LSocket: TInteropSocket;
  LProvider: ICryptoProvider;
  LOptions: TInteropEngineOptions;
  LEngine: ITlsEngine;
  LResult: TInteropResult;
  LSent: TBytes;
begin
  Result := '';
  LSocket := TInteropSocket.Connect('127.0.0.1', APort);
  try
    LProvider := TInteropEngine.DefaultProvider;
    LOptions := Default(TInteropEngineOptions);
    LOptions.Role := TInteropRole.Client;
    LOptions.SupportedVersions := AScenario.Versions;
    LOptions.ServerName := 'localhost';
    LOptions.CheckServerName := True;
    LOptions.Trust := TInteropCredentials.TrustFromFieldFile(LProvider, ACredentialFile);
    if AScenario.MutualTls then
    begin
      // present a dual-EKU (clientAuth) client certificate the server requests
      LOptions.HasCredential := True;
      LOptions.Credential := TInteropCredentials.ServerCredentialFromFieldFile(LProvider,
        ExtractFilePath(ACredentialFile) + 'ClientAuthChain.txt');
    end;
    LEngine := TInteropEngine.Build(LProvider, LOptions);

    LEngine.StartHandshake;
    LResult := TInteropPump.DriveHandshake(LEngine, LSocket);
    if LResult.Status <> TInteropStatus.Ok then
      Exit('client handshake failed: ' + LResult.Detail);

    LSent := StrBytes('hello over real tcp from the interop client');
    TInteropPump.WriteAppData(LEngine, LSocket, LSent);
    LResult := TInteropPump.PumpAppData(LEngine, LSocket);
    if not BytesEqual(LResult.Data, LSent) then
      Exit('client did not receive its echo intact');

    TInteropPump.Close(LEngine, LSocket);
  finally
    LSocket.Free;
  end;
end;

function RunScenario(const ACredentialFile: string;
  const AScenario: TScenario): string;
var
  LListener: TInteropListener;
  LServer: TServerThread;
begin
  Result := '';
  LListener := TInteropListener.Bind('127.0.0.1', 0);
  try
    LServer := TServerThread.Create(LListener, ACredentialFile, AScenario);
    try
      Result := RunClient(LListener.Port, ACredentialFile, AScenario);
      LServer.WaitFor;
      // surface the server-side error too: a server abort closes the socket, which the
      // client reports only as a vague "peer closed" - reporting just that masks the cause
      if LServer.Error <> '' then
        if Result = '' then
          Result := LServer.Error
        else
          Result := Result + ' | server: ' + LServer.Error;
    finally
      LServer.Free;
    end;
  finally
    LListener.Free;
  end;
end;

function Scenario(const AName: string; const AVersions: TArray<UInt16>;
  AMutualTls: Boolean): TScenario;
begin
  Result.Name := AName;
  Result.Versions := AVersions;
  Result.MutualTls := AMutualTls;
end;

type
  // a test hang handler that records how many times it fired and the last input and
  // iteration it saw (in place of the default emit-and-halt)
  TFlagHangHandler = class(TInterfacedObject, IFuzzHangHandler)
  strict private
    FCount: Int32;
    FInput: TBytes;
    FIteration: Int32;
  public
    procedure HandleHang(const AInput: TBytes; AIteration: Int32);
    property Count: Int32 read FCount;
    property Input: TBytes read FInput;
    property Iteration: Int32 read FIteration;
  end;

procedure TFlagHangHandler.HandleHang(const AInput: TBytes; AIteration: Int32);
begin
  Inc(FCount);
  FInput := AInput;
  FIteration := AIteration;
end;

// the watchdog fires exactly once when an armed interval outlives the timeout - carrying
// the armed input and iteration - and stays quiet when disarmed in time or after it fired.
// fire detection waits (bounded) for the poll thread rather than a fixed delay, so a loaded
// host cannot make it flaky
function WatchdogSelfTest: string;

  function AwaitFire(const AFlag: TFlagHangHandler; AMaxWaitMs: Int32): Boolean;
  var
    LWaited: Int32;
  begin
    LWaited := 0;
    while (AFlag.Count = 0) and (LWaited < AMaxWaitMs) do
    begin
      Sleep(10);
      Inc(LWaited, 10);
    end;
    Result := AFlag.Count > 0;
  end;

var
  LFlag: TFlagHangHandler;
  LHandler: IFuzzHangHandler;
  LWatchdog: TFuzzWatchdog;
  LInput: TBytes;
begin
  Result := '';
  LInput := StrBytes('watchdog test input');

  // A: an interval that overruns the timeout fires once, with the armed input/iteration
  LFlag := TFlagHangHandler.Create;
  LHandler := LFlag; // the interface reference owns the handler
  LWatchdog := TFuzzWatchdog.Create(50, LHandler);
  try
    LWatchdog.Arm(LInput, 7);
    // the "hung" stub: wait (bounded) for the fire past the 50 ms timeout
    if not AwaitFire(LFlag, 3000) then
      Result := 'the watchdog did not fire on a hang past the timeout'
    else if LFlag.Count <> 1 then
      Result := 'the watchdog fired more than once for a single armed interval'
    else if not BytesEqual(LFlag.Input, LInput) then
      Result := 'the watchdog fired with the wrong input'
    else if LFlag.Iteration <> 7 then
      Result := 'the watchdog fired with the wrong iteration';
    LWatchdog.Disarm;
  finally
    LWatchdog.Free;
  end;
  if Result <> '' then
    Exit;

  // B: an interval disarmed before the timeout never fires
  LFlag := TFlagHangHandler.Create;
  LHandler := LFlag;
  LWatchdog := TFuzzWatchdog.Create(50, LHandler);
  try
    LWatchdog.Arm(LInput, 1);
    LWatchdog.Disarm; // before the 50 ms timeout
    Sleep(200); // give the poll time to run; it must stay quiet
    if LFlag.Count <> 0 then
      Result := 'the watchdog fired for an interval that was disarmed in time';
  finally
    LWatchdog.Free;
  end;
  if Result <> '' then
    Exit;

  // C: after firing once for an armed interval it does not fire again for that same arm
  LFlag := TFlagHangHandler.Create;
  LHandler := LFlag;
  LWatchdog := TFuzzWatchdog.Create(50, LHandler);
  try
    LWatchdog.Arm(LInput, 2);
    if not AwaitFire(LFlag, 3000) then
      Result := 'the watchdog did not fire once for the armed interval'
    else
    begin
      Sleep(200); // a second poll window: it must not fire again for the same arm
      if LFlag.Count <> 1 then
        Result := 'the watchdog fired more than once for a single armed interval';
    end;
    LWatchdog.Disarm;
  finally
    LWatchdog.Free;
  end;
end;

var
  GCredentialFile: string;
  GScenarios: TArray<TScenario>;
  GScenario: TScenario;
  GError: string;
begin
  ExitCode := 0;
  try
    GCredentialFile := TInteropUtils.LocateDataDir + PathDelim + 'Certs' +
      PathDelim + 'EcP256Chain.txt';
    GScenarios := TArray<TScenario>.Create(
      Scenario('TLS 1.3', nil, False),
      Scenario('TLS 1.3 mutual TLS', TArray<UInt16>.Create(TlsWireVersionTls13), True),
      Scenario('TLS 1.2', TArray<UInt16>.Create(TlsWireVersionTls12), False),
      Scenario('TLS 1.2 mutual TLS', TArray<UInt16>.Create(TlsWireVersionTls12), True));
    for GScenario in GScenarios do
    begin
      GError := RunScenario(GCredentialFile, GScenario);
      if GError <> '' then
      begin
        WriteLn('FAIL [', GScenario.Name, ']: ', GError);
        ExitCode := 1;
        Break;
      end;
      WriteLn('PASS [', GScenario.Name, ']: handshake + echo + close over real TCP');
    end;
    if ExitCode = 0 then
    begin
      GError := WatchdogSelfTest;
      if GError <> '' then
      begin
        WriteLn('FAIL [fuzz watchdog]: ', GError);
        ExitCode := 1;
      end
      else
        WriteLn('PASS [fuzz watchdog]: fires on a hang, stays quiet when disarmed in time');
    end;
  except
    on E: Exception do
    begin
      WriteLn('FAIL: ', E.ClassName, ': ', E.Message);
      ExitCode := 1;
    end;
  end;
end.
