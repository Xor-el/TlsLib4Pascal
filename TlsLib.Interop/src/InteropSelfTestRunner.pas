{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit InteropSelfTestRunner;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

interface

uses
  SysUtils,
  Classes,
  TlpTlsVersion,
  TlpTlsCredential,
  TlpTrustPolicy,
  TlpTlsAlert,
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

  TRevExpect = (RevOk, RevClientAlert);

  /// <summary>One revocation cell: the offered version, whether the server presents the
  /// must-staple leaf, which OCSP vector it staples (empty = none), the client posture, and
  /// the expected outcome (a clean handshake, or a client abort carrying Alert).</summary>
  TRevCell = record
    Name: string;
    Version: UInt16;
    MustStapleLeaf: Boolean;
    StapleField: string;
    Posture: TRevocationPosture;
    Expect: TRevExpect;
    Alert: TTlsAlertDescription;
  end;

  /// <summary>
  /// The no-external-deps smoke: drives real TLS handshakes between our own client and server
  /// engines over a loopback TCP socket (TLS 1.3, hardened 1.2, mutual TLS), then the
  /// revocation-over-the-wire cells (a stapled Good/Revoked/stale/must-staple response asserted
  /// end to end across both stapling framings), then the fuzz-watchdog self-test. Proves the
  /// socket transport + pump + engine composition so CI can gate it on every leg without Go or
  /// openssl.
  /// </summary>
  TInteropSelfTestRunner = class sealed(TObject)
  strict private
    class function StrBytes(const AText: string): TBytes; static;
    class function BytesEqual(const A, B: TBytes): Boolean; static;
    class function Scenario(const AName: string; const AVersions: TArray<UInt16>;
      AMutualTls: Boolean): TScenario; static;
    class function RunClient(APort: Word; const ACredentialFile: string;
      const AScenario: TScenario): string; static;
    class function RunScenario(const ACredentialFile: string;
      const AScenario: TScenario): string; static;
    class function RevCell(const AName: string; AVersion: UInt16; AMustStapleLeaf: Boolean;
      const AStapleField: string; APosture: TRevocationPosture; AExpect: TRevExpect;
      AAlert: TTlsAlertDescription): TRevCell; static;
    class function RevocationCellsFor(AVersion: UInt16): TArray<TRevCell>; static;
    class function RunRevClient(APort: Word; const ADataFile: string;
      const ACell: TRevCell): string; static;
    class function RunRevCell(const ADataFile: string; const ACell: TRevCell): string; static;
    class function WatchdogSelfTest: string; static;
  public
    /// <summary>Runs every scenario, revocation cell and the watchdog; returns the exit code.</summary>
    class function Run: Int32; static;
  end;

implementation

type
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

  TRevServerThread = class(TThread)
  strict private
    FListener: TInteropListener;
    FDataFile: string;
    FCell: TRevCell;
    FError: string;
  protected
    procedure Execute; override;
  public
    constructor Create(AListener: TInteropListener; const ADataFile: string;
      const ACell: TRevCell);
    // set only on an unexpected server exception; a client abort is an expected, clean
    // handshake failure here, not a server error
    property Error: string read FError;
  end;

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

{ TServerThread }

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

{ TRevServerThread }

constructor TRevServerThread.Create(AListener: TInteropListener;
  const ADataFile: string; const ACell: TRevCell);
begin
  inherited Create(False);
  FreeOnTerminate := False;
  FListener := AListener;
  FDataFile := ADataFile;
  FCell := ACell;
end;

procedure TRevServerThread.Execute;
var
  LSocket: TInteropSocket;
  LProvider: ICryptoProvider;
  LOptions: TInteropEngineOptions;
  LEngine: ITlsEngine;
  LResult: TInteropResult;
  LFields: TStringList;
begin
  FError := '';
  LSocket := nil;
  try
    LSocket := FListener.Accept;
    LProvider := TInteropEngine.DefaultProvider;
    LOptions := Default(TInteropEngineOptions);
    LOptions.Role := TInteropRole.Server;
    LOptions.SupportedVersions := TArray<UInt16>.Create(FCell.Version);
    LOptions.HasCredential := True;
    if FCell.MustStapleLeaf then
      LOptions.Credential := TInteropCredentials.ServerStaplingCredentialFields(
        LProvider, FDataFile, 'muststaple_leaf_cert', 'muststaple_leaf_key')
    else
      LOptions.Credential := TInteropCredentials.ServerStaplingCredentialFields(
        LProvider, FDataFile, 'leaf_cert', 'leaf_key');
    if FCell.StapleField <> '' then
    begin
      LFields := TStringList.Create;
      try
        TInteropUtils.LoadFieldFile(FDataFile, LFields);
        LOptions.OcspStaple := TInteropUtils.DecodeHex(LFields.Values[FCell.StapleField]);
      finally
        LFields.Free;
      end;
    end;
    LEngine := TInteropEngine.Build(LProvider, LOptions);

    LResult := TInteropPump.DriveHandshake(LEngine, LSocket);
    // a client that rejects the staple aborts the handshake: expected for the reject cells,
    // so only the accept cells reach the echo phase
    if LResult.Status = TInteropStatus.Ok then
    begin
      repeat
        LResult := TInteropPump.PumpAppData(LEngine, LSocket);
        if System.Length(LResult.Data) > 0 then
          TInteropPump.WriteAppData(LEngine, LSocket, LResult.Data);
      until LResult.Status <> TInteropStatus.Ok;
      if LResult.Status = TInteropStatus.PeerClosed then
        TInteropPump.Close(LEngine, LSocket);
    end;
  except
    on E: Exception do
      FError := 'server exception: ' + E.Message;
  end;
  LSocket.Free;
end;

{ TFlagHangHandler }

procedure TFlagHangHandler.HandleHang(const AInput: TBytes; AIteration: Int32);
begin
  Inc(FCount);
  FInput := AInput;
  FIteration := AIteration;
end;

{ TInteropSelfTestRunner }

class function TInteropSelfTestRunner.StrBytes(const AText: string): TBytes;
begin
  Result := TEncoding.UTF8.GetBytes(AText);
end;

class function TInteropSelfTestRunner.BytesEqual(const A, B: TBytes): Boolean;
begin
  Result := (System.Length(A) = System.Length(B)) and
    ((System.Length(A) = 0) or CompareMem(@A[0], @B[0], System.Length(A)));
end;

class function TInteropSelfTestRunner.Scenario(const AName: string;
  const AVersions: TArray<UInt16>; AMutualTls: Boolean): TScenario;
begin
  Result.Name := AName;
  Result.Versions := AVersions;
  Result.MutualTls := AMutualTls;
end;

class function TInteropSelfTestRunner.RunClient(APort: Word;
  const ACredentialFile: string; const AScenario: TScenario): string;
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

class function TInteropSelfTestRunner.RunScenario(const ACredentialFile: string;
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

class function TInteropSelfTestRunner.RevCell(const AName: string; AVersion: UInt16;
  AMustStapleLeaf: Boolean; const AStapleField: string; APosture: TRevocationPosture;
  AExpect: TRevExpect; AAlert: TTlsAlertDescription): TRevCell;
begin
  Result.Name := AName;
  Result.Version := AVersion;
  Result.MustStapleLeaf := AMustStapleLeaf;
  Result.StapleField := AStapleField;
  Result.Posture := APosture;
  Result.Expect := AExpect;
  Result.Alert := AAlert;
end;

// the five posture x vector outcomes, run under both stapling framings
class function TInteropSelfTestRunner.RevocationCellsFor(
  AVersion: UInt16): TArray<TRevCell>;
begin
  Result := TArray<TRevCell>.Create(
    RevCell('good staple / Hard -> accept', AVersion, False, 'ocsp_good',
      TRevocationPosture.Hard, TRevExpect.RevOk, TTlsAlertDescription.CloseNotify),
    RevCell('revoked staple / Soft -> certificate_revoked', AVersion, False, 'ocsp_revoked',
      TRevocationPosture.Soft, TRevExpect.RevClientAlert,
      TTlsAlertDescription.CertificateRevoked),
    RevCell('stale staple / Hard -> bad_certificate_status_response', AVersion, False,
      'ocsp_stale', TRevocationPosture.Hard, TRevExpect.RevClientAlert,
      TTlsAlertDescription.BadCertificateStatusResponse),
    RevCell('stale staple / Soft -> accept', AVersion, False, 'ocsp_stale',
      TRevocationPosture.Soft, TRevExpect.RevOk, TTlsAlertDescription.CloseNotify),
    RevCell('must-staple, no staple / Off -> bad_certificate_status_response', AVersion,
      True, '', TRevocationPosture.Off, TRevExpect.RevClientAlert,
      TTlsAlertDescription.BadCertificateStatusResponse));
end;

class function TInteropSelfTestRunner.RunRevClient(APort: Word;
  const ADataFile: string; const ACell: TRevCell): string;
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
    LOptions.SupportedVersions := TArray<UInt16>.Create(ACell.Version);
    LOptions.ServerName := 'localhost';
    LOptions.CheckServerName := True;
    LOptions.Trust := TInteropCredentials.TrustFromFieldFile(LProvider, ADataFile);
    // offer status_request regardless of posture, else the server never staples and the cell
    // proves nothing; pin the posture the cell dictates
    LOptions.RequestOcsp := True;
    LOptions.ApplyRevocation := True;
    LOptions.RevocationPosture := ACell.Posture;
    LEngine := TInteropEngine.Build(LProvider, LOptions);

    LEngine.StartHandshake;
    LResult := TInteropPump.DriveHandshake(LEngine, LSocket);

    if ACell.Expect = TRevExpect.RevClientAlert then
    begin
      if LResult.Status <> TInteropStatus.LocalAlert then
        Exit(Format('expected a client abort, got status %d (%s)',
          [Ord(LResult.Status), LResult.Detail]));
      if (not LResult.HasAlert) or (LResult.Alert <> ACell.Alert) then
        Exit(Format('expected alert %d, got %d', [Ord(ACell.Alert), Ord(LResult.Alert)]));
      Exit('');
    end;

    // RevOk: the handshake must complete and the connection carry application data
    if LResult.Status <> TInteropStatus.Ok then
      Exit('expected a completed handshake, got: ' + LResult.Detail);
    LSent := StrBytes('revocation cell application data');
    TInteropPump.WriteAppData(LEngine, LSocket, LSent);
    LResult := TInteropPump.PumpAppData(LEngine, LSocket);
    if not BytesEqual(LResult.Data, LSent) then
      Exit('client did not receive its echo intact');
    TInteropPump.Close(LEngine, LSocket);
  finally
    LSocket.Free;
  end;
end;

class function TInteropSelfTestRunner.RunRevCell(const ADataFile: string;
  const ACell: TRevCell): string;
var
  LListener: TInteropListener;
  LServer: TRevServerThread;
begin
  Result := '';
  LListener := TInteropListener.Bind('127.0.0.1', 0);
  try
    LServer := TRevServerThread.Create(LListener, ADataFile, ACell);
    try
      Result := RunRevClient(LListener.Port, ADataFile, ACell);
      LServer.WaitFor;
      if LServer.Error <> '' then
        if Result = '' then
          Result := LServer.Error
        else
          Result := Result + ' | ' + LServer.Error;
    finally
      LServer.Free;
    end;
  finally
    LListener.Free;
  end;
end;

// the watchdog fires exactly once when an armed interval outlives the timeout - carrying
// the armed input and iteration - and stays quiet when disarmed in time or after it fired.
// fire detection waits (bounded) for the poll thread rather than a fixed delay, so a loaded
// host cannot make it flaky
class function TInteropSelfTestRunner.WatchdogSelfTest: string;

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

class function TInteropSelfTestRunner.Run: Int32;
var
  LCredentialFile: string;
  LScenarios: TArray<TScenario>;
  LScenario: TScenario;
  LError: string;
  LStapleFile: string;
  LRevVersions: TArray<UInt16>;
  LRevVersion: UInt16;
  LRevCell: TRevCell;
  LRevLabel: string;
begin
  Result := 0;
  try
    LCredentialFile := TInteropUtils.LocateDataDir + PathDelim + 'Certs' +
      PathDelim + 'EcP256Chain.txt';
    LScenarios := TArray<TScenario>.Create(
      Scenario('TLS 1.3', nil, False),
      Scenario('TLS 1.3 mutual TLS', TArray<UInt16>.Create(TlsWireVersionTls13), True),
      Scenario('TLS 1.2', TArray<UInt16>.Create(TlsWireVersionTls12), False),
      Scenario('TLS 1.2 mutual TLS', TArray<UInt16>.Create(TlsWireVersionTls12), True));
    for LScenario in LScenarios do
    begin
      LError := RunScenario(LCredentialFile, LScenario);
      if LError <> '' then
      begin
        WriteLn('FAIL [', LScenario.Name, ']: ', LError);
        Result := 1;
        Break;
      end;
      WriteLn('PASS [', LScenario.Name, ']: handshake + echo + close over real TCP');
    end;
    if Result = 0 then
    begin
      LStapleFile := TInteropUtils.LocateDataDir + PathDelim + 'Certs' +
        PathDelim + 'OcspStapling.txt';
      LRevVersions := TArray<UInt16>.Create(TlsWireVersionTls13, TlsWireVersionTls12);
      for LRevVersion in LRevVersions do
      begin
        if LRevVersion = TlsWireVersionTls12 then
          LRevLabel := 'TLS 1.2'
        else
          LRevLabel := 'TLS 1.3';
        for LRevCell in RevocationCellsFor(LRevVersion) do
        begin
          LError := RunRevCell(LStapleFile, LRevCell);
          if LError <> '' then
          begin
            WriteLn('FAIL [', LRevLabel, ' revocation: ', LRevCell.Name, ']: ', LError);
            Result := 1;
            Break;
          end;
          WriteLn('PASS [', LRevLabel, ' revocation: ', LRevCell.Name, ']');
        end;
        if Result <> 0 then
          Break;
      end;
    end;
    if Result = 0 then
    begin
      LError := WatchdogSelfTest;
      if LError <> '' then
      begin
        WriteLn('FAIL [fuzz watchdog]: ', LError);
        Result := 1;
      end
      else
        WriteLn('PASS [fuzz watchdog]: fires on a hang, stays quiet when disarmed in time');
    end;
  except
    on E: Exception do
    begin
      WriteLn('FAIL: ', E.ClassName, ': ', E.Message);
      Result := 1;
    end;
  end;
end;

end.
