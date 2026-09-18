{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TrustDelegateInteropRunner;

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
  TlpIClock,
  TlpICryptoProvider,
  TlpITlsEngine,
  TlpITlsConfigBuilder,
  TlpTlsPresets,
  TlpTlsEngineFactory,
  TlpSystemTrustFacade,
  TlpOSSystemTrust,
  InteropSocket,
  InteropEngine,
  InteropCredentials,
  InteropPump,
  InteropUtils;

type
  /// <summary>The one native-trust cell to run, parsed from the command line.</summary>
  TTrustCell = record
    TlsVersion: UInt16;
    Delegate: Boolean;
    RootFile: string;
    ServerCertFile: string;
    ServerKeyFile: string;
    StapleFile: string;
    ExpectName: string;
    Posture: TRevocationPosture;
    UseClock: Boolean;
    NowMs: UInt64;
    ExpectAccept: Boolean;
    HasExpectAlert: Boolean;
    ExpectAlert: Int32;
  end;

  /// <summary>
  /// Runs one native-trust cell over a loopback: our server presents a supplied certificate
  /// chain (optionally stapling an OCSP response) and our client verifies it either through the
  /// portable PKIX verifier (a fixed root file) or through the OS trust delegate against the
  /// real machine store. The client asserts a clean handshake or an abort with a given alert,
  /// with a settable revocation posture, injected clock (expired-at-verify-time) and expected
  /// hostname. The CI runner brackets the delegate accept path with a machine-store install.
  /// </summary>
  TTrustDelegateInteropRunner = class sealed(TObject)
  strict private
    class function ArgValue(const AName, ADefault: string): string; static;
    class function HasArg(const AName: string): Boolean; static;
    class function ParsePosture(const ASpec: string): TRevocationPosture; static;
    /// <summary>Parses --expect accept | reject | reject:&lt;alertnum&gt; into ACell.</summary>
    class procedure ParseExpect(const ASpec: string; var ACell: TTrustCell); static;
    class function BuildClientEngine(const AProvider: ICryptoProvider;
      const ACell: TTrustCell): ITlsEngine; static;
    class function RunClient(APort: Word; const ACell: TTrustCell): string; static;
    class function RunCell(const ACell: TTrustCell): string; static;
  public
    /// <summary>Parses the command line, runs the cell, prints PASS/FAIL; returns the exit code.</summary>
    class function Run: Int32; static;
  end;

implementation

type
  /// <summary>A clock pinned to a caller-supplied instant, to drive an expired-at-verify-time
  /// cell (the OS delegate and our verifier both read the validation time from here).</summary>
  TFixedClock = class sealed(TInterfacedObject, ITlsClock)
  strict private
    FNowMs: UInt64;
  public
    constructor Create(ANowMs: UInt64);
    function NowUnixMillis: UInt64;
  end;

  TTrustServerThread = class(TThread)
  strict private
    FListener: TInteropListener;
    FCell: TTrustCell;
    FError: string;
  protected
    procedure Execute; override;
  public
    constructor Create(AListener: TInteropListener; const ACell: TTrustCell);
    // set only on an unexpected server exception; a client abort is an expected, clean
    // handshake failure here, not a server error
    property Error: string read FError;
  end;

{ TFixedClock }

constructor TFixedClock.Create(ANowMs: UInt64);
begin
  inherited Create;
  FNowMs := ANowMs;
end;

function TFixedClock.NowUnixMillis: UInt64;
begin
  Result := FNowMs;
end;

{ TTrustServerThread }

constructor TTrustServerThread.Create(AListener: TInteropListener;
  const ACell: TTrustCell);
begin
  inherited Create(False);
  FreeOnTerminate := False;
  FListener := AListener;
  FCell := ACell;
end;

procedure TTrustServerThread.Execute;
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
    LOptions.SupportedVersions := TArray<UInt16>.Create(FCell.TlsVersion);
    LOptions.HasCredential := True;
    LOptions.Credential := TInteropCredentials.ServerCredentialFromPem(LProvider,
      FCell.ServerCertFile, FCell.ServerKeyFile);
    if FCell.StapleFile <> '' then
      LOptions.OcspStaple := TInteropUtils.ReadAllBytes(FCell.StapleFile);
    LEngine := TInteropEngine.Build(LProvider, LOptions);

    LResult := TInteropPump.DriveHandshake(LEngine, LSocket);
    // a client that rejects the chain aborts the handshake (the reject cells); only an accept
    // cell reaches the echo phase
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

{ TTrustDelegateInteropRunner }

class function TTrustDelegateInteropRunner.ArgValue(const AName,
  ADefault: string): string;
var
  LI: Int32;
begin
  Result := ADefault;
  for LI := 1 to ParamCount - 1 do
    if ParamStr(LI) = AName then
      Exit(ParamStr(LI + 1));
end;

class function TTrustDelegateInteropRunner.HasArg(const AName: string): Boolean;
var
  LI: Int32;
begin
  Result := False;
  for LI := 1 to ParamCount do
    if ParamStr(LI) = AName then
      Exit(True);
end;

class function TTrustDelegateInteropRunner.ParsePosture(
  const ASpec: string): TRevocationPosture;
begin
  if SameText(ASpec, 'hard') then
    Result := TRevocationPosture.Hard
  else if SameText(ASpec, 'off') then
    Result := TRevocationPosture.Off
  else
    Result := TRevocationPosture.Soft;
end;

class procedure TTrustDelegateInteropRunner.ParseExpect(const ASpec: string;
  var ACell: TTrustCell);
var
  LColon: Int32;
begin
  ACell.ExpectAccept := SameText(ASpec, 'accept');
  ACell.HasExpectAlert := False;
  ACell.ExpectAlert := -1;
  if ACell.ExpectAccept then
    Exit;
  LColon := Pos(':', ASpec);
  if LColon > 0 then
  begin
    ACell.HasExpectAlert := True;
    ACell.ExpectAlert := StrToIntDef(Copy(ASpec, LColon + 1, MaxInt), -1);
  end;
end;

class function TTrustDelegateInteropRunner.BuildClientEngine(
  const AProvider: ICryptoProvider; const ACell: TTrustCell): ITlsEngine;
var
  LBuilder: ITlsConfigBuilder;
  LClient: ITlsClientConfigBuilder;
begin
  LBuilder := TTlsPresets.Compatible(AProvider);
  LClient := LBuilder.Client;
  LClient.WithSupportedVersions(TArray<UInt16>.Create(ACell.TlsVersion));
  LClient.WithOcspStaplingRequest(True);
  LClient.WithRevocation(ACell.Posture);
  if ACell.UseClock then
    LClient.WithClock(TFixedClock.Create(ACell.NowMs) as ITlsClock);
  if ACell.Delegate then
    // verify the server certificate through the OS trust engine against the real machine store
    TSystemTrust.WithSystemTrust(LClient, AProvider, TSystemTrustMode.Delegate)
  else
    LClient.WithTrustStore(TInteropCredentials.TrustFromPem(AProvider, ACell.RootFile));
  Result := TTlsEngineFactory.CreateClientEngine(LClient.Build, ACell.ExpectName);
end;

class function TTrustDelegateInteropRunner.RunClient(APort: Word;
  const ACell: TTrustCell): string;
var
  LSocket: TInteropSocket;
  LProvider: ICryptoProvider;
  LEngine: ITlsEngine;
  LResult: TInteropResult;
  LSent: TBytes;
begin
  Result := '';
  LSocket := TInteropSocket.Connect('127.0.0.1', APort);
  try
    LProvider := TInteropEngine.DefaultProvider;
    LEngine := BuildClientEngine(LProvider, ACell);
    LEngine.StartHandshake;
    LResult := TInteropPump.DriveHandshake(LEngine, LSocket);

    if not ACell.ExpectAccept then
    begin
      if LResult.Status <> TInteropStatus.LocalAlert then
        Exit(Format('expected a client reject, got status %d (%s)',
          [Ord(LResult.Status), LResult.Detail]));
      if ACell.HasExpectAlert and
        ((not LResult.HasAlert) or (Ord(LResult.Alert) <> ACell.ExpectAlert)) then
        Exit(Format('expected reject alert %d, got %d',
          [ACell.ExpectAlert, Ord(LResult.Alert)]));
      Exit('');
    end;

    if LResult.Status <> TInteropStatus.Ok then
    begin
      if LResult.HasAlert then
        Exit(Format('expected a completed handshake, got status %d alert %d (%s)',
          [Ord(LResult.Status), Ord(LResult.Alert), LResult.Detail]));
      Exit(Format('expected a completed handshake, got status %d (%s)',
        [Ord(LResult.Status), LResult.Detail]));
    end;
    LSent := TEncoding.UTF8.GetBytes('native trust cell application data');
    TInteropPump.WriteAppData(LEngine, LSocket, LSent);
    LResult := TInteropPump.PumpAppData(LEngine, LSocket);
    if not TInteropUtils.BytesEqual(LResult.Data, LSent) then
      Exit('client did not receive its echo intact');
    TInteropPump.Close(LEngine, LSocket);
  finally
    LSocket.Free;
  end;
end;

class function TTrustDelegateInteropRunner.RunCell(const ACell: TTrustCell): string;
var
  LListener: TInteropListener;
  LServer: TTrustServerThread;
begin
  Result := '';
  LListener := TInteropListener.Bind('127.0.0.1', 0);
  try
    LServer := TTrustServerThread.Create(LListener, ACell);
    try
      Result := RunClient(LListener.Port, ACell);
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

class function TTrustDelegateInteropRunner.Run: Int32;
var
  LCell: TTrustCell;
  LError, LVersionArg: string;
begin
  Result := 0;
  try
    LVersionArg := ArgValue('--tls-version', '13');
    if LVersionArg = '12' then
      LCell.TlsVersion := TlsWireVersionTls12
    else
      LCell.TlsVersion := TlsWireVersionTls13;
    LCell.Delegate := SameText(ArgValue('--trust-mode', 'portable'), 'os-delegate');
    LCell.RootFile := ArgValue('--root', '');
    LCell.ServerCertFile := ArgValue('--server-cert', '');
    LCell.ServerKeyFile := ArgValue('--server-key', '');
    LCell.StapleFile := ArgValue('--staple', '');
    LCell.ExpectName := ArgValue('--expect-name', 'localhost');
    LCell.Posture := ParsePosture(ArgValue('--posture', 'soft'));
    LCell.UseClock := HasArg('--now-ms');
    LCell.NowMs := UInt64(StrToInt64Def(ArgValue('--now-ms', '0'), 0));
    ParseExpect(ArgValue('--expect', 'accept'), LCell);

    if (LCell.ServerCertFile = '') or (LCell.ServerKeyFile = '') then
      raise Exception.Create('--server-cert and --server-key are required');
    if (not LCell.Delegate) and (LCell.RootFile = '') then
      raise Exception.Create('portable trust mode requires --root');

    LError := RunCell(LCell);
    if LError <> '' then
    begin
      WriteLn('FAIL: ', LError);
      Result := 1;
    end
    else
      WriteLn('PASS');
  except
    on E: Exception do
    begin
      WriteLn('FAIL: ', E.ClassName, ': ', E.Message);
      Result := 1;
    end;
  end;
end;

end.
