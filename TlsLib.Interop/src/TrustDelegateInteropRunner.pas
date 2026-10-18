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
  TlpIPkixProvider,
  TlpITlsEngine,
  TlpITlsConfigBuilder,
  TlpCertificateVerifierSource,
  TlpTlsPresets,
  TlpTlsEngineFactory,
  TlpITlsConfig,
  TlpITrustAnchorStore,
  TlpSystemTrustFacade,
  TlpSystemTrustBase,
  TlpOSLiveRevocation,
  TlpOSSystemTrust,
  InteropSocket,
  InteropEngine,
  TlsLibTestProviders,
  InteropCredentials,
  InteropPump,
  InteropUtils;

type
  /// <summary>The one native-trust cell to run, parsed from the command line.</summary>
  TTrustCell = record
    TlsVersion: UInt16;
    // the OS trust engine decides (os-delegate); Anchors instead feeds the OS root set, and its
    // distrust set, into our own verifier (os-anchors)
    Delegate: Boolean;
    Anchors: Boolean;
    Live: Boolean;
    // server-mode (mTLS): our server verifies the peer CLIENT certificate live through the OS
    // delegate, and a client presenter offers the certificate
    IsServer: Boolean;
    RootFile: string;
    // os-delegate / os-anchors only: a root trusted beside the OS roots
    HostRootFile: string;
    // client only: dial this dotted-IPv4 peer instead of the in-process server (--connect ip:port)
    ConnectHost: string;
    ConnectPort: Word;
    ServerCertFile: string;
    ServerKeyFile: string;
    StapleFile: string;
    // server-mode only: the presenter's credential, the server's exclusive client-CA anchor, and
    // (for the exclusivity cell) a separate client-CA the live resolver roots against
    ClientCertFile: string;
    ClientKeyFile: string;
    ClientCaFile: string;
    LiveClientCaFile: string;
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
  /// portable PKIX verifier (a fixed root file), through the OS trust delegate against the
  /// real machine store, or through our own verifier over the OS root set and its distrust set
  /// (os-anchors). The client asserts a clean handshake or an abort with a given alert,
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
    class function BuildClientConfig(const ACryptoProvider: ICryptoProvider;
      const APkix: IPkixProvider; const ACell: TTrustCell): ITlsClientConfig; static;
    /// <summary>Maps a handshake outcome to '' (matched --expect) or a failure message. Shared by
    /// the client-verifies-server and server-verifies-client paths.</summary>
    class function MapOutcome(const ACell: TTrustCell;
      const AResult: TInteropResult): string; static;
    /// <summary>The server config for the mTLS cell: an OS client delegate (Live) over ACaFile as the
    /// exclusive client-CA anchor. Built here (not via InteropEngine) so the frozen ITlsServerConfig
    /// is kept for both the engine and the live resolver.</summary>
    class function BuildServerConfig(const ACryptoProvider: ICryptoProvider;
      const APkix: IPkixProvider; const ACell: TTrustCell;
      const ACaFile: string): ITlsServerConfig; static;
    class function RunClient(const AHost: string; APort: Word;
      const ACell: TTrustCell): string; static;
    class function RunCell(const ACell: TTrustCell): string; static;
    class function RunServer(const ACell: TTrustCell): string; static;
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

  /// <summary>The mTLS peer for the server-verifies-client cell: a client that offers a certificate
  /// over an already-connected socket (the main thread connects and hands it over, so the presenter
  /// can never miss the accept). It trusts the server root and drives to completion; on an accept
  /// cell it verifies the server's echo. Its error is consulted only on accept cells - on a reject
  /// cell the server's alert breaks this side, which is expected.</summary>
  TClientPresenterThread = class(TThread)
  strict private
    FSocket: TInteropSocket;
    FCell: TTrustCell;
    FError: string;
  protected
    procedure Execute; override;
  public
    constructor Create(ASocket: TInteropSocket; const ACell: TTrustCell);
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
  LCrypto: ICryptoProvider;
  LPkix: IPkixProvider;
  LOptions: TInteropEngineOptions;
  LEngine: ITlsEngine;
  LResult: TInteropResult;
begin
  FError := '';
  LSocket := nil;
  try
    LSocket := FListener.Accept;
    LCrypto := TTlsLibTestProviders.Crypto;
    LPkix := TTlsLibTestProviders.Pkix;
    LOptions := Default(TInteropEngineOptions);
    LOptions.Role := TInteropRole.Server;
    LOptions.SupportedVersions := TArray<UInt16>.Create(FCell.TlsVersion);
    LOptions.HasCredential := True;
    LOptions.Credential := TInteropCredentials.ServerCredentialFromPem(LCrypto, LPkix,
      FCell.ServerCertFile, FCell.ServerKeyFile);
    if FCell.StapleFile <> '' then
      LOptions.OcspStaple := TInteropUtils.ReadAllBytes(FCell.StapleFile);
    LEngine := TInteropEngine.Build(LCrypto, LOptions);

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

{ TClientPresenterThread }

constructor TClientPresenterThread.Create(ASocket: TInteropSocket;
  const ACell: TTrustCell);
begin
  inherited Create(False);
  FreeOnTerminate := False;
  FSocket := ASocket;
  FCell := ACell;
end;

procedure TClientPresenterThread.Execute;
var
  LCrypto: ICryptoProvider;
  LPkix: IPkixProvider;
  LBuilder: ITlsConfigBuilder;
  LClient: ITlsClientConfigBuilder;
  LConfig: ITlsClientConfig;
  LEngine: ITlsEngine;
  LResult: TInteropResult;
  LSent: TBytes;
begin
  FError := '';
  try
    LCrypto := TTlsLibTestProviders.Crypto;
    LPkix := TTlsLibTestProviders.Pkix;
    LBuilder := TTlsPresets.Compatible(LCrypto, LPkix);
    LClient := LBuilder.Client;
    LClient.WithSupportedVersions(TArray<UInt16>.Create(FCell.TlsVersion));
    // trust the server's own certificate (portable, cache-only - this side is not under test)
    LClient.WithServerVerification(TServerVerification.WebPki(
      TInteropCredentials.TrustFromPem(LPkix, FCell.RootFile)).Build);
    // offer the client certificate the server verifies (leaf-only: the CA is the server's anchor)
    LClient.WithCredential(TInteropCredentials.ServerCredentialFromPem(LCrypto, LPkix,
      FCell.ClientCertFile, FCell.ClientKeyFile));
    LConfig := LClient.Build;
    LEngine := TTlsEngineFactory.CreateClientEngine(LConfig, FCell.ExpectName);
    LEngine.StartHandshake;
    LResult := TInteropPump.DriveHandshake(LEngine, FSocket);
    if LResult.Status = TInteropStatus.Ok then
    begin
      // accept path: exchange one echo so both sides complete cleanly, and confirm it round-trips
      LSent := TEncoding.UTF8.GetBytes('native trust mtls client data');
      TInteropPump.WriteAppData(LEngine, FSocket, LSent);
      LResult := TInteropPump.PumpAppData(LEngine, FSocket);
      if not TInteropUtils.BytesEqual(LResult.Data, LSent) then
        FError := 'presenter did not receive its echo intact'
      else
        TInteropPump.Close(LEngine, FSocket);
    end;
    // a non-Ok handshake here is the server rejecting the client cert - expected on reject cells,
    // ignored by the caller unless this is an accept cell
  except
    on E: Exception do
      FError := 'presenter exception: ' + E.Message;
  end;
  FSocket.Free;
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
  if ACell.ExpectAccept or SameText(ASpec, 'reject') then
    Exit;
  LColon := Pos(':', ASpec);
  if (LColon > 0) and SameText(Copy(ASpec, 1, LColon - 1), 'reject') then
  begin
    ACell.ExpectAlert := StrToIntDef(Copy(ASpec, LColon + 1, MaxInt), -1);
    if (ACell.ExpectAlert >= 0) and (ACell.ExpectAlert <= 255) then
    begin
      ACell.HasExpectAlert := True;
      Exit;
    end;
  end;
  raise Exception.Create('--expect takes accept, reject or reject:<alert>, got ''' + ASpec + '''');
end;

class function TTrustDelegateInteropRunner.BuildClientConfig(
  const ACryptoProvider: ICryptoProvider; const APkix: IPkixProvider;
  const ACell: TTrustCell): ITlsClientConfig;
const
  // the resolver fetch budget for the live cells; the OS fetch over loopback settles well within it
  LiveDeadlineMs = Cardinal(10000);
var
  LBuilder: ITlsConfigBuilder;
  LClient: ITlsClientConfigBuilder;
  LHostRoots: ITrustAnchorStore;
begin
  LHostRoots := nil;
  if ACell.HostRootFile <> '' then
    LHostRoots := TInteropCredentials.TrustFromPem(APkix, ACell.HostRootFile);
  LBuilder := TTlsPresets.Compatible(ACryptoProvider, APkix);
  LClient := LBuilder.Client;
  LClient.WithSupportedVersions(TArray<UInt16>.Create(ACell.TlsVersion));
  LClient.WithOcspStaplingRequest(True);
  if ACell.UseClock then
    LClient.WithClock(TFixedClock.Create(ACell.NowMs) as ITlsClock);
  if ACell.Anchors then
    // the OS root set and its distrust set, harvested into our own verifier
    LClient.WithServerVerification(TSystemTrust.ServerVerification(APkix,
      TSystemTrustMode.Anchors, LHostRoots).WithRevocation(ACell.Posture).Build)
  else if ACell.Delegate then
  begin
    // verify the server certificate through the OS trust engine against the real machine store;
    // live arms the async park the OS-native resolver decides in
    if ACell.Live then
      TSystemTrust.WithLiveSystemTrust(LClient, ACell.Posture, LiveDeadlineMs)
    else
      LClient.WithServerVerification(TSystemTrust.ServerVerification(APkix,
        TSystemTrustMode.Delegate, LHostRoots).WithRevocation(ACell.Posture).Build);
  end
  else
    LClient.WithServerVerification(TServerVerification.WebPki(
      TInteropCredentials.TrustFromPem(APkix, ACell.RootFile)).WithRevocation(ACell.Posture).Build);
  Result := LClient.Build;
end;

class function TTrustDelegateInteropRunner.MapOutcome(const ACell: TTrustCell;
  const AResult: TInteropResult): string;
begin
  Result := '';
  if not ACell.ExpectAccept then
  begin
    if AResult.Status <> TInteropStatus.LocalAlert then
      Exit(Format('expected a reject, got status %d (%s)',
        [Ord(AResult.Status), AResult.Detail]));
    if ACell.HasExpectAlert and
      ((not AResult.HasAlert) or (Ord(AResult.Alert) <> ACell.ExpectAlert)) then
      Exit(Format('expected reject alert %d, got %d',
        [ACell.ExpectAlert, Ord(AResult.Alert)]));
    Exit('');
  end;
  if AResult.Status <> TInteropStatus.Ok then
  begin
    if AResult.HasAlert then
      Exit(Format('expected a completed handshake, got status %d alert %d (%s)',
        [Ord(AResult.Status), Ord(AResult.Alert), AResult.Detail]));
    Exit(Format('expected a completed handshake, got status %d (%s)',
      [Ord(AResult.Status), AResult.Detail]));
  end;
end;

class function TTrustDelegateInteropRunner.RunClient(const AHost: string;
  APort: Word; const ACell: TTrustCell): string;
var
  LSocket: TInteropSocket;
  LCrypto: ICryptoProvider;
  LPkix: IPkixProvider;
  LConfig: ITlsClientConfig;
  LEngine: ITlsEngine;
  LResolver: TOSLiveRevocationResolverBase;
  LResult: TInteropResult;
  LSent: TBytes;
begin
  Result := '';
  LSocket := TInteropSocket.Connect(AHost, APort);
  try
    LCrypto := TTlsLibTestProviders.Crypto;
    LPkix := TTlsLibTestProviders.Pkix;
    LConfig := BuildClientConfig(LCrypto, LPkix, ACell);
    LEngine := TTlsEngineFactory.CreateClientEngine(LConfig, ACell.ExpectName);
    LEngine.StartHandshake;
    if ACell.Live then
    begin
      // the host resolves the async park by re-running the OS engine live (network on)
      LResolver := TOSSystemTrust.LiveRevocationResolver(LConfig);
      try
        LResult := TInteropPump.DriveHandshake(LEngine, LSocket,
          LResolver.ResolveVerdict, True);
      finally
        LResolver.Free;
      end;
    end
    else
      LResult := TInteropPump.DriveHandshake(LEngine, LSocket);

    Result := MapOutcome(ACell, LResult);
    if (Result <> '') or (not ACell.ExpectAccept) then
      Exit;
    // a real peer does not echo: the verdict is all the connect mode measures
    if ACell.ConnectHost <> '' then
    begin
      TInteropPump.Close(LEngine, LSocket);
      Exit;
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

class function TTrustDelegateInteropRunner.BuildServerConfig(
  const ACryptoProvider: ICryptoProvider; const APkix: IPkixProvider;
  const ACell: TTrustCell; const ACaFile: string): ITlsServerConfig;
const
  // the resolver fetch budget for the live client-cert check; the OS fetch over loopback settles
  // well within it
  LiveDeadlineMs = Cardinal(10000);
var
  LBuilder: ITlsConfigBuilder;
  LServer: ITlsServerConfigBuilder;
begin
  LBuilder := TTlsPresets.Compatible(ACryptoProvider, APkix);
  LServer := LBuilder.Server;
  LServer.WithSupportedVersions(TArray<UInt16>.Create(ACell.TlsVersion));
  LServer.WithCredential(TInteropCredentials.ServerCredentialFromPem(ACryptoProvider, APkix,
    ACell.ServerCertFile, ACell.ServerKeyFile));
  LServer.WithPeerAuth(TClientAuthMode.Required);
  // arm the live-revocation park the OS-native resolver decides in (Hard client-cert needs it)
  LServer.WithLiveRevocationVerdict(LiveDeadlineMs);
  // a NewSessionTicket would otherwise arrive before the echo and look like a broken round-trip
  LServer.WithResumption(False);
  // the OS engine verifies the client certificate live at the park, rooted at the client-CA
  LServer.WithClientVerification(TClientVerification.VerifierSource(
    TOSSystemTrust.ClientVerifierSource(TSystemTrustFetch.Live),
    TInteropCredentials.TrustFromPem(APkix, ACaFile)).WithRevocation(ACell.Posture).Build);
  Result := LServer.Build;
end;

class function TTrustDelegateInteropRunner.RunServer(const ACell: TTrustCell): string;
var
  LListener: TInteropListener;
  LPresenterSocket, LServerSocket: TInteropSocket;
  LPresenter: TClientPresenterThread;
  LCrypto: ICryptoProvider;
  LPkix: IPkixProvider;
  LConfig: ITlsServerConfig;
  LEngine: ITlsEngine;
  LResolver: TOSLiveRevocationResolverBase;
  LResult, LEcho: TInteropResult;
  LLiveCaFile: string;
begin
  Result := '';
  LCrypto := TTlsLibTestProviders.Crypto;
  LPkix := TTlsLibTestProviders.Pkix;
  LListener := TInteropListener.Bind('127.0.0.1', 0);
  try
    // the main thread connects the presenter first (so it can never miss the accept), then hands the
    // connected socket to the presenter thread
    LPresenterSocket := TInteropSocket.Connect('127.0.0.1', LListener.Port);
    LPresenter := TClientPresenterThread.Create(LPresenterSocket, ACell);
    try
      LServerSocket := LListener.Accept;
      try
        LConfig := BuildServerConfig(LCrypto, LPkix, ACell, ACell.ClientCaFile);
        LEngine := TTlsEngineFactory.CreateServerEngine(LConfig);
        // the live resolver roots against the client-CA of a possibly-different config: for the
        // exclusivity cell that is a foreign CA (--live-client-ca), else the same inline client CA
        LLiveCaFile := ACell.LiveClientCaFile;
        if LLiveCaFile = '' then
          LLiveCaFile := ACell.ClientCaFile;
        LResolver := TOSSystemTrust.LiveRevocationResolver(
          BuildServerConfig(LCrypto, LPkix, ACell, LLiveCaFile));
        try
          LResult := TInteropPump.DriveHandshake(LEngine, LServerSocket,
            LResolver.ResolveVerdict, False);
          // accept path: echo the presenter's app data so both sides complete cleanly
          if LResult.Status = TInteropStatus.Ok then
          begin
            repeat
              LEcho := TInteropPump.PumpAppData(LEngine, LServerSocket);
              if System.Length(LEcho.Data) > 0 then
                TInteropPump.WriteAppData(LEngine, LServerSocket, LEcho.Data);
            until LEcho.Status <> TInteropStatus.Ok;
            if LEcho.Status = TInteropStatus.PeerClosed then
              TInteropPump.Close(LEngine, LServerSocket);
          end;
        finally
          LResolver.Free;
        end;
      finally
        // free the server socket BEFORE WaitFor: it sends the FIN the presenter's drain-close is
        // waiting on, so the presenter thread can finish (avoids a mutual close_notify deadlock)
        LServerSocket.Free;
      end;
      LPresenter.WaitFor;
      // the server is the side under test (it verifies the client cert and emits any reject alert)
      Result := MapOutcome(ACell, LResult);
      // a presenter error only matters on an accept cell; on a reject the server's alert breaks it
      if (Result = '') and ACell.ExpectAccept and (LPresenter.Error <> '') then
        Result := LPresenter.Error;
    finally
      LPresenter.Free;
    end;
  finally
    LListener.Free;
  end;
end;

class function TTrustDelegateInteropRunner.RunCell(const ACell: TTrustCell): string;
var
  LListener: TInteropListener;
  LServer: TTrustServerThread;
begin
  // server-mode (mTLS): our server verifies the peer client certificate live through the OS delegate
  if ACell.IsServer then
    Exit(RunServer(ACell));
  if ACell.ConnectHost <> '' then
    Exit(RunClient(ACell.ConnectHost, ACell.ConnectPort, ACell));
  Result := '';
  LListener := TInteropListener.Bind('127.0.0.1', 0);
  try
    LServer := TTrustServerThread.Create(LListener, ACell);
    try
      Result := RunClient('127.0.0.1', LListener.Port, ACell);
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
  LError, LVersionArg, LConnect: string;
  LColon: Int32;
begin
  Result := 0;
  try
    LVersionArg := ArgValue('--tls-version', '13');
    if LVersionArg = '12' then
      LCell.TlsVersion := TlsWireVersionTls12
    else
      LCell.TlsVersion := TlsWireVersionTls13;
    LCell.IsServer := SameText(ArgValue('--role', 'client'), 'server');
    LCell.Delegate := SameText(ArgValue('--trust-mode', 'portable'), 'os-delegate');
    LCell.Anchors := SameText(ArgValue('--trust-mode', 'portable'), 'os-anchors');
    // live OS-native revocation implies the OS delegate (the live re-check runs the OS engine)
    LCell.Live := SameText(ArgValue('--revocation-fetch', 'cache'), 'live');
    if LCell.Live and LCell.Anchors then
      raise Exception.Create('os-anchors has no live revocation; use os-delegate');
    if LCell.Live then
      LCell.Delegate := True;
    // the server cell always verifies the peer client cert live through the OS delegate
    if LCell.IsServer then
    begin
      if LCell.Anchors then
        raise Exception.Create('--role server verifies through the OS delegate, not os-anchors');
      LCell.Delegate := True;
      LCell.Live := True;
    end;
    LCell.RootFile := ArgValue('--root', '');
    LCell.HostRootFile := ArgValue('--host-root', '');
    if (LCell.HostRootFile <> '') and (LCell.IsServer or LCell.Live) then
      raise Exception.Create('--host-root applies to the non-live client OS modes only');
    if (LCell.HostRootFile <> '') and not (LCell.Delegate or LCell.Anchors) then
      raise Exception.Create('--host-root needs --trust-mode os-delegate or os-anchors');
    LConnect := ArgValue('--connect', '');
    LCell.ConnectHost := '';
    LCell.ConnectPort := 0;
    if LConnect <> '' then
    begin
      LColon := Pos(':', LConnect);
      LCell.ConnectHost := Copy(LConnect, 1, LColon - 1);
      LCell.ConnectPort := Word(StrToIntDef(Copy(LConnect, LColon + 1, MaxInt), 0));
      if (LColon = 0) or (LCell.ConnectHost = '') or (LCell.ConnectPort = 0) then
        raise Exception.Create('--connect expects <ipv4>:<port>');
      if LCell.IsServer or LCell.Live or not (LCell.Delegate or LCell.Anchors) then
        raise Exception.Create(
          '--connect applies to the non-live client os-delegate / os-anchors modes only');
      if HasArg('--server-cert') or HasArg('--server-key') or HasArg('--staple') or
        HasArg('--now-ms') then
        raise Exception.Create('--connect dials a real peer: no --server-cert/--server-key/--staple/--now-ms');
    end;
    LCell.ServerCertFile := ArgValue('--server-cert', '');
    LCell.ServerKeyFile := ArgValue('--server-key', '');
    LCell.StapleFile := ArgValue('--staple', '');
    LCell.ClientCertFile := ArgValue('--client-cert', '');
    LCell.ClientKeyFile := ArgValue('--client-key', '');
    LCell.ClientCaFile := ArgValue('--client-ca', '');
    LCell.LiveClientCaFile := ArgValue('--live-client-ca', '');
    LCell.ExpectName := ArgValue('--expect-name', 'localhost');
    LCell.Posture := ParsePosture(ArgValue('--posture', 'soft'));
    LCell.UseClock := HasArg('--now-ms');
    LCell.NowMs := UInt64(StrToInt64Def(ArgValue('--now-ms', '0'), 0));
    ParseExpect(ArgValue('--expect', 'accept'), LCell);

    if (LCell.ConnectHost = '') and
      ((LCell.ServerCertFile = '') or (LCell.ServerKeyFile = '')) then
      raise Exception.Create('--server-cert and --server-key are required');
    if LCell.IsServer then
    begin
      if (LCell.RootFile = '') or (LCell.ClientCertFile = '') or
        (LCell.ClientKeyFile = '') or (LCell.ClientCaFile = '') then
        raise Exception.Create(
          '--role server requires --root, --client-cert, --client-key and --client-ca');
    end
    else if (not LCell.Delegate) and (not LCell.Anchors) and (LCell.RootFile = '') then
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
