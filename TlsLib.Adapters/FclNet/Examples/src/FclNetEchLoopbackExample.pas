{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

/// <summary>
/// An Encrypted Client Hello (RFC 9849) loopback over fcl-net's TSSLSocketHandler seam on
/// 127.0.0.1. One ECH key pair is generated in-process: the server loads its PEM into an ECH key
/// store, the client offers the matching ECHConfigList. Both are supplied whole through the
/// adapter's ServerConfig/ClientConfig escape hatch. Each side then asserts EchStatus = Accepted -
/// the client hid its real SNI and the server recovered it - proving the ECH path through the
/// fcl-net adapter end to end.
/// </summary>
unit FclNetEchLoopbackExample;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

interface

type
  TFclNetEchLoopbackExample = class sealed(TObject)
  public
    /// <summary>Runs the ECH loopback; returns 0 on success, 1 on failure.</summary>
    class function Run: Integer; static;
  end;

implementation

uses
  SysUtils,
  Classes,
  SyncObjs,
  ssockets,
  TlpDataEncoding,
  TlpCryptoDomainTypes,
  TlpICryptoProvider,
  TlpDefaultCryptoProvider,
  TlpITlsConfig,
  TlpITlsConfigBuilder,
  TlpTlsPresets,
  TlpIEch,
  TlpInMemoryEchKeyStore,
  TlpEchConfig,
  TlpEchKeyGen,
  TlsLibFclNetTls;

const
  PORT = 28456;
  PING = 'ping from the fclnet ech client';
  PUBLIC_NAME = 'cover.example';
  INNER_HOST = 'localhost';

var
  GVector: string;
  GServerError: string;
  GServerEch: TEchStatus;

type
  TVec = class sealed(TObject)
  strict private
    class function SearchFrom(const AStart: string): string; static;
  public
    class procedure Locate; static;
    class function Bytes(const AName: string): TBytes; static;
  end;

  // the loopback server: hands each accepted connection an ECH-configured handler (whose Accept
  // runs our server handshake), captures it to read the server-side ECH outcome, then echoes
  TServerThread = class(TThread)
  strict private
  var
    FServerConfig: ITlsServerConfig;
    FHandler: TTlsLibSocketHandler;
    FReady: TEvent;
    procedure MakeHandler(Sender: TObject; out AHandler: TSocketHandler);
    procedure HandleConnect(Sender: TObject; AStream: TSocketStream);
  protected
    procedure Execute; override;
  public
    constructor Create(const AServerConfig: ITlsServerConfig; AReady: TEvent);
  end;

class function TVec.SearchFrom(const AStart: string): string;
const
  REL = 'TlsLib.Tests' + PathDelim + 'Data' + PathDelim + 'Certs' + PathDelim +
    'EcP256Chain.txt';
var
  LDir, LTry: string;
  LI: Integer;
begin
  Result := '';
  LDir := AStart;
  for LI := 0 to 8 do
  begin
    LTry := IncludeTrailingPathDelimiter(LDir) + REL;
    if FileExists(LTry) then
      Exit(LTry);
    LDir := ExtractFileDir(ExcludeTrailingPathDelimiter(LDir));
    if LDir = '' then
      Break;
  end;
end;

class procedure TVec.Locate;
begin
  GVector := SearchFrom(ExtractFilePath(ParamStr(0)));
  if GVector = '' then
    GVector := SearchFrom(GetCurrentDir);
  if GVector = '' then
    raise Exception.Create('EcP256Chain.txt vector not found (searched up from the exe and cwd)');
end;

class function TVec.Bytes(const AName: string): TBytes;
var
  LLines: TStringList;
  LI: Integer;
  LPrefix: string;
begin
  Result := nil;
  LPrefix := AName + '=';
  LLines := TStringList.Create;
  try
    LLines.LoadFromFile(GVector);
    for LI := 0 to LLines.Count - 1 do
      if Pos(LPrefix, LLines[LI]) = 1 then
        Exit(TDataEncoding.HexDecode(
          Copy(LLines[LI], System.Length(LPrefix) + 1, MaxInt)));
  finally
    LLines.Free;
  end;
end;

{ TServerThread }

constructor TServerThread.Create(const AServerConfig: ITlsServerConfig;
  AReady: TEvent);
begin
  inherited Create(True);
  FreeOnTerminate := False;
  FServerConfig := AServerConfig;
  FReady := AReady;
end;

procedure TServerThread.MakeHandler(Sender: TObject; out AHandler: TSocketHandler);
begin
  // supply the whole ECH server config; its credential and key store ride on it
  FHandler := TTlsLibSocketHandler.Create;
  FHandler.ServerConfig := FServerConfig;
  AHandler := FHandler;
end;

procedure TServerThread.HandleConnect(Sender: TObject; AStream: TSocketStream);
var
  LBuf: TBytes;
  LN: Integer;
begin
  try
    // the handshake already ran during accept; the captured handler carries the outcome
    GServerEch := FHandler.EchStatus;
    SetLength(LBuf, 1024);
    LN := AStream.Read(LBuf[0], System.Length(LBuf));
    if LN > 0 then
      AStream.Write(LBuf[0], LN);
  except
    on E: Exception do
      GServerError := 'server connection: ' + E.ClassName + ': ' + E.Message;
  end;
  AStream.Free;
end;

procedure TServerThread.Execute;
var
  LServer: TInetServer;
begin
  LServer := TInetServer.Create('127.0.0.1', PORT);
  try
    try
      LServer.ReuseAddress := True;
      LServer.MaxConnections := 1;
      LServer.OnCreateClientSocketHandler := MakeHandler;
      LServer.OnConnect := HandleConnect;
      LServer.Listen;
      FReady.SetEvent;
      LServer.StartAccepting;
    except
      on E: Exception do
      begin
        GServerError := 'server: ' + E.ClassName + ': ' + E.Message;
        FReady.SetEvent;
      end;
    end;
  finally
    LServer.Free;
  end;
end;

{ TFclNetEchLoopbackExample }

class function TFclNetEchLoopbackExample.Run: Integer;
var
  LProvider: ICryptoProvider;
  LEch: TEchKeyGenResult;
  LServerBuilder: ITlsServerConfigBuilder;
  LClientBuilder: ITlsClientConfigBuilder;
  LServerConfig: ITlsServerConfig;
  LClientConfig: ITlsClientConfig;
  LServer: TServerThread;
  LSock: TInetSocket;
  LHandler: TTlsLibSocketHandler;
  LReady: TEvent;
  LEcho: string;
  LClientEch: TEchStatus;
  LOut: AnsiString;
  LBuf: TBytes;
  LN: Integer;
begin
  Result := 1;
  LEcho := '';
  GServerError := '';
  GServerEch := TEchStatus.NotOffered;
  TVec.Locate;
  LProvider := TDefaultCryptoProvider.Create as ICryptoProvider;

  LEch := TEchKeyGenerator.Generate(LProvider, PUBLIC_NAME, 1,
    THpkeKem.DHKEM_X25519_HKDF_SHA256, THpkeKdf.HKDF_SHA256,
    THpkeAead.AES_128_GCM, 0);

  LServerBuilder := TTlsPresets.Compatible(LProvider).Server
    .WithCredential(TVec.Bytes('leaf_cert'), TVec.Bytes('leaf_key'), '');
  LServerBuilder.Tls13.WithEchKeyStore(
    TInMemoryEchKeyStore.FromPem(LEch.Pem, LProvider));
  LServerBuilder.Tls13.WithEchTrialDecrypt(True);
  LServerConfig := LServerBuilder.Build;

  LClientBuilder := TTlsPresets.Compatible(LProvider).Client
    .WithTrustAnchors(TVec.Bytes('root_cert'));
  LClientBuilder.Tls13.WithEncryptedClientHello(LEch.EchConfigList);
  LClientConfig := LClientBuilder.Build;

  LReady := TEvent.Create(nil, True, False, '');
  try
    LServer := TServerThread.Create(LServerConfig, LReady);
    try
      LServer.Start;
      LReady.WaitFor(5000);
      if GServerError <> '' then
        raise Exception.Create(GServerError);

      LHandler := TTlsLibSocketHandler.Create;
      LHandler.ClientConfig := LClientConfig; // config-in: trust + ECH ride on it
      LSock := TInetSocket.Create(INNER_HOST, PORT, LHandler);
      try
        try
          LSock.Connect;
        except
          on E: ESocketError do
            raise Exception.Create('handshake failed: ' + LHandler.LastErrorDesc);
        end;
        LClientEch := LHandler.EchStatus; // read before LSock.Free drops the handler
        LOut := AnsiString(PING);
        LSock.Write(LOut[1], System.Length(LOut));
        SetLength(LBuf, 1024);
        LN := LSock.Read(LBuf[0], System.Length(LBuf));
        if LN > 0 then
          SetString(LEcho, PAnsiChar(@LBuf[0]), LN);
      finally
        LSock.Free;
      end;

      LServer.WaitFor;
      if GServerError <> '' then
        raise Exception.Create(GServerError);
    finally
      LServer.Free;
    end;

    if (LEcho = PING) and (LClientEch = TEchStatus.Accepted) and
      (GServerEch = TEchStatus.Accepted) then
    begin
      WriteLn('FclNet ECH loopback PASS: handshake + echo, ECH accepted on both sides');
      Result := 0;
    end
    else
      WriteLn('FclNet ECH loopback FAIL: echo="', LEcho, '" clientEch=',
        Ord(LClientEch), ' serverEch=', Ord(GServerEch));
  except
    on E: Exception do
      WriteLn('FclNet ECH loopback FAIL: ', E.ClassName, ': ', E.Message);
  end;
  LReady.Free;
end;

end.
