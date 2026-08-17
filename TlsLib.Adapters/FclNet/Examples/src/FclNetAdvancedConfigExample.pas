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
/// Advanced configuration over the fcl-net adapter: instead of the handler's cert/trust
/// properties, the app hands it fully-built TlsLib configs through the ClientConfig /
/// ServerConfig escape hatch. The injected configs pin an ordered, bound cipher-suite
/// preference and TLS 1.2 only - so this loopback negotiating TLS 1.2 (the Compatible preset
/// would pick 1.3) proves the app's config replaced the adapter's built-in build. The same
/// seam exposes the whole builder API (groups, resumption, ALPN, ...).
/// </summary>
unit FclNetAdvancedConfigExample;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

interface

type
  TFclNetAdvancedConfigExample = class sealed(TObject)
  public
    /// <summary>Runs the loopback; returns 0 on success, 1 on failure.</summary>
    class function Run: Integer; static;
  end;

implementation

uses
  SysUtils,
  Classes,
  SyncObjs,
  ssockets,
  TlpDataEncoding,
  TlpTlsVersion,
  TlpNegotiationTypes,
  TlpINegotiation,
  TlpCipherSuiteRegistry,
  TlpICryptoProvider,
  TlpDefaultCryptoProvider,
  TlpITlsConfig,
  TlpITlsConfigBuilder,
  TlpTlsPresets,
  TlpFclNetTls;

const
  PORT = 28447;
  PING = 'ping from the fclnet advanced-config client';

var
  GLeafDer, GKeyDer, GRootDer: TBytes;
  GVector: string;

function LocateVector: string;
const
  REL = 'TlsLib.Tests' + PathDelim + 'Data' + PathDelim + 'Certs' + PathDelim +
    'EcP256Chain.txt';
var
  LDir, LTry: string;
  LI: Integer;
begin
  Result := '';
  LDir := ExtractFilePath(ParamStr(0));
  for LI := 0 to 8 do
  begin
    LTry := IncludeTrailingPathDelimiter(LDir) + REL;
    if FileExists(LTry) then
      Exit(LTry);
    LDir := ExtractFileDir(ExcludeTrailingPathDelimiter(LDir));
    if LDir = '' then
      Break;
  end;
  if Result = '' then
    raise Exception.Create('EcP256Chain.txt vector not found (searched up from the exe)');
end;

function FieldDer(const AName: string): TBytes;
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
        Exit(TDataEncoding.HexDecode(Copy(LLines[LI], System.Length(LPrefix) + 1, MaxInt)));
  finally
    LLines.Free;
  end;
end;

// an ordered, bound TLS 1.2 cipher-suite preference: only these suites may be negotiated and the
// Add order is the preference order (server-preference is the model, so the server's order wins)
function OrderedSuites(const AProvider: ICryptoProvider): ICipherSuiteRegistry;
var
  LAll, LOrdered: ICipherSuiteRegistry;
  LSuite: TTlsCipherSuite;
begin
  LAll := TCipherSuiteRegistry.CreateDualVersion(AProvider);
  LOrdered := TCipherSuiteRegistry.Create;
  if LAll.TryGet(TCipherSuites12.EcdheEcdsaAes256GcmSha384, LSuite) then LOrdered.Add(LSuite);
  if LAll.TryGet(TCipherSuites12.EcdheEcdsaChaCha20Poly1305Sha256, LSuite) then LOrdered.Add(LSuite);
  if LAll.TryGet(TCipherSuites12.EcdheEcdsaAes128GcmSha256, LSuite) then LOrdered.Add(LSuite);
  Result := LOrdered;
end;

function BuildClientConfig: ITlsClientConfig;
var
  LProvider: ICryptoProvider;
  LClient: ITlsClientConfigBuilder;
begin
  LProvider := TDefaultCryptoProvider.Create as ICryptoProvider;
  LClient := TTlsPresets.Compatible(LProvider).Client;
  LClient.WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls12));
  // X25519 for the ECDHE, plus the leaf's P-256 curve (RFC 8422 5.4)
  LClient.WithPreferredGroups(TArray<UInt16>.Create(TNamedGroupCatalog.X25519,
    TNamedGroupCatalog.Secp256r1));
  LClient.WithCipherSuites(OrderedSuites(LProvider));
  LClient.WithTrustAnchors(GRootDer);
  Result := LClient.Build;
end;

function BuildServerConfig: ITlsServerConfig;
var
  LProvider: ICryptoProvider;
  LServer: ITlsServerConfigBuilder;
begin
  LProvider := TDefaultCryptoProvider.Create as ICryptoProvider;
  LServer := TTlsPresets.Compatible(LProvider).Server;
  LServer.WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls12));
  LServer.WithPreferredGroups(TArray<UInt16>.Create(TNamedGroupCatalog.X25519,
    TNamedGroupCatalog.Secp256r1));
  LServer.WithCipherSuites(OrderedSuites(LProvider));
  LServer.WithCredential(GLeafDer, GKeyDer);
  Result := LServer.Build;
end;

type
  TServerThread = class(TThread)
  strict private
    FError: string;
    FReady: TEvent;
    procedure MakeHandler(Sender: TObject; out AHandler: TSocketHandler);
    procedure HandleConnect(Sender: TObject; AStream: TSocketStream);
  protected
    procedure Execute; override;
  public
    constructor Create(AReady: TEvent);
    property Error: string read FError;
  end;

constructor TServerThread.Create(AReady: TEvent);
begin
  inherited Create(True);
  FreeOnTerminate := False;
  FReady := AReady;
end;

procedure TServerThread.MakeHandler(Sender: TObject; out AHandler: TSocketHandler);
var
  LHandler: TTlsLibSocketHandler;
begin
  LHandler := TTlsLibSocketHandler.Create;
  LHandler.ServerConfig := BuildServerConfig; // the escape hatch: use our config verbatim
  AHandler := LHandler;
end;

procedure TServerThread.HandleConnect(Sender: TObject; AStream: TSocketStream);
var
  LBuf: TBytes;
  LN: Integer;
begin
  try
    LBuf := nil;
    SetLength(LBuf, 1024);
    LN := AStream.Read(LBuf[0], System.Length(LBuf));
    if LN > 0 then
      AStream.Write(LBuf[0], LN);
  except
    on E: Exception do
      FError := 'server connection: ' + E.Message;
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
        FError := 'server: ' + E.Message;
        FReady.SetEvent;
      end;
    end;
  finally
    LServer.Free;
  end;
end;

class function TFclNetAdvancedConfigExample.Run: Integer;
var
  LServer: TServerThread;
  LSock: TInetSocket;
  LHandler: TTlsLibSocketHandler;
  LReady: TEvent;
  LEcho: string;
  LOut: AnsiString;
  LBuf: TBytes;
  LN: Integer;
  LVersion: TTlsVersion;
begin
  Result := 1;
  LEcho := '';
  GVector := LocateVector;
  GLeafDer := FieldDer('leaf_cert');
  GKeyDer := FieldDer('leaf_key');
  GRootDer := FieldDer('root_cert');
  LReady := TEvent.Create(nil, True, False, '');
  try
    LServer := TServerThread.Create(LReady);
    try
      LServer.Start;
      LReady.WaitFor(5000);
      if LServer.Error <> '' then
        raise Exception.Create(LServer.Error);

      LHandler := TTlsLibSocketHandler.Create;
      LHandler.ClientConfig := BuildClientConfig; // the escape hatch: use our config verbatim
      LSock := TInetSocket.Create('localhost', PORT, LHandler);
      try
        try
          LSock.Connect;
        except
          on E: ESocketError do
            raise Exception.Create('handshake failed: ' + LHandler.LastErrorDesc);
        end;
        LVersion := LHandler.NegotiatedVersion;
        LOut := AnsiString(PING);
        LSock.Write(LOut[1], System.Length(LOut));
        LBuf := nil;
        SetLength(LBuf, 1024);
        LN := LSock.Read(LBuf[0], System.Length(LBuf));
        if LN > 0 then
          SetString(LEcho, PAnsiChar(@LBuf[0]), LN);
      finally
        LSock.Free;
      end;
      LServer.WaitFor;
      if LServer.Error <> '' then
        raise Exception.Create(LServer.Error);
    finally
      LServer.Free;
    end;

    if (LEcho = PING) and (LVersion.WireValue = TlsWireVersionTls12) then
    begin
      Writeln('FclNet advanced-config PASS: injected config pinned TLS 1.2 + ordered ciphers, echo ok');
      Result := 0;
    end
    else
      Writeln('FclNet advanced-config FAIL: echo="', LEcho, '" version=$',
        IntToHex(LVersion.WireValue, 4));
  except
    on E: Exception do
      Writeln('FclNet advanced-config FAIL: ', E.ClassName, ': ', E.Message);
  end;
  LReady.Free;
end;

end.
