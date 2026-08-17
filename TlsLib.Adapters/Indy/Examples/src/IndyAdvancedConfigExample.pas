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
/// Advanced configuration over the Indy adapter, demonstrating cipher-suite preference. The app
/// hands the IOHandlers fully-built configs through SSLOptions.ServerConfig / ClientConfig, and
/// controls WHICH suite is negotiated via the server's WithCipherSuitePreference: ServerOrder
/// (the default) imposes the server's order, ClientOrder honors the client's. The client offers
/// AES-256 then AES-128 (or the reverse), and the example reads back the negotiated suite through
/// the adapter's NegotiatedCipherSuite accessor. It asserts:
///   - ClientOrder: the client's most-preferred offered suite always wins (flipping the client's
///     order flips the negotiated suite);
///   - ServerOrder: the negotiated suite is stable regardless of the client's order (the server's
///     preference decides).
/// This proves - through the real adapter - that only the server guides selection, and that the
/// server can defer to the client's order when it chooses to.
/// </summary>
unit IndyAdvancedConfigExample;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

interface

type
  TIndyAdvancedConfigExample = class sealed(TObject)
  public
    /// <summary>Runs the demonstration; returns 0 on success, 1 on failure.</summary>
    class function Run: Integer; static;
  end;

implementation

uses
  SysUtils,
  Classes,
  IdContext,
  IdTCPServer,
  IdTCPClient,
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
  TlpIndyTls;

const
  PORTBASE = 28452;
  PING = 'ping';

var
  GServerError: string;
  GVector: string;
  GLeafDer, GKeyDer, GRootDer: TBytes;
  GProvider: ICryptoProvider;

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

// a registry holding exactly ACodes, in that order; the client offers suites in registry order,
// so this controls the client's advertised preference
function OrderedRegistry(const ACodes: array of UInt16): ICipherSuiteRegistry;
var
  LAll, LReg: ICipherSuiteRegistry;
  LSuite: TTlsCipherSuite;
  LI: Integer;
begin
  LAll := TCipherSuiteRegistry.CreateDualVersion(GProvider);
  LReg := TCipherSuiteRegistry.Create;
  for LI := System.Low(ACodes) to System.High(ACodes) do
    if LAll.TryGet(ACodes[LI], LSuite) then
      LReg.Add(LSuite);
  Result := LReg;
end;

function BuildServerConfig(APreference: TServerCipherPreference): ITlsServerConfig;
var
  LServer: ITlsServerConfigBuilder;
begin
  LServer := TTlsPresets.Compatible(GProvider).Server;
  LServer.WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls13));
  LServer.WithPreferredGroups(TArray<UInt16>.Create(TNamedGroupCatalog.X25519));
  // the server offers both AES suites; its selection strategy is the knob under test
  LServer.WithCipherSuites(OrderedRegistry([TCipherSuites13.Aes128GcmSha256,
    TCipherSuites13.Aes256GcmSha384]));
  LServer.WithCipherSuitePreference(APreference);
  LServer.WithCredential(GLeafDer, GKeyDer);
  Result := LServer.Build;
end;

function BuildClientConfig(const AClientOrder: array of UInt16): ITlsClientConfig;
var
  LClient: ITlsClientConfigBuilder;
begin
  LClient := TTlsPresets.Compatible(GProvider).Client;
  LClient.WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls13));
  LClient.WithPreferredGroups(TArray<UInt16>.Create(TNamedGroupCatalog.X25519));
  LClient.WithCipherSuites(OrderedRegistry(AClientOrder)); // the client's advertised order
  LClient.WithTrustAnchors(GRootDer);
  Result := LClient.Build;
end;

type
  TEchoHandler = class sealed(TObject)
  public
    procedure DoExecute(AContext: TIdContext);
  end;

procedure TEchoHandler.DoExecute(AContext: TIdContext);
var
  LLine: string;
begin
  try
    LLine := AContext.Connection.IOHandler.ReadLn;
    AContext.Connection.IOHandler.WriteLn(LLine);
  except
    on E: Exception do
      GServerError := E.ClassName + ': ' + E.Message;
  end;
end;

// one full Indy handshake with the given server preference and client-offered order; returns the
// negotiated cipher-suite codepoint the client observed through the adapter accessor
function Negotiate(APreference: TServerCipherPreference;
  const AClientOrder: array of UInt16; APort: Integer): UInt16;
var
  LServer: TIdTCPServer;
  LServerIO: TTlsLibServerIOHandler;
  LClient: TIdTCPClient;
  LClientIO: TTlsLibIOHandlerSocket;
  LEchoHandler: TEchoHandler;
begin
  Result := 0;
  LEchoHandler := TEchoHandler.Create;
  LServer := TIdTCPServer.Create(nil);
  LClient := TIdTCPClient.Create(nil);
  try
    LServerIO := TTlsLibServerIOHandler.Create(LServer);
    LServerIO.SSLOptions.ServerConfig := BuildServerConfig(APreference);
    LServer.IOHandler := LServerIO;
    LServer.DefaultPort := APort;
    LServer.OnExecute := LEchoHandler.DoExecute;
    LServer.Active := True;

    LClientIO := TTlsLibIOHandlerSocket.Create(LClient);
    LClientIO.SSLOptions.ClientConfig := BuildClientConfig(AClientOrder);
    LClient.IOHandler := LClientIO;
    LClient.Host := 'localhost'; // verify the leaf for its 'localhost' SAN
    LClient.Port := APort;
    LClient.Connect;
    try
      LClientIO.WriteLn(PING);
      LClientIO.ReadLn;
      Result := LClientIO.NegotiatedCipherSuite; // the adapter's read-only accessor
    finally
      LClient.Disconnect;
    end;
    LServer.Active := False;
  finally
    LClient.Free;
    LServer.Free;
    LEchoHandler.Free;
  end;
end;

class function TIndyAdvancedConfigExample.Run: Integer;
var
  LClientPref256, LClientPref128, LServerA, LServerB: UInt16;
  LOk: Boolean;
begin
  Result := 1;
  GServerError := '';
  GVector := LocateVector;
  GLeafDer := FieldDer('leaf_cert');
  GKeyDer := FieldDer('leaf_key');
  GRootDer := FieldDer('root_cert');
  GProvider := TDefaultCryptoProvider.Create as ICryptoProvider;
  try
    // ClientOrder: the server honors the client's advertised order, so the client's first suite wins
    LClientPref256 := Negotiate(TServerCipherPreference.ClientOrder,
      [TCipherSuites13.Aes256GcmSha384, TCipherSuites13.Aes128GcmSha256], PORTBASE);
    LClientPref128 := Negotiate(TServerCipherPreference.ClientOrder,
      [TCipherSuites13.Aes128GcmSha256, TCipherSuites13.Aes256GcmSha384], PORTBASE + 1);
    // ServerOrder (default): the server's own preference decides, independent of the client's order
    LServerA := Negotiate(TServerCipherPreference.ServerOrder,
      [TCipherSuites13.Aes256GcmSha384, TCipherSuites13.Aes128GcmSha256], PORTBASE + 2);
    LServerB := Negotiate(TServerCipherPreference.ServerOrder,
      [TCipherSuites13.Aes128GcmSha256, TCipherSuites13.Aes256GcmSha384], PORTBASE + 3);

    // the negotiated suites are the signal: correct, non-zero values prove each handshake
    // completed (a post-exchange truncation on the client's abrupt disconnect is benign, as in
    // the loopback example, so GServerError is diagnostic only - not a pass/fail gate)
    LOk := (LClientPref256 = TCipherSuites13.Aes256GcmSha384) and
      (LClientPref128 = TCipherSuites13.Aes128GcmSha256) and (LServerA = LServerB) and
      (LServerA <> 0);
    if LOk then
    begin
      Writeln('Indy advanced-config PASS: ClientOrder honors the client (',
        IntToHex(LClientPref256, 4), ' then ', IntToHex(LClientPref128, 4),
        '); ServerOrder is stable regardless of client order (', IntToHex(LServerA, 4), ')');
      Result := 0;
    end
    else
      Writeln('Indy advanced-config FAIL: clientPref=', IntToHex(LClientPref256, 4), '/',
        IntToHex(LClientPref128, 4), ' serverStable=', IntToHex(LServerA, 4), '/',
        IntToHex(LServerB, 4), ' server="', GServerError, '"');
  except
    on E: Exception do
      Writeln('Indy advanced-config FAIL: ', E.ClassName, ': ', E.Message,
        ' server="', GServerError, '"');
  end;
end;

end.
