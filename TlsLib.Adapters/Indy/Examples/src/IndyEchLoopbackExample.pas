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
/// An Encrypted Client Hello (RFC 9849) loopback over Indy's IOHandler seam on 127.0.0.1.
/// One ECH key pair is generated in-process: the server loads its PEM into an ECH key store,
/// the client offers the matching ECHConfigList. Both sides then assert EchStatus = Accepted -
/// the client hid its real SNI in the encrypted inner ClientHello and the server recovered it -
/// proving the ECH path end to end through the Indy adapter. The configs are supplied whole via
/// the adapter's ClientConfig/ServerConfig escape hatch. Shared by the FreePascal and Delphi
/// example programs.
/// </summary>
unit IndyEchLoopbackExample;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

interface

type
  TIndyEchLoopbackExample = class sealed(TObject)
  public
    /// <summary>Runs the ECH loopback; returns 0 on success, 1 on failure.</summary>
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
  TlsLibIndyTls;

const
  PORT = 28454;
  PUBLIC_NAME = 'cover.example';
  INNER_HOST = 'localhost'; // the leaf's SAN; the real (inner) SNI the client hides

var
  GServerError: string;
  GServerEch: TEchStatus;
  GVector: string;

type
  // finds and reads the shared EcP256 test credential the loopback presents
  TVec = class sealed(TObject)
  strict private
    class function SearchFrom(const AStart: string): string; static;
  public
    class function Find: string; static;
    class function Bytes(const AName: string): TBytes; static;
  end;

  TEchoHandler = class sealed(TObject)
  public
    procedure DoExecute(AContext: TIdContext);
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

class function TVec.Find: string;
begin
  Result := SearchFrom(ExtractFilePath(ParamStr(0)));
  if Result = '' then
    Result := SearchFrom(GetCurrentDir);
  if Result = '' then
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

procedure TEchoHandler.DoExecute(AContext: TIdContext);
var
  LLine: string;
begin
  try
    // the first read drives the deferred handshake; capture the server-side ECH outcome before
    // echoing, so the client (which waits on the echo) can never observe it unset
    LLine := AContext.Connection.IOHandler.ReadLn;
    GServerEch := (AContext.Connection.IOHandler as TTlsLibIOHandlerSocket).EchStatus;
    AContext.Connection.IOHandler.WriteLn(LLine);
  except
    on E: Exception do
      GServerError := E.ClassName + ': ' + E.Message;
  end;
end;

class function TIndyEchLoopbackExample.Run: Integer;
var
  LProvider: ICryptoProvider;
  LEch: TEchKeyGenResult;
  LServerBuilder: ITlsServerConfigBuilder;
  LClientBuilder: ITlsClientConfigBuilder;
  LServerConfig: ITlsServerConfig;
  LClientConfig: ITlsClientConfig;
  LServer: TIdTCPServer;
  LServerIO: TTlsLibServerIOHandler;
  LClient: TIdTCPClient;
  LClientIO: TTlsLibIOHandlerSocket;
  LEcho: string;
  LEchoHandler: TEchoHandler;
  LClientEch: TEchStatus;
  LOk: Boolean;
begin
  Result := 1;
  GServerError := '';
  GServerEch := TEchStatus.NotOffered;
  GVector := TVec.Find;
  LProvider := TDefaultCryptoProvider.Create as ICryptoProvider;

  // one ECH key pair drives both sides: the PEM the server store loads (private key + config)
  // and the ECHConfigList the client offers (DHKEM-X25519 / HKDF-SHA256 / AES-128-GCM)
  LEch := TEchKeyGenerator.Generate(LProvider, PUBLIC_NAME, 1,
    THpkeKem.DHKEM_X25519_HKDF_SHA256, THpkeKdf.HKDF_SHA256,
    THpkeAead.AES_128_GCM, 0);

  // server config: the localhost leaf credential plus the ECH key store, trial decryption on so
  // the server matches a client that hid the config id
  LServerBuilder := TTlsPresets.Compatible(LProvider).Server
    .WithCredential(TVec.Bytes('leaf_cert'), TVec.Bytes('leaf_key'), '');
  LServerBuilder.Tls13.WithEchKeyStore(
    TInMemoryEchKeyStore.FromPem(LEch.Pem, LProvider));
  LServerBuilder.Tls13.WithEchTrialDecrypt(True);
  LServerConfig := LServerBuilder.Build;

  // client config: trust the test root, verify the inner name, and offer ECH with the config list
  LClientBuilder := TTlsPresets.Compatible(LProvider).Client
    .WithTrustAnchors(TVec.Bytes('root_cert'));
  LClientBuilder.WithNameCheck(True);
  LClientBuilder.Tls13.WithEncryptedClientHello(LEch.EchConfigList);
  LClientConfig := LClientBuilder.Build;

  LEchoHandler := TEchoHandler.Create;
  LServer := TIdTCPServer.Create(nil);
  LClient := TIdTCPClient.Create(nil);
  try
    LServerIO := TTlsLibServerIOHandler.Create(LServer);
    // supply the whole ECH server config; the cert/key ride on it, not on the file options
    LServerIO.SSLOptions.ServerConfig := LServerConfig;
    LServer.IOHandler := LServerIO;
    LServer.DefaultPort := PORT;
    LServer.OnExecute := LEchoHandler.DoExecute;
    LServer.Active := True;

    LClientIO := TTlsLibIOHandlerSocket.Create(LClient);
    LClientIO.SSLOptions.ClientConfig := LClientConfig;
    LClient.IOHandler := LClientIO;
    LClient.Host := INNER_HOST; // the inner SNI, verified against the leaf's localhost SAN
    LClient.Port := PORT;
    LClient.Connect;
    try
      LClientIO.WriteLn('ping from the ech indy client');
      LEcho := LClientIO.ReadLn;
      LClientEch := LClientIO.EchStatus;
    finally
      LClient.Disconnect;
    end;

    LServer.Active := False;

    LOk := (LEcho = 'ping from the ech indy client') and
      (LClientEch = TEchStatus.Accepted) and (GServerEch = TEchStatus.Accepted);
    if LOk then
    begin
      Writeln('Indy ECH loopback PASS: handshake + echo, ECH accepted on both sides');
      Result := 0;
    end
    else
      Writeln('Indy ECH loopback FAIL: echo="', LEcho, '" clientEch=',
        Ord(LClientEch), ' serverEch=', Ord(GServerEch), ' server="',
        GServerError, '"');
  except
    on E: Exception do
      Writeln('Indy ECH loopback FAIL: ', E.ClassName, ': ', E.Message,
        ' server="', GServerError, '"');
  end;
  LClient.Free;
  LServer.Free;
  LEchoHandler.Free;
end;

end.
