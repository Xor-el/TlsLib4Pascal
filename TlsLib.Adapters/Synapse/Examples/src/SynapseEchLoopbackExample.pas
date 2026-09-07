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
/// An Encrypted Client Hello (RFC 9849) loopback over Synapse's TCustomSSL seam on 127.0.0.1.
/// One ECH key pair is generated in-process: the server loads its PEM into an ECH key store, the
/// client offers the matching ECHConfigList. Both are supplied whole through the plugin's
/// ServerConfig/ClientConfig escape hatch. Each side then asserts EchStatus = Accepted - the
/// client hid its real SNI and the server recovered it - proving the ECH path through the
/// Synapse plugin end to end. Shared by the FreePascal and Delphi example programs.
/// </summary>
unit SynapseEchLoopbackExample;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

interface

type
  TSynapseEchLoopbackExample = class sealed(TObject)
  public
    /// <summary>Runs the ECH loopback; returns 0 on success, 1 on failure.</summary>
    class function Run: Integer; static;
  end;

implementation

uses
  SysUtils,
  Classes,
  SyncObjs,
  blcksock,
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
  TlsLibSynapseTls;

const
  PORT = '28455';
  CRLF = #13#10;
  PING = 'ping from the synapse ech client';
  PUBLIC_NAME = 'cover.example';
  INNER_HOST = 'localhost';

var
  GServerConfig: ITlsServerConfig;
  GReady: TEvent;
  GServerError: string;
  GServerEch: TEchStatus;
  GVector: string;

type
  TVec = class sealed(TObject)
  strict private
    class function SearchFrom(const AStart: string): string; static;
  public
    class procedure Locate; static;
    class function Bytes(const AName: string): TBytes; static;
  end;

  TServerThread = class(TThread)
  protected
    procedure Execute; override;
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

procedure TServerThread.Execute;
var
  LListener, LClient: TTCPBlockSocket;
  LLine: string;
begin
  LListener := TTCPBlockSocket.Create;
  try
    try
      LListener.CreateSocket;
      LListener.SetLinger(True, 1000);
      LListener.Bind('127.0.0.1', PORT);
      LListener.Listen;
      GReady.SetEvent;
      if LListener.CanRead(5000) then
      begin
        LClient := TTCPBlockSocket.CreateWithSSL(SSLImplementation);
        try
          LClient.Socket := LListener.Accept;
          // supply the whole ECH server config; its credential and key store ride on it
          (LClient.SSL as TSSLTlsLib).ServerConfig := GServerConfig;
          if not LClient.SSLAcceptConnection then
            raise Exception.Create('ssl accept failed: ' + LClient.SSL.LastErrorDesc);
          // capture the server-side ECH outcome before the echo the client waits on
          GServerEch := (LClient.SSL as TSSLTlsLib).EchStatus;
          LLine := LClient.RecvString(5000);
          LClient.SendString(LLine + CRLF);
        finally
          LClient.Free;
        end;
      end;
    except
      on E: Exception do
      begin
        GServerError := E.ClassName + ': ' + E.Message;
        GReady.SetEvent;
      end;
    end;
  finally
    LListener.Free;
  end;
end;

{ TSynapseEchLoopbackExample }

class function TSynapseEchLoopbackExample.Run: Integer;
var
  LProvider: ICryptoProvider;
  LEch: TEchKeyGenResult;
  LServerBuilder: ITlsServerConfigBuilder;
  LClientBuilder: ITlsClientConfigBuilder;
  LClientConfig: ITlsClientConfig;
  LServer: TServerThread;
  LClient: TTCPBlockSocket;
  LEcho: string;
  LClientEch: TEchStatus;
begin
  Result := 1;
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
  GServerConfig := LServerBuilder.Build;

  LClientBuilder := TTlsPresets.Compatible(LProvider).Client
    .WithTrustAnchors(TVec.Bytes('root_cert'));
  LClientBuilder.WithNameCheck(True);
  LClientBuilder.Tls13.WithEncryptedClientHello(LEch.EchConfigList);
  LClientConfig := LClientBuilder.Build;

  GReady := TEvent.Create(nil, True, False, '');
  try
    LServer := TServerThread.Create(True);
    LServer.FreeOnTerminate := False;
    LServer.Start;
    GReady.WaitFor(5000);
    if GServerError <> '' then
      raise Exception.Create('server: ' + GServerError);

    LClient := TTCPBlockSocket.CreateWithSSL(SSLImplementation);
    try
      (LClient.SSL as TSSLTlsLib).ClientConfig := LClientConfig;
      LClient.SSL.SNIHost := INNER_HOST; // the inner SNI, verified against the leaf's SAN
      LClient.Connect('127.0.0.1', PORT);
      if LClient.LastError <> 0 then
        raise Exception.Create('tcp connect failed');
      LClient.SSLDoConnect;
      if not LClient.SSL.SSLEnabled then
        raise Exception.Create('ssl connect failed: ' + LClient.SSL.LastErrorDesc);
      LClientEch := (LClient.SSL as TSSLTlsLib).EchStatus;
      LClient.SendString(PING + CRLF);
      LEcho := LClient.RecvString(5000);
    finally
      LClient.Free;
    end;

    LServer.WaitFor;
    if GServerError <> '' then
      raise Exception.Create('server: ' + GServerError);

    if (LEcho = PING) and (LClientEch = TEchStatus.Accepted) and
      (GServerEch = TEchStatus.Accepted) then
    begin
      Writeln('Synapse ECH loopback PASS: handshake + echo, ECH accepted on both sides');
      Result := 0;
    end
    else
      Writeln('Synapse ECH loopback FAIL: echo="', LEcho, '" clientEch=',
        Ord(LClientEch), ' serverEch=', Ord(GServerEch));
    LServer.Free;
  except
    on E: Exception do
      Writeln('Synapse ECH loopback FAIL: ', E.ClassName, ': ', E.Message);
  end;
  GReady.Free;
end;

end.
