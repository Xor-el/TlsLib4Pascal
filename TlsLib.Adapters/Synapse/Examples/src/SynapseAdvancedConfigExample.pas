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
/// Advanced configuration over the Synapse plugin: instead of the TCustomSSL cert/CA
/// properties, the app hands each socket a fully-built TlsLib config through the
/// (Sock.SSL as TSSLTlsLib).ClientConfig / ServerConfig escape hatch. The injected configs
/// pin an ordered, bound cipher-suite preference and TLS 1.2 only - so this loopback
/// negotiating TLS 1.2 (the Compatible preset would pick 1.3) proves the app's config replaced
/// the plugin's built-in build. The same seam exposes the whole builder API (groups,
/// resumption, ALPN, ...).
/// </summary>
unit SynapseAdvancedConfigExample;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

interface

type
  TSynapseAdvancedConfigExample = class sealed(TObject)
  public
    /// <summary>Runs the loopback; returns 0 on success, 1 on failure.</summary>
    class function Run: Integer; static;
  end;

implementation

uses
  SysUtils,
  Classes,
  SyncObjs,
  blcksock,
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
  TlpSynapseTls;

const
  PORT = '28450';
  CRLF = #13#10;
  PING = 'ping from the synapse advanced-config client';

var
  GReady: TEvent;
  GServerError: string;
  GVector: string;
  GLeafDer, GKeyDer, GRootDer: TBytes;

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
  protected
    procedure Execute; override;
  end;

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
          (LClient.SSL as TSSLTlsLib).ServerConfig := BuildServerConfig; // the escape hatch
          if not LClient.SSLAcceptConnection then
            raise Exception.Create('ssl accept failed: ' + LClient.SSL.LastErrorDesc);
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

class function TSynapseAdvancedConfigExample.Run: Integer;
var
  LServer: TServerThread;
  LClient: TTCPBlockSocket;
  LEcho, LVersion: string;
begin
  Result := 1;
  GServerError := '';
  GVector := LocateVector;
  GLeafDer := FieldDer('leaf_cert');
  GKeyDer := FieldDer('leaf_key');
  GRootDer := FieldDer('root_cert');
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
      (LClient.SSL as TSSLTlsLib).ClientConfig := BuildClientConfig; // the escape hatch
      LClient.SSL.SNIHost := 'localhost'; // verify the leaf for its 'localhost' SAN
      LClient.Connect('127.0.0.1', PORT);
      if LClient.LastError <> 0 then
        raise Exception.Create('tcp connect failed');
      LClient.SSLDoConnect;
      if not LClient.SSL.SSLEnabled then
        raise Exception.Create('ssl connect failed: ' + LClient.SSL.LastErrorDesc);
      LVersion := LClient.SSL.GetSSLVersion;
      LClient.SendString(PING + CRLF);
      LEcho := LClient.RecvString(5000);
    finally
      LClient.Free;
    end;

    LServer.WaitFor;
    if GServerError <> '' then
      raise Exception.Create('server: ' + GServerError);

    if (LEcho = PING) and (LVersion = 'TLSv1.2') then
    begin
      Writeln('Synapse advanced-config PASS: injected config pinned TLS 1.2 + ordered ciphers, echo ok');
      Result := 0;
    end
    else
      Writeln('Synapse advanced-config FAIL: echo="', LEcho, '" version="', LVersion, '"');
    LServer.Free;
  except
    on E: Exception do
      Writeln('Synapse advanced-config FAIL: ', E.ClassName, ': ', E.Message);
  end;
  GReady.Free;
end;

end.
