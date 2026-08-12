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
/// Advanced configuration over the mORMot adapter: instead of the TNetTlsContext cert/trust
/// fields, the app installs fully-built TlsLib configs process-wide through
/// SetTlsLibMormotClientConfig / SetTlsLibMormotServerConfig (mORMot builds an INetTls per
/// connection via a global factory, so its neutral hooks are unit-level setters). The injected
/// configs pin an ordered, bound cipher-suite preference and TLS 1.2 only - so this loopback
/// negotiating TLS 1.2 (the Compatible preset would pick 1.3) proves the app's config replaced
/// the adapter's built-in build. The same seam exposes the whole builder API (groups,
/// resumption, ALPN, ...).
/// </summary>
unit MormotAdvancedConfigExample;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

interface

type
  TMormotAdvancedConfigExample = class sealed(TObject)
  public
    /// <summary>Runs the loopback; returns 0 on success, 1 on failure.</summary>
    class function Run: Integer; static;
  end;

implementation

uses
  SysUtils,
  Classes,
  SyncObjs,
  mormot.core.base,
  mormot.core.unicode,
  mormot.net.sock,
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
  TlsLibMormotTls;

const
  PORT = '28449';
  HOST = '127.0.0.1';
  PINGHEX = '70696e672066726f6d20746865206d6f724d6f742061632063';

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
  LListener, LClient: TNetSocket;
  LAddr: TNetAddr;
  LCtx: TNetTlsContext;
  LTls: INetTls;
  LLastErr, LCipher: RawUtf8;
  LBuf: TBytes;
  LLen: Integer;
begin
  try
    FillCharFast(LCtx, SizeOf(LCtx), 0); // the config is installed process-wide, so the context is empty
    if NewSocket(HOST, PORT, nlTcp, {dobind=}True, 3000, 3000, 3000, 0,
      LListener) <> nrOK then
      raise Exception.Create('server bind failed');
    GReady.SetEvent;
    if LListener.Accept(LClient, LAddr, {async=}False) <> nrOK then
      raise Exception.Create('accept failed');
    LTls := NewTlsLib4PascalTls;
    LTls.AfterAccept(LClient, LCtx, @LLastErr, @LCipher);
    LBuf := nil;
    SetLength(LBuf, 4096);
    LLen := System.Length(LBuf);
    if LTls.Receive(@LBuf[0], LLen) = nrOK then
      LTls.Send(@LBuf[0], LLen);
  except
    on E: Exception do
    begin
      GServerError := E.ClassName + ': ' + E.Message;
      GReady.SetEvent;
    end;
  end;
end;

class function TMormotAdvancedConfigExample.Run: Integer;
var
  LServer: TServerThread;
  LCtx: TNetTlsContext;
  LSock: TNetSocket;
  LTls: INetTls;
  LPing, LEcho: TBytes;
  LLen: Integer;
  LOk: Boolean;
begin
  Result := 1;
  GServerError := '';
  GVector := LocateVector;
  GLeafDer := FieldDer('leaf_cert');
  GKeyDer := FieldDer('leaf_key');
  GRootDer := FieldDer('root_cert');
  GReady := TEvent.Create(nil, True, False, '');
  try
    // install the fully-built configs process-wide; every handshake now uses them verbatim
    SetTlsLibMormotServerConfig(BuildServerConfig);
    SetTlsLibMormotClientConfig(BuildClientConfig);
    try
      LServer := TServerThread.Create(True);
      LServer.FreeOnTerminate := False;
      LServer.Start;
      GReady.WaitFor(5000);
      if GServerError <> '' then
        raise Exception.Create('server: ' + GServerError);

      FillCharFast(LCtx, SizeOf(LCtx), 0);
      if NewSocket(HOST, PORT, nlTcp, {dobind=}False, 3000, 3000, 3000, 0, LSock) <> nrOK then
        raise Exception.Create('client connect failed');
      LTls := NewTlsLib4PascalTls;
      // connect to 127.0.0.1 but verify the certificate for 'localhost' (its SAN)
      LTls.AfterConnection(LSock, LCtx, 'localhost');

      LPing := TDataEncoding.HexDecode(PINGHEX);
      LLen := System.Length(LPing);
      LTls.Send(@LPing[0], LLen);
      LEcho := nil;
      SetLength(LEcho, 4096);
      LLen := System.Length(LEcho);
      LTls.Receive(@LEcho[0], LLen);

      LServer.WaitFor;
      if GServerError <> '' then
        raise Exception.Create('server: ' + GServerError);

      LOk := (LLen = System.Length(LPing)) and CompareMem(@LEcho[0], @LPing[0], LLen)
        and (LTls.GetCipherName = 'TLSv1.2');
      if LOk then
      begin
        Writeln('mORMot advanced-config PASS: injected config pinned TLS 1.2 + ordered ciphers, echo ok');
        Result := 0;
      end
      else
        Writeln('mORMot advanced-config FAIL: echo/version mismatch (', LTls.GetCipherName, ')');
      LServer.Free;
    finally
      // clear the process-wide configs so later work in the same process is unaffected
      SetTlsLibMormotServerConfig(nil);
      SetTlsLibMormotClientConfig(nil);
    end;
  except
    on E: Exception do
      Writeln('mORMot advanced-config FAIL: ', E.ClassName, ': ', E.Message);
  end;
  GReady.Free;
end;

end.
