{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

/// <summary>
/// Handshake customization over the Indy adapter, as a runnable check: SNI, cipher suites,
/// and the named group (key_share curve), with PEM certificates.
///
/// It stands up a loopback TIdTCPServer + TIdTCPClient and drives two handshakes:
///
///   Run A - the SSLOptions.ServerConfig / ClientConfig escape hatch, fed PEM bytes. It
///           pins the named groups so the key_share curve is secp256r1 (NOT the x25519
///           default), sets an explicit cipher-suite list under server preference, and the
///           client sends SNI via its Host. It then asserts, through the adapter accessors,
///           that both peers negotiated exactly those parameters and that the server saw the
///           client's SNI on the wire (PeerServerName).
///
///   Run B - the plain SSLOptions.CertFile / KeyFile / RootCertFile properties pointed at
///           real *.pem files (written from the same fixture). This proves a PEM file loads
///           as-is: no hex/DER conversion is required. Both PEM and DER are auto-detected.
///
/// Feeding a TIdHTTPServer looks the same - the IOHandler is configured identically:
///
///   LServerIO := TTlsLibServerIOHandler.Create(AHttpServer);
///   LServerIO.SSLOptions.CertFile := 'server.pem';   // or .ServerConfig := BuildServerConfig(...)
///   LServerIO.SSLOptions.KeyFile  := 'server.key';
///   LServerIO.SSLOptions.KeyPassword := '...';        // only if the key is encrypted
///   LServerIO.SSLOptions.HandshakeTimeoutMs := 15000;
///   AHttpServer.IOHandler := LServerIO;
///
/// SNI for a client is just the connection Host (for TIdHTTP, the request URL's host); the
/// default WithNameCheck(True) verifies the leaf against it. The FIRST WithPreferredGroups
/// entry is the curve the client generates its key_share for.
/// </summary>
unit IndyCustomizationExample;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

interface

type
  TIndyCustomizationExample = class sealed(TObject)
  public
    /// <summary>Runs both checks; returns 0 on success, 1 on failure.</summary>
    class function Run: Integer; static;
  end;

implementation

uses
  SysUtils,
  Classes,
  SyncObjs,
  IdContext,
  IdTCPServer,
  IdTCPClient,
  IdGlobal,
  IdCoderMIME,
  TlpDataEncoding,
  TlpTlsVersion,
  TlpNegotiationTypes,
  TlpINegotiation,
  TlpCipherSuiteRegistry,
  TlpDefaultCryptoProvider,
  TlpITlsConfig,
  TlpITlsConfigBuilder,
  TlpTlsPresets,
  TlpIndyTls;

const
  PORT_A = 28470;
  PORT_B = 28471;
  SNI_HOST = 'localhost'; // matches the leaf's CN/SAN in the fixture
  PING = 'ping';

// ---------------------------------------------------------------- fixture plumbing

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
  raise Exception.Create('EcP256Chain.txt vector not found (searched up from the exe)');
end;

function FieldDer(const AVector, AName: string): TBytes;
var
  LLines: TStringList;
  LI: Integer;
  LPrefix: string;
begin
  Result := nil;
  LPrefix := AName + '=';
  LLines := TStringList.Create;
  try
    LLines.LoadFromFile(AVector);
    for LI := 0 to LLines.Count - 1 do
      if Pos(LPrefix, LLines[LI]) = 1 then
        Exit(TDataEncoding.HexDecode(Copy(LLines[LI], System.Length(LPrefix) + 1, MaxInt)));
  finally
    LLines.Free;
  end;
end;

// ---- DER -> PEM (so the demo can feed real PEM bytes and write real *.pem files) ----

function PemText(const ADer: TBytes; const ALabel: string): string;
var
  LB64: string;
  LI: Integer;
begin
  if System.Length(ADer) > 0 then
    LB64 := TIdEncoderMIME.EncodeBytes(RawToBytes(ADer[0], System.Length(ADer)))
  else
    LB64 := '';
  Result := '-----BEGIN ' + ALabel + '-----'#10;
  LI := 1;
  while LI <= System.Length(LB64) do
  begin
    Result := Result + Copy(LB64, LI, 64) + #10;
    Inc(LI, 64);
  end;
  Result := Result + '-----END ' + ALabel + '-----'#10;
end;

function PemBytes(const ADer: TBytes; const ALabel: string): TBytes;
var
  LText: string;
  LI: Integer;
begin
  Result := nil;
  LText := PemText(ADer, ALabel);
  SetLength(Result, System.Length(LText));
  for LI := 1 to System.Length(LText) do
    Result[LI - 1] := Byte(Ord(LText[LI]));
end;

function TempDir: string;
begin
  Result := GetEnvironmentVariable('TEMP');
  if Result = '' then
    Result := GetEnvironmentVariable('TMPDIR');
  if Result = '' then
    Result := GetCurrentDir;
end;

function WritePem(const AName: string; const ADer: TBytes; const ALabel: string): string;
var
  LStream: TFileStream;
  LBytes: TBytes;
begin
  Result := IncludeTrailingPathDelimiter(TempDir) + AName;
  LBytes := PemBytes(ADer, ALabel);
  LStream := TFileStream.Create(Result, fmCreate);
  try
    LStream.WriteBuffer(LBytes[0], System.Length(LBytes));
  finally
    LStream.Free;
  end;
end;

// ---------------------------------------------------------------- config building

// a registry holding exactly ACodes, in that order (the advertised / preferred order)
function OrderedRegistry(const ACodes: array of UInt16): ICipherSuiteRegistry;
var
  LAll, LReg: ICipherSuiteRegistry;
  LSuite: TTlsCipherSuite;
  LI: Integer;
begin
  LAll := TCipherSuiteRegistry.CreateDualVersion(TDefaultCryptoProvider.Shared);
  LReg := TCipherSuiteRegistry.Create;
  for LI := System.Low(ACodes) to System.High(ACodes) do
    if LAll.TryGet(ACodes[LI], LSuite) then
      LReg.Add(LSuite);
  Result := LReg;
end;

function BuildServerConfig(const ACertPem, AKeyPem: TBytes): ITlsServerConfig;
var
  LServer: ITlsServerConfigBuilder;
begin
  LServer := TTlsPresets.Compatible(TDefaultCryptoProvider.Shared).Server;
  LServer.WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls13));
  // P-256 first => the key_share curve is secp256r1, not x25519; X25519 stays negotiable
  LServer.WithPreferredGroups(TArray<UInt16>.Create(TNamedGroupCatalog.Secp256r1,
    TNamedGroupCatalog.X25519));
  LServer.WithCipherSuites(OrderedRegistry([TCipherSuites13.Aes256GcmSha384,
    TCipherSuites13.Aes128GcmSha256, TCipherSuites13.ChaCha20Poly1305Sha256]));
  LServer.WithCipherSuitePreference(TServerCipherPreference.ServerOrder);
  LServer.WithServerNameAcknowledgement(True);
  LServer.WithCredential(ACertPem, AKeyPem); // PEM bytes (DER works too, auto-detected)
  Result := LServer.Build;
end;

function BuildClientConfig(const ARootPem: TBytes): ITlsClientConfig;
var
  LClient: ITlsClientConfigBuilder;
begin
  LClient := TTlsPresets.Compatible(TDefaultCryptoProvider.Shared).Client;
  LClient.WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls13));
  LClient.WithPreferredGroups(TArray<UInt16>.Create(TNamedGroupCatalog.Secp256r1,
    TNamedGroupCatalog.X25519));
  LClient.WithCipherSuites(OrderedRegistry([TCipherSuites13.Aes256GcmSha384,
    TCipherSuites13.Aes128GcmSha256, TCipherSuites13.ChaCha20Poly1305Sha256]));
  LClient.WithTrustAnchors(ARootPem); // PEM root (DER works too)
  // WithNameCheck(True) is the default: the leaf is verified against the connection Host
  Result := LClient.Build;
end;

// ---- server side: echo one line, capturing what it negotiated for that connection ----

type
  TServerObserver = class sealed(TObject)
  strict private
    FLock: TCriticalSection;
    FSni: string;
    FGroup, FSuite: UInt16;
    FErr: string;
    FDone: Boolean;
  public
    constructor Create;
    destructor Destroy; override;
    procedure DoExecute(AContext: TIdContext);
    procedure Snapshot(out ASni: string; out AGroup, ASuite: UInt16; out AErr: string);
  end;

constructor TServerObserver.Create;
begin
  FLock := TCriticalSection.Create;
end;

destructor TServerObserver.Destroy;
begin
  FLock.Free;
  inherited;
end;

procedure TServerObserver.DoExecute(AContext: TIdContext);
var
  LIO: TTlsLibIOHandlerSocket;
  LLine: string;
begin
  try
    LLine := AContext.Connection.IOHandler.ReadLn;
    // the handshake is complete by the first read; capture the SNI the client requested and
    // what the server peer negotiated, proving the accessors work on the server-side handler
    if AContext.Connection.IOHandler is TTlsLibIOHandlerSocket then
    begin
      LIO := TTlsLibIOHandlerSocket(AContext.Connection.IOHandler);
      FLock.Enter;
      try
        if not FDone then
        begin
          FSni := LIO.PeerServerName;
          FGroup := LIO.NegotiatedGroup;
          FSuite := LIO.NegotiatedCipherSuite;
          FDone := True;
        end;
      finally
        FLock.Leave;
      end;
    end;
    AContext.Connection.IOHandler.WriteLn(LLine);
  except
    // a post-echo disconnect is benign; record only for diagnostics, never a pass/fail gate
    on E: Exception do
    begin
      FLock.Enter;
      try
        if FErr = '' then
          FErr := E.ClassName + ': ' + E.Message;
      finally
        FLock.Leave;
      end;
    end;
  end;
end;

procedure TServerObserver.Snapshot(out ASni: string; out AGroup, ASuite: UInt16;
  out AErr: string);
begin
  FLock.Enter;
  try
    ASni := FSni;
    AGroup := FGroup;
    ASuite := FSuite;
    AErr := FErr;
  finally
    FLock.Leave;
  end;
end;

// ---------------------------------------------------------------- the two runs

// Run A: escape hatch + PEM bytes. Returns True and the client/server-observed parameters.
function RunEscapeHatch(const ACertPem, AKeyPem, ARootPem: TBytes;
  out AClientSuite, AClientGroup, AServerSuite, AServerGroup: UInt16;
  out AServerSni, AFailReason: string): Boolean;
var
  LServer: TIdTCPServer;
  LServerIO: TTlsLibServerIOHandler;
  LClient: TIdTCPClient;
  LClientIO: TTlsLibIOHandlerSocket;
  LObs: TServerObserver;
  LErr: string;
begin
  Result := False;
  AClientSuite := 0; AClientGroup := 0; AServerSuite := 0; AServerGroup := 0;
  AServerSni := ''; AFailReason := '';
  LObs := TServerObserver.Create;
  LServer := TIdTCPServer.Create(nil);
  LClient := TIdTCPClient.Create(nil);
  try
    LServerIO := TTlsLibServerIOHandler.Create(LServer);
    LServerIO.SSLOptions.ServerConfig := BuildServerConfig(ACertPem, AKeyPem);
    LServer.IOHandler := LServerIO;
    LServer.DefaultPort := PORT_A;
    LServer.OnExecute := LObs.DoExecute;
    LServer.Active := True;

    LClientIO := TTlsLibIOHandlerSocket.Create(LClient);
    LClientIO.SSLOptions.ClientConfig := BuildClientConfig(ARootPem);
    LClient.IOHandler := LClientIO;
    LClient.Host := SNI_HOST; // <- this is the SNI sent on the wire, and the name verified
    LClient.Port := PORT_A;
    LClient.Connect;
    try
      LClientIO.WriteLn(PING);
      LClientIO.ReadLn;
      AClientSuite := LClientIO.NegotiatedCipherSuite;
      AClientGroup := LClientIO.NegotiatedGroup;
    finally
      LClient.Disconnect;
    end;
    LObs.Snapshot(AServerSni, AServerGroup, AServerSuite, LErr);
    LServer.Active := False;
    Result := True;
  finally
    LClient.Free;
    LServer.Free;
    LObs.Free;
  end;
end;

// Run B: PEM *files* via SSLOptions.CertFile/KeyFile/RootCertFile. Returns True on a clean echo.
function RunPemFiles(const ACertFile, AKeyFile, ARootFile: string;
  out AFailReason: string): Boolean;
var
  LServer: TIdTCPServer;
  LServerIO: TTlsLibServerIOHandler;
  LClient: TIdTCPClient;
  LClientIO: TTlsLibIOHandlerSocket;
  LObs: TServerObserver;
  LEcho: string;
begin
  Result := False;
  AFailReason := '';
  LObs := TServerObserver.Create;
  LServer := TIdTCPServer.Create(nil);
  LClient := TIdTCPClient.Create(nil);
  try
    LServerIO := TTlsLibServerIOHandler.Create(LServer);
    LServerIO.SSLOptions.CertFile := ACertFile; // a real *.pem, loaded as-is
    LServerIO.SSLOptions.KeyFile := AKeyFile;    // a real *.pem, loaded as-is
    LServer.IOHandler := LServerIO;
    LServer.DefaultPort := PORT_B;
    LServer.OnExecute := LObs.DoExecute;
    LServer.Active := True;

    LClientIO := TTlsLibIOHandlerSocket.Create(LClient);
    LClientIO.SSLOptions.RootCertFile := ARootFile; // a real *.pem trust anchor
    LClient.IOHandler := LClientIO;
    LClient.Host := SNI_HOST;
    LClient.Port := PORT_B;
    LClient.Connect;
    try
      LClientIO.WriteLn(PING);
      LEcho := LClientIO.ReadLn;
    finally
      LClient.Disconnect;
    end;
    LServer.Active := False;
    if LEcho = PING then
      Result := True
    else
      AFailReason := 'PEM-file handshake did not echo (' + LEcho + ')';
  finally
    LClient.Free;
    LServer.Free;
    LObs.Free;
  end;
end;

// ---------------------------------------------------------------- entry point

class function TIndyCustomizationExample.Run: Integer;
var
  LVector: string;
  LLeafDer, LKeyDer, LRootDer: TBytes;
  LLeafPem, LKeyPem, LRootPem: TBytes;
  LCertFile, LKeyFile, LRootFile: string;
  LClientSuite, LClientGroup, LServerSuite, LServerGroup: UInt16;
  LServerSni, LReason: string;
  LOk: Boolean;
begin
  Result := 1;
  try
    LVector := LocateVector;
    LLeafDer := FieldDer(LVector, 'leaf_cert');
    LKeyDer := FieldDer(LVector, 'leaf_key');
    LRootDer := FieldDer(LVector, 'root_cert');
    LLeafPem := PemBytes(LLeafDer, 'CERTIFICATE');
    LKeyPem := PemBytes(LKeyDer, 'PRIVATE KEY');
    LRootPem := PemBytes(LRootDer, 'CERTIFICATE');

    // ---- Run A: customization asserted through the adapter accessors ----
    if not RunEscapeHatch(LLeafPem, LKeyPem, LRootPem, LClientSuite, LClientGroup,
      LServerSuite, LServerGroup, LServerSni, LReason) then
    begin
      Writeln('Indy customization FAIL (Run A): ', LReason);
      Exit;
    end;

    LOk := (LClientSuite = TCipherSuites13.Aes256GcmSha384) and
      (LServerSuite = TCipherSuites13.Aes256GcmSha384) and
      (LClientGroup = TNamedGroupCatalog.Secp256r1) and
      (LServerGroup = TNamedGroupCatalog.Secp256r1) and
      (LServerSni = SNI_HOST);
    if not LOk then
    begin
      Writeln('Indy customization FAIL (Run A): suite c/s=', IntToHex(LClientSuite, 4), '/',
        IntToHex(LServerSuite, 4), ' group c/s=', IntToHex(LClientGroup, 4), '/',
        IntToHex(LServerGroup, 4), ' serverSNI="', LServerSni, '"');
      Exit;
    end;
    Writeln('Run A OK: suite=', IntToHex(LClientSuite, 4), ' (AES-256-GCM) both sides, ',
      'key_share group=', IntToHex(LClientGroup, 4),
      ' (secp256r1, not the x25519 default), server saw client SNI="', LServerSni, '"');

    // ---- Run B: a plain *.pem file loads as-is ----
    LCertFile := WritePem('tls_custom_leaf.pem', LLeafDer, 'CERTIFICATE');
    LKeyFile := WritePem('tls_custom_key.pem', LKeyDer, 'PRIVATE KEY');
    LRootFile := WritePem('tls_custom_root.pem', LRootDer, 'CERTIFICATE');
    if not RunPemFiles(LCertFile, LKeyFile, LRootFile, LReason) then
    begin
      Writeln('Indy customization FAIL (Run B): ', LReason);
      Exit;
    end;
    Writeln('Run B OK: SSLOptions.CertFile/KeyFile/RootCertFile accepted PEM files as-is');

    Writeln('Indy customization PASS');
    Result := 0;
  except
    on E: Exception do
      Writeln('Indy customization FAIL: ', E.ClassName, ': ', E.Message);
  end;
end;

end.
