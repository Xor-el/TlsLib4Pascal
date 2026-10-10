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
/// A real loopback over Synapse's TCustomSSL seam on 127.0.0.1: both ends are TTCPBlockSocket
/// instances created with our SSLImplementation plugin. The server runs on a background
/// thread, the client on the caller's thread. It asserts a full handshake, a round-tripped
/// line and a read bounded by ReadTimeoutMs when the peer stalls mid-record - proving the
/// Synapse plugin end to end. Shared by the FreePascal and Delphi example
/// programs.
/// </summary>
unit SynapseLoopbackExample;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

interface

type
  TSynapseLoopbackExample = class sealed(TObject)
  public
    /// <summary>Runs the loopback; returns 0 on success, 1 on failure.</summary>
    class function Run: Integer; static;
  end;

implementation

uses
  SysUtils,
  Classes,
  SyncObjs,
  DateUtils,
  blcksock,
  synsock,
  TlpDataEncoding,
  TlpTlsCredential,
  TlpNegotiationTypes,
  TlsLibSynapseTls;

const
  PORT = '28445';
  MUTUAL_PORT = '28455';
  CRLF = #13#10;
  STALL_HOLD_MS = 4000; // how long the server stays silent after the partial record
  READ_CAP_MS = 800;
  STALL_LIMIT_MS = 3000; // the cap must end the wait well before the server's silence does

var
  GRootFile: string;
  GLeafPfx: AnsiString;
  // the dual-EKU chain the mutual-TLS check serves and authenticates with
  GMutualRootFile: string;
  GMutualPfx: AnsiString;
  GReady: TEvent;
  GServerError: string;
  GVector: string;

type
  TVectorLocator = class sealed(TObject)
  strict private
    class function SearchFrom(const AStart: string): string; static;
  public
    class function Find: string; static;
    class function FieldHex(const AName: string): string; static;
    /// <summary>A field of another vector file in the same folder as the main one.</summary>
    class function FieldHexFrom(const AFile, AName: string): string; static;
    class function WriteDer(const AName, AHex: string): string; static;
  end;

  TServerThread = class(TThread)
  protected
    procedure Execute; override;
  end;

  /// <summary>A server that requires a client certificate and serves two connections in turn,
  /// recording whether each handshake was accepted and the peer fingerprint it saw.</summary>
  TMutualServerThread = class(TThread)
  strict private
  var
    FSeen: array[0..1] of Boolean;
    FAccepted: array[0..1] of Boolean;
    FFingerprint: array[0..1] of string;
  protected
    procedure Execute; override;
  public
    /// <summary>Whether a connection reached the server, so a missing one is not read as a
    /// rejection.</summary>
    function Seen(AIndex: Integer): Boolean;
    function Accepted(AIndex: Integer): Boolean;
    function Fingerprint(AIndex: Integer): string;
  end;

  TMutualTlsCheck = class sealed(TObject)
  strict private
    class function Connect(AWithIdentity: Boolean; out AEcho: string): Boolean; static;
  public
    /// <summary>A client that presents the PKCS#12 identity authenticates to a server requiring a
    /// certificate, and one that presents none is turned away.</summary>
    class procedure Run; static;
  end;

class function TVectorLocator.SearchFrom(const AStart: string): string;
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

class function TVectorLocator.Find: string;
begin
  Result := SearchFrom(ExtractFilePath(ParamStr(0)));
  if Result = '' then
    Result := SearchFrom(GetCurrentDir);
  if Result = '' then
    raise Exception.Create('EcP256Chain.txt vector not found (searched up from the exe and cwd)');
end;

class function TVectorLocator.FieldHex(const AName: string): string;
begin
  Result := FieldHexFrom(ExtractFileName(GVector), AName);
end;

class function TVectorLocator.FieldHexFrom(const AFile, AName: string): string;
var
  LLines: TStringList;
  LI: Integer;
  LPrefix: string;
begin
  Result := '';
  LPrefix := AName + '=';
  LLines := TStringList.Create;
  try
    LLines.LoadFromFile(ExtractFilePath(GVector) + AFile);
    for LI := 0 to LLines.Count - 1 do
      if Pos(LPrefix, LLines[LI]) = 1 then
        Exit(Copy(LLines[LI], System.Length(LPrefix) + 1, MaxInt));
  finally
    LLines.Free;
  end;
end;

class function TVectorLocator.WriteDer(const AName, AHex: string): string;
var
  LBytes: TBytes;
  LFile: TFileStream;
begin
  LBytes := TDataEncoding.HexDecode(AHex);
  Result := IncludeTrailingPathDelimiter(GetEnvironmentVariable('TEMP')) +
    'tlslib_syn_' + AName + '.der';
  LFile := TFileStream.Create(Result, fmCreate);
  try
    if System.Length(LBytes) > 0 then
      LFile.WriteBuffer(LBytes[0], System.Length(LBytes));
  finally
    LFile.Free;
  end;
end;

procedure TServerThread.Execute;
var
  LListener, LClient: TTCPBlockSocket;
  LLine: string;
  LHdr: array[0..2] of Byte;
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
          // the server identity as an in-memory PKCS#12
          LClient.SSL.PFX := GLeafPfx;
          LClient.SSL.KeyPassword := 'tlslib';
          if not LClient.SSLAcceptConnection then
            raise Exception.Create('ssl accept failed: ' + LClient.SSL.LastErrorDesc);
          LLine := LClient.RecvString(5000);
          LClient.SendString(LLine + CRLF);
          // then the first bytes of a TLS record straight on the socket, and silence: the client's
          // read cap, not this thread's exit, must be what ends its wait. The pause keeps them from
          // arriving in the same segment as the echo, where the client would read them early.
          Sleep(300);
          LHdr[0] := $17; LHdr[1] := $03; LHdr[2] := $03;
          synsock.Send(LClient.Socket, @LHdr[0], 3, 0);
          Sleep(STALL_HOLD_MS);
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

{ TMutualServerThread }

function TMutualServerThread.Seen(AIndex: Integer): Boolean;
begin
  Result := FSeen[AIndex];
end;

function TMutualServerThread.Accepted(AIndex: Integer): Boolean;
begin
  Result := FAccepted[AIndex];
end;

function TMutualServerThread.Fingerprint(AIndex: Integer): string;
begin
  Result := FFingerprint[AIndex];
end;

procedure TMutualServerThread.Execute;
var
  LListener, LClient: TTCPBlockSocket;
  LI: Integer;
begin
  LListener := TTCPBlockSocket.Create;
  try
    try
      LListener.CreateSocket;
      LListener.SetLinger(True, 1000);
      LListener.Bind('127.0.0.1', MUTUAL_PORT);
      LListener.Listen;
      GReady.SetEvent;
      for LI := 0 to 1 do
      begin
        if not LListener.CanRead(5000) then
          Break;
        LClient := TTCPBlockSocket.CreateWithSSL(SSLImplementation);
        try
          LClient.Socket := LListener.Accept;
          FSeen[LI] := True;
          LClient.SSL.PFX := GMutualPfx;
          LClient.SSL.KeyPassword := 'tlslib';
          // the test root vouches for clients, and a certificate is required
          LClient.SSL.CertCAFile := GMutualRootFile;
          LClient.SSL.VerifyCert := True;
          (LClient.SSL as TSSLTlsLib).ClientAuth := TClientAuthMode.Required;
          FAccepted[LI] := LClient.SSLAcceptConnection;
          if FAccepted[LI] then
          begin
            FFingerprint[LI] := LClient.SSL.GetPeerFingerprint;
            LClient.SendString(LClient.RecvString(5000) + CRLF);
          end;
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

{ TMutualTlsCheck }

class function TMutualTlsCheck.Connect(AWithIdentity: Boolean; out AEcho: string): Boolean;
var
  LClient: TTCPBlockSocket;
begin
  AEcho := '';
  LClient := TTCPBlockSocket.CreateWithSSL(SSLImplementation);
  try
    LClient.SSL.CertCAFile := GMutualRootFile;
    LClient.SSL.VerifyCert := True;
    LClient.SSL.SNIHost := 'localhost';
    if AWithIdentity then
    begin
      LClient.SSL.PFX := GMutualPfx;
      LClient.SSL.KeyPassword := 'tlslib';
    end;
    LClient.Connect('127.0.0.1', MUTUAL_PORT);
    LClient.SSLDoConnect;
    Result := LClient.SSL.SSLEnabled;
    if Result then
    begin
      // TLS 1.3 lets the client finish before the server judges its certificate: the answer is
      // the echo, which a rejected client never gets
      LClient.SendString('mutual' + CRLF);
      AEcho := LClient.RecvString(2000);
    end;
  finally
    LClient.Free;
  end;
end;

class procedure TMutualTlsCheck.Run;
var
  LServer: TMutualServerThread;
  LEcho: string;
  LPfx: TBytes;
begin
  LPfx := TDataEncoding.HexDecode(TVectorLocator.FieldHexFrom('ClientAuthChain.txt', 'leaf_pfx'));
  SetString(GMutualPfx, PAnsiChar(@LPfx[0]), System.Length(LPfx));
  GMutualRootFile := TVectorLocator.WriteDer('mutual_root',
    TVectorLocator.FieldHexFrom('ClientAuthChain.txt', 'root_cert'));
  GReady.ResetEvent;
  LServer := TMutualServerThread.Create(True);
  LServer.FreeOnTerminate := False;
  try
    LServer.Start;
    GReady.WaitFor(5000);
    if GServerError <> '' then
      raise Exception.Create('mutual server: ' + GServerError);
    Connect(True, LEcho);
    if LEcho <> 'mutual' then
      raise Exception.Create('a client presenting the PFX identity was not served');
    // the client side of a TLS 1.3 handshake completes before the server judges its certificate
    if not Connect(False, LEcho) then
      raise Exception.Create('the client with no certificate never completed its handshake');
    if LEcho <> '' then
      raise Exception.Create('a client with no certificate was served');
    LServer.WaitFor;
    if GServerError <> '' then
      raise Exception.Create('mutual server: ' + GServerError);
    if not LServer.Accepted(0) then
      raise Exception.Create('the server did not accept the PFX identity');
    if LServer.Fingerprint(0) = '' then
      raise Exception.Create('the server saw no client certificate');
    if not LServer.Seen(1) then
      raise Exception.Create('the client with no certificate never reached the server');
    if LServer.Accepted(1) then
      raise Exception.Create('the server accepted a client with no certificate');
  finally
    LServer.Free;
  end;
end;

// Assign keeps the plugin's own properties, and a Ciphers value that is not a suite name is refused
// rather than ignored
procedure CheckAssignAndCiphers;
var
  LFrom, LTo: TTCPBlockSocket;
begin
  LFrom := TTCPBlockSocket.CreateWithSSL(SSLImplementation);
  LTo := TTCPBlockSocket.CreateWithSSL(SSLImplementation);
  try
    (LFrom.SSL as TSSLTlsLib).ClientAuth := TClientAuthMode.Required;
    LTo.SSL.Assign(LFrom.SSL);
    if (LTo.SSL as TSSLTlsLib).ClientAuth <> TClientAuthMode.Required then
      raise Exception.Create('Assign dropped ClientAuth');
    LTo.SSL.Ciphers := 'HIGH';
    if LTo.SSL.Connect then
      raise Exception.Create('a Ciphers list was accepted');
    if Pos('Ciphers', LTo.SSL.LastErrorDesc) = 0 then
      raise Exception.Create('Ciphers refusal not reported: ' + LTo.SSL.LastErrorDesc);
    // two sources for one credential are refused, naming both properties
    LTo.SSL.Ciphers := '';
    LTo.SSL.PFX := 'pfx';
    LTo.SSL.CertificateFile := 'cert.pem';
    if LTo.SSL.Connect then
      raise Exception.Create('a PFX beside a CertificateFile was accepted');
    if (Pos('PFX', LTo.SSL.LastErrorDesc) = 0) or
      (Pos('CertificateFile', LTo.SSL.LastErrorDesc) = 0) then
      raise Exception.Create('credential conflict not reported: ' + LTo.SSL.LastErrorDesc);
  finally
    LTo.Free;
    LFrom.Free;
  end;
end;

class function TSynapseLoopbackExample.Run: Integer;
var
  LServer: TServerThread;
  LClient: TTCPBlockSocket;
  LEcho: string;
  LPfx: TBytes;
  LStart: TDateTime;
  LStallMs: Int64;
begin
  Result := 1;
  GServerError := '';
  GVector := TVectorLocator.Find;
  GReady := TEvent.Create(nil, True, False, '');
  try
    CheckAssignAndCiphers;
    LPfx := TDataEncoding.HexDecode(TVectorLocator.FieldHex('leaf_pfx'));
    SetString(GLeafPfx, PAnsiChar(@LPfx[0]), System.Length(LPfx));
    GRootFile := TVectorLocator.WriteDer('root', TVectorLocator.FieldHex('root_cert'));

    LServer := TServerThread.Create(True);
    LServer.FreeOnTerminate := False;
    LServer.Start;
    GReady.WaitFor(5000);
    if GServerError <> '' then
      raise Exception.Create('server: ' + GServerError);

    LClient := TTCPBlockSocket.CreateWithSSL(SSLImplementation);
    try
      LClient.SSL.CertCAFile := GRootFile;
      LClient.SSL.VerifyCert := True;
      LClient.SSL.SNIHost := 'localhost'; // verify the leaf for its 'localhost' SAN
      // the client offers one suite, so a negotiated AES-256 proves the list was honoured
      LClient.SSL.Ciphers := 'TLS_AES_256_GCM_SHA384';
      LClient.Connect('127.0.0.1', PORT);
      if LClient.LastError <> 0 then
        raise Exception.Create('tcp connect failed');
      LClient.SSLDoConnect;
      if not LClient.SSL.SSLEnabled then
        raise Exception.Create('ssl connect failed: ' + LClient.SSL.LastErrorDesc);
      if TSSLTlsLib(LClient.SSL).NegotiatedCipherSuite <> TCipherSuites13.Aes256GcmSha384 then
        raise Exception.Create('the Ciphers list was not honoured: ' + LClient.SSL.GetCipherName);
      LClient.SendString('ping from the synapse client' + CRLF);
      LEcho := LClient.RecvString(5000);
      // the server now sends part of a record and stalls: with the cap set the read must fail fast
      TSSLTlsLib(LClient.SSL).ReadTimeoutMs := READ_CAP_MS;
      LStart := Now;
      LClient.RecvPacket(10000);
      LStallMs := MilliSecondsBetween(Now, LStart);
      if (LClient.LastError = 0) or (LStallMs > STALL_LIMIT_MS) then
        raise Exception.CreateFmt('a stalled record was not bounded by ReadTimeoutMs (%d ms, error %d)',
          [LStallMs, LClient.LastError]);
    finally
      LClient.Free;
    end;

    LServer.WaitFor;
    if GServerError <> '' then
      raise Exception.Create('server: ' + GServerError);
    TMutualTlsCheck.Run;

    if LEcho = 'ping from the synapse client' then
    begin
      Writeln('Synapse loopback PASS: handshake + echo + a stalled record bounded in ',
        LStallMs, ' ms + client PFX identity authenticated');
      Result := 0;
    end
    else
      Writeln('Synapse loopback FAIL: echo="', LEcho, '"');
    LServer.Free;
  except
    on E: Exception do
      Writeln('Synapse loopback FAIL: ', E.ClassName, ': ', E.Message);
  end;
  GReady.Free;
end;

end.
