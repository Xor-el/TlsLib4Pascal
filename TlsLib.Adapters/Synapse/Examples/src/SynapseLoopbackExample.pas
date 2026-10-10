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
  CRLF = #13#10;
  STALL_HOLD_MS = 4000; // how long the server stays silent after the partial record
  READ_CAP_MS = 800;
  STALL_LIMIT_MS = 3000; // the cap must end the wait well before the server's silence does

var
  GRootFile: string;
  GLeafPfx: AnsiString;
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
    class function WriteDer(const AName, AHex: string): string; static;
  end;

  TServerThread = class(TThread)
  protected
    procedure Execute; override;
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
var
  LLines: TStringList;
  LI: Integer;
  LPrefix: string;
begin
  Result := '';
  LPrefix := AName + '=';
  LLines := TStringList.Create;
  try
    LLines.LoadFromFile(GVector);
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

    if LEcho = 'ping from the synapse client' then
    begin
      Writeln('Synapse loopback PASS: handshake + echo + a stalled record bounded in ',
        LStallMs, ' ms');
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
