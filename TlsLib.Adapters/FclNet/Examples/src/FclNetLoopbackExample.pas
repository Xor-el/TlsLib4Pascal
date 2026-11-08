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
/// A real loopback over fcl-net's TSSLSocketHandler seam on 127.0.0.1: the server is a fcl-net
/// TInetServer whose accepted connections carry our TTlsLibSocketHandler (supplied through
/// OnCreateClientSocketHandler); the client is a fcl-net TInetSocket driven with the same handler
/// class. The server runs on a background thread, the client on the caller's thread. It asserts a
/// full TLS 1.3 handshake, a round-tripped line and a read bounded by IOTimeout when the peer
/// stalls mid-record - proving the fcl-net adapter end to end. Further checks cover a client
/// identity (mutual TLS), an early-closing client, VerifyPeerCert (a False written through
/// fcl-net's base type is ignored, one written through our type is honoured) and a self-signed
/// leaf trusted as its own anchor.
/// </summary>
unit FclNetLoopbackExample;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

interface

uses
  TlpTlsVersion;

type
  TFclNetLoopbackExample = class sealed(TObject)
  strict private
    class function VersionText(const AVersion: TTlsVersion): string; static;
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
  TypInfo,
  ssockets,
  sslbase,
  sslsockets,
  Sockets,
  TlpDataEncoding,
  TlpNegotiationTypes,
  TlpTlsCredential,
  TlpICryptoProvider,
  TlpIPkixProvider,
  TlpDefaultCryptoProvider,
  TlpDefaultPkixProvider,
  TlpITlsConfigBuilder,
  TlpCertificateVerifierSource,
  TlpTlsPresets,
  TlsLibFclNetTls;

const
  PORT = 28446;
  MUTUAL_PORT = 28456;
  EARLY_CLOSE_PORT = 28457;
  VERIFY_PORT = 28458;
  VERIFY_SELF_PORT = 28459;
  BASE_WRITE_HINT = 'does not switch verification off';
  UNTRUSTED_CHAIN = 'chain was not trusted'; // the one message any certificate rejection carries
  EARLY_CLOSE_LIMIT_MS = 2000;
  STALL_HOLD_MS = 4000; // how long the server stays silent after the partial record
  READ_CAP_MS = 800;
  ACCEPT_POLL_MS = 100;
  STALL_LIMIT_MS = 3000; // the socket timeout must end the wait well before the server's silence does
  PING = 'ping from the fclnet client';

type
  TVectorLocator = class sealed(TObject)
  strict private
    class function SearchFrom(const AStart: string): string; static;
    class var FVector: string;
  public
    class procedure Locate; static;
    class function FieldHex(const AName: string): string; static;
    /// <summary>A field of another vector file in the same folder as the main one.</summary>
    class function FieldHexFrom(const AFile, AName: string): string; static;
    class function WriteDer(const AName, AHex: string): string; static;
  end;

  /// <summary>The loopback server: binds 127.0.0.1:PORT, hands each accepted connection a fcl-net
  /// TTlsLibSocketHandler carrying the leaf cert/key, echoes the one line the client sends, then
  /// sends part of a record and goes silent.</summary>
  TServerThread = class(TThread)
  strict private
  var
    FError, FPeerServerName: string;
    FPfx: TBytes;
    FReady: TEvent;
    // the accepted connection's handler; the stream owns it and frees it with the stream
    FAccepted: TTlsLibSocketHandler;
    FServer: TInetServer;
    procedure MakeHandler(Sender: TObject; out AHandler: TSocketHandler);
    procedure HandleConnect(Sender: TObject; AStream: TSocketStream);
    procedure HandleIdle(Sender: TObject);
  protected
    procedure Execute; override;
  public
    constructor Create(const APfx: TBytes; AReady: TEvent);
    property Error: string read FError;
    /// <summary>The SNI host_name the client sent, as the server saw it.</summary>
    property PeerServerName: string read FPeerServerName;
  end;

  /// <summary>A server that requires a client certificate and serves one connection, counting the
  /// ones that reached it. A client turned away in the handshake is not an accepted connection, so
  /// the loop ends after the first one that authenticates.</summary>
  TMutualServerThread = class(TThread)
  strict private
  var
    FPfx: TBytes;
    FRootFile, FError: string;
    FServed, FAttempts: Integer;
    FReady: TEvent;
    FServer: TInetServer;
    procedure MakeHandler(Sender: TObject; out AHandler: TSocketHandler);
    procedure HandleConnect(Sender: TObject; AStream: TSocketStream);
    procedure HandleIdle(Sender: TObject);
  protected
    procedure Execute; override;
  public
    constructor Create(const APfx: TBytes; const ARootFile: string; AReady: TEvent);
    property Error: string read FError;
    property Served: Integer read FServed;
    /// <summary>Connections that reached the server, so a missing one is not read as a
    /// rejection.</summary>
    property Attempts: Integer read FAttempts;
  end;

  /// <summary>A server that records how long its TLS accept takes to give up on a client that
  /// connects and closes before sending a ClientHello.</summary>
  TEarlyCloseServerThread = class(TThread)
  strict private
  var
    FPfx: TBytes;
    FError: string;
    FReady, FSettled: TEvent;
    FServer: TInetServer;
    FAttemptAt: TDateTime;
    FSettledMs: Int64;
    procedure MakeHandler(Sender: TObject; out AHandler: TSocketHandler);
    procedure HandleConnect(Sender: TObject; AStream: TSocketStream);
    procedure HandleIdle(Sender: TObject);
  protected
    procedure Execute; override;
  public
    constructor Create(const APfx: TBytes; AReady, ASettled: TEvent);
    property Error: string read FError;
    /// <summary>From the connection reaching the server to its accept loop being idle again.</summary>
    property SettledMs: Int64 read FSettledMs;
  end;

  /// <summary>A server presenting one certificate and key, which echoes the line each client
  /// sends; it takes every connection until stopped.</summary>
  TVerifyServerThread = class(TThread)
  strict private
  var
    FCertificate, FPrivateKey: TBytes;
    FPort: Integer;
    FError: string;
    FReady: TEvent;
    FServer: TInetServer;
    procedure MakeHandler(Sender: TObject; out AHandler: TSocketHandler);
    procedure HandleConnect(Sender: TObject; AStream: TSocketStream);
    procedure HandleIdle(Sender: TObject);
  protected
    procedure Execute; override;
  public
    constructor Create(const ACertificate, APrivateKey: TBytes; APort: Integer);
    destructor Destroy; override;
    /// <summary>Starts the thread and returns once it listens; raises why when it cannot.</summary>
    procedure StartListening;
  end;

  TVerifyClient = class sealed(TObject)
  public
    /// <summary>Connects the handler (which the socket then owns) to the server on APort, sends a
    /// line and returns the echo; AError carries why when the connection or the echo fails.</summary>
    class function Echo(const AHandler: TTlsLibSocketHandler; APort: Integer;
      out AError: string): string; static;
  end;

  /// <summary>A user handler class registered as fcl-net's default class.</summary>
  TVerifySubclassHandler = class(TTlsLibSocketHandler)
  end;

  TVerifyIgnoredCheck = class sealed(TObject)
  public
    /// <summary>A VerifyPeerCert False written through fcl-net's base handler type, as fcl-web
    /// clients do, does not switch verification off, and the refusal says so.</summary>
    class procedure Run; static;
  end;

  TVerifyHonouredCheck = class sealed(TObject)
  public
    /// <summary>A VerifyPeerCert False written through TTlsLibSocketHandler skips verification,
    /// by property, by name and on the default handler, and an untouched handler verifies.</summary>
    class procedure Run; static;
  end;

  TSelfSignedLeafCheck = class sealed(TObject)
  public
    /// <summary>A self-signed leaf named in TrustedCertificate or CertCA is trusted as its own
    /// anchor, for the host name it carries.</summary>
    class procedure Run; static;
  end;

  TEarlyCloseCheck = class sealed(TObject)
  public
    /// <summary>The server's accept of a client that closes before its ClientHello returns
    /// promptly, not after the handshake cap.</summary>
    class procedure Run; static;
  end;

  TMutualTlsCheck = class sealed(TObject)
  strict private
    class function Echo(const APfx: TBytes; const ARootFile: string;
      AWithIdentity: Boolean; out AError: string): string; static;
    /// <summary>Whether a PFX beside a Certificate is refused with both properties named.</summary>
    class function RefusesTwoSources(const APfx: TBytes; const ARootFile: string): Boolean; static;
  public
    /// <summary>A client that presents the PKCS#12 identity authenticates to a server requiring a
    /// certificate, and one that presents none is turned away.</summary>
    class procedure Run; static;
  end;

{ TVectorLocator }

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

class procedure TVectorLocator.Locate;
begin
  FVector := SearchFrom(ExtractFilePath(ParamStr(0)));
  if FVector = '' then
    FVector := SearchFrom(GetCurrentDir);
  if FVector = '' then
    raise Exception.Create('EcP256Chain.txt vector not found (searched up from the exe and cwd)');
end;

class function TVectorLocator.FieldHex(const AName: string): string;
begin
  Result := FieldHexFrom(ExtractFileName(FVector), AName);
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
    LLines.LoadFromFile(ExtractFilePath(FVector) + AFile);
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
  Result := IncludeTrailingPathDelimiter(GetTempDir) + 'tlslib_fcl_' + AName + '.der';
  LFile := TFileStream.Create(Result, fmCreate);
  try
    if System.Length(LBytes) > 0 then
      LFile.WriteBuffer(LBytes[0], System.Length(LBytes));
  finally
    LFile.Free;
  end;
end;

{ TServerThread }

constructor TServerThread.Create(const APfx: TBytes; AReady: TEvent);
begin
  inherited Create(True);
  FreeOnTerminate := False;
  FPfx := APfx;
  FReady := AReady;
end;

procedure TServerThread.MakeHandler(Sender: TObject; out AHandler: TSocketHandler);
var
  LHandler: TTlsLibSocketHandler;
begin
  // fcl-net asks the server for a handler per accepted connection: hand it a configured one
  // carrying the server credential as an in-memory PKCS#12 (its Accept runs our server handshake
  // automatically)
  LHandler := TTlsLibSocketHandler.Create;
  LHandler.CertificateData.PFX.Value := FPfx;
  LHandler.CertificateData.KeyPassword := 'tlslib';
  FAccepted := LHandler;
  AHandler := LHandler;
end;

procedure TServerThread.HandleConnect(Sender: TObject; AStream: TSocketStream);
var
  LBuf: TBytes;
  LN: Integer;
begin
  // the handshake already ran during accept; move one line of plaintext through our records
  try
    FPeerServerName := FAccepted.PeerServerName;
    SetLength(LBuf, 1024);
    LN := AStream.Read(LBuf[0], System.Length(LBuf));
    if LN > 0 then
      AStream.Write(LBuf[0], LN); // echo it back
    // then the first bytes of a TLS record straight on the socket, and silence: the client's
    // socket timeout, not this thread's exit, must be what ends its wait
    SetLength(LBuf, 3);
    LBuf[0] := $17; LBuf[1] := $03; LBuf[2] := $03;
    fpSend(AStream.Handle, @LBuf[0], 3, 0);
    Sleep(STALL_HOLD_MS);
  except
    on E: Exception do
      FError := 'server connection: ' + E.ClassName + ': ' + E.Message;
  end;
  // we own the accepted stream in OnConnect: freeing it flushes close_notify then closes the socket
  AStream.Free;
end;

procedure TServerThread.HandleIdle(Sender: TObject);
begin
  if Terminated then
    FServer.StopAccepting(False);
end;

procedure TServerThread.Execute;
begin
  FServer := TInetServer.Create('127.0.0.1', PORT);
  try
    try
      FServer.ReuseAddress := True;
      FServer.MaxConnections := 1;
      FServer.AcceptIdleTimeout := ACCEPT_POLL_MS;
      FServer.OnIdle := HandleIdle;
      FServer.OnCreateClientSocketHandler := MakeHandler;
      FServer.OnConnect := HandleConnect;
      FServer.Listen; // bind + listen before the client is told to connect
      FReady.SetEvent;
      FServer.StartAccepting; // returns once the one connection is handled, or when terminated
    except
      on E: Exception do
      begin
        FError := 'server: ' + E.ClassName + ': ' + E.Message;
        FReady.SetEvent;
      end;
    end;
  finally
    FreeAndNil(FServer);
  end;
end;

{ TMutualServerThread }

constructor TMutualServerThread.Create(const APfx: TBytes; const ARootFile: string;
  AReady: TEvent);
begin
  inherited Create(True);
  FreeOnTerminate := False;
  FPfx := APfx;
  FRootFile := ARootFile;
  FReady := AReady;
end;

procedure TMutualServerThread.MakeHandler(Sender: TObject; out AHandler: TSocketHandler);
var
  LHandler: TTlsLibSocketHandler;
begin
  Inc(FAttempts);
  LHandler := TTlsLibSocketHandler.Create;
  LHandler.CertificateData.PFX.Value := FPfx;
  LHandler.CertificateData.KeyPassword := 'tlslib';
  // the test root vouches for clients, and a certificate is required
  LHandler.CertificateData.CertCA.FileName := FRootFile;
  LHandler.ClientAuth := TClientAuthMode.Required;
  AHandler := LHandler;
end;

procedure TMutualServerThread.HandleConnect(Sender: TObject; AStream: TSocketStream);
var
  LBuf: TBytes;
  LN: Integer;
begin
  try
    SetLength(LBuf, 64);
    LN := AStream.Read(LBuf[0], System.Length(LBuf));
    if LN > 0 then
    begin
      AStream.Write(LBuf[0], LN);
      Inc(FServed);
    end;
  except
    // a client turned away mid-handshake is the expected outcome for the no-certificate leg
  end;
  AStream.Free;
end;

procedure TMutualServerThread.HandleIdle(Sender: TObject);
begin
  if Terminated then
    FServer.StopAccepting(False);
end;

procedure TMutualServerThread.Execute;
begin
  FServer := TInetServer.Create('127.0.0.1', MUTUAL_PORT);
  try
    try
      FServer.ReuseAddress := True;
      FServer.MaxConnections := 1;
      FServer.AcceptIdleTimeout := ACCEPT_POLL_MS;
      FServer.OnIdle := HandleIdle;
      FServer.OnCreateClientSocketHandler := MakeHandler;
      FServer.OnConnect := HandleConnect;
      FServer.Listen;
      FReady.SetEvent;
      FServer.StartAccepting;
    except
      on E: Exception do
      begin
        FError := 'mutual server: ' + E.ClassName + ': ' + E.Message;
        FReady.SetEvent;
      end;
    end;
  finally
    FreeAndNil(FServer);
  end;
end;

{ TEarlyCloseServerThread }

constructor TEarlyCloseServerThread.Create(const APfx: TBytes; AReady, ASettled: TEvent);
begin
  inherited Create(True);
  FreeOnTerminate := False;
  FPfx := APfx;
  FReady := AReady;
  FSettled := ASettled;
  FSettledMs := -1;
end;

procedure TEarlyCloseServerThread.MakeHandler(Sender: TObject; out AHandler: TSocketHandler);
var
  LHandler: TTlsLibSocketHandler;
begin
  FAttemptAt := Now;
  LHandler := TTlsLibSocketHandler.Create;
  LHandler.CertificateData.PFX.Value := FPfx;
  LHandler.CertificateData.KeyPassword := 'tlslib';
  AHandler := LHandler;
end;

procedure TEarlyCloseServerThread.HandleConnect(Sender: TObject; AStream: TSocketStream);
begin
  AStream.Free;
end;

procedure TEarlyCloseServerThread.HandleIdle(Sender: TObject);
begin
  if (FAttemptAt <> 0) and (FSettledMs < 0) then
  begin
    FSettledMs := MilliSecondsBetween(Now, FAttemptAt);
    FSettled.SetEvent;
  end;
  if Terminated then
    FServer.StopAccepting(False);
end;

procedure TEarlyCloseServerThread.Execute;
begin
  FServer := TInetServer.Create('127.0.0.1', EARLY_CLOSE_PORT);
  try
    try
      FServer.ReuseAddress := True;
      FServer.AcceptIdleTimeout := ACCEPT_POLL_MS;
      FServer.OnIdle := HandleIdle;
      FServer.OnCreateClientSocketHandler := MakeHandler;
      FServer.OnConnect := HandleConnect;
      FServer.Listen;
      FReady.SetEvent;
      FServer.StartAccepting;
    except
      on E: Exception do
      begin
        FError := 'early-close server: ' + E.ClassName + ': ' + E.Message;
        FReady.SetEvent;
      end;
    end;
  finally
    FreeAndNil(FServer);
  end;
end;

{ TVerifyServerThread }

constructor TVerifyServerThread.Create(const ACertificate, APrivateKey: TBytes; APort: Integer);
begin
  inherited Create(True);
  FreeOnTerminate := False;
  FCertificate := ACertificate;
  FPrivateKey := APrivateKey;
  FPort := APort;
  FReady := TEvent.Create(nil, True, False, '');
end;

destructor TVerifyServerThread.Destroy;
begin
  inherited Destroy;
  FReady.Free;
end;

procedure TVerifyServerThread.StartListening;
begin
  Start;
  FReady.WaitFor(5000);
  if FError <> '' then
    raise Exception.Create(FError);
end;

procedure TVerifyServerThread.MakeHandler(Sender: TObject; out AHandler: TSocketHandler);
var
  LHandler: TTlsLibSocketHandler;
begin
  LHandler := TTlsLibSocketHandler.Create;
  LHandler.CertificateData.Certificate.Value := FCertificate;
  LHandler.CertificateData.PrivateKey.Value := FPrivateKey;
  AHandler := LHandler;
end;

procedure TVerifyServerThread.HandleConnect(Sender: TObject; AStream: TSocketStream);
var
  LBuf: TBytes;
  LN: Integer;
begin
  try
    SetLength(LBuf, 64);
    LN := AStream.Read(LBuf[0], System.Length(LBuf));
    if LN > 0 then
      AStream.Write(LBuf[0], LN);
  except
    // a client that left mid-exchange is not this server's failure
  end;
  AStream.Free;
end;

procedure TVerifyServerThread.HandleIdle(Sender: TObject);
begin
  if Terminated then
    FServer.StopAccepting(False);
end;

procedure TVerifyServerThread.Execute;
begin
  FServer := TInetServer.Create('127.0.0.1', FPort);
  try
    try
      FServer.ReuseAddress := True;
      FServer.AcceptIdleTimeout := ACCEPT_POLL_MS;
      FServer.OnIdle := HandleIdle;
      FServer.OnCreateClientSocketHandler := MakeHandler;
      FServer.OnConnect := HandleConnect;
      FServer.Listen;
      FReady.SetEvent;
      FServer.StartAccepting;
    except
      on E: Exception do
      begin
        FError := 'verify server: ' + E.ClassName + ': ' + E.Message;
        FReady.SetEvent;
      end;
    end;
  finally
    FreeAndNil(FServer);
  end;
end;

{ TVerifyClient }

class function TVerifyClient.Echo(const AHandler: TTlsLibSocketHandler; APort: Integer;
  out AError: string): string;
var
  LSock: TInetSocket;
  LBuf: TBytes;
  LN: Integer;
begin
  Result := '';
  AError := '';
  LSock := TInetSocket.Create('localhost', APort, AHandler);
  try
    try
      LSock.Connect;
      LSock.IOTimeout := 2000;
      LBuf := TBytes.Create(Ord('v'), Ord('e'), Ord('r'), Ord('i'), Ord('f'), Ord('y'));
      LSock.Write(LBuf[0], System.Length(LBuf));
      SetLength(LBuf, 64);
      LN := LSock.Read(LBuf[0], System.Length(LBuf));
      if LN > 0 then
        SetString(Result, PAnsiChar(@LBuf[0]), LN);
    except
      on E: Exception do
        AError := E.Message + ' ' + AHandler.LastErrorDesc;
    end;
    // a failed read reports through the handler rather than raising
    if AError = '' then
      AError := AHandler.LastErrorDesc;
  finally
    LSock.Free;
  end;
end;

class procedure TVerifyIgnoredCheck.Run;
var
  LServer: TVerifyServerThread;
  LBase: TSSLSocketHandler;
  LHandler: TTlsLibSocketHandler;
  LPreviousClass: TSSLSocketHandlerClass;
  LCrypto: ICryptoProvider;
  LPkix: IPkixProvider;
  LRootDer, LWrongRootDer: TBytes;
  LRoot, LWrongRoot, LError: string;
begin
  LRoot := TVectorLocator.WriteDer('verify_root', TVectorLocator.FieldHex('root_cert'));
  LWrongRoot := TVectorLocator.WriteDer('verify_wrong_root', TVectorLocator.FieldHex('root2_cert'));
  LRootDer := TDataEncoding.HexDecode(TVectorLocator.FieldHex('root_cert'));
  LWrongRootDer := TDataEncoding.HexDecode(TVectorLocator.FieldHex('root2_cert'));
  LCrypto := TDefaultCryptoProvider.Create as ICryptoProvider;
  LPkix := TDefaultPkixProvider.Create as IPkixProvider;
  LServer := TVerifyServerThread.Create(
    TDataEncoding.HexDecode(TVectorLocator.FieldHex('leaf_cert')),
    TDataEncoding.HexDecode(TVectorLocator.FieldHex('leaf_key')), VERIFY_PORT);
  try
    LServer.StartListening;

    // what fcl-web clients do: fetch the default handler as the base type and write False on it
    LBase := TSSLSocketHandler.GetDefaultHandler;
    LBase.VerifyPeerCert := False;
    if TVerifyClient.Echo(LBase as TTlsLibSocketHandler, VERIFY_PORT, LError) <> '' then
      raise Exception.Create('an untrusted server was served after a base-typed False');
    if Pos('no trust source was named', LError) = 0 then
      raise Exception.Create('the refusal does not say no trust source was named: ' + LError);
    if Pos(BASE_WRITE_HINT, LError) = 0 then
      raise Exception.Create('the refusal does not carry the base-write hint: ' + LError);

    LBase := TSSLSocketHandler.GetDefaultHandler;
    LBase.VerifyPeerCert := False;
    LBase.CertificateData.CertCA.FileName := LWrongRoot;
    if TVerifyClient.Echo(LBase as TTlsLibSocketHandler, VERIFY_PORT, LError) <> '' then
      raise Exception.Create('a server outside the pinned root was served after a base-typed False');
    if Pos(UNTRUSTED_CHAIN, LError) = 0 then
      raise Exception.Create('the refusal is not a chain failure: ' + LError);
    if Pos(BASE_WRITE_HINT, LError) = 0 then
      raise Exception.Create('the chain refusal does not carry the base-write hint: ' + LError);

    LBase := TSSLSocketHandler.GetDefaultHandler;
    LBase.VerifyPeerCert := False;
    LBase.CertificateData.CertCA.FileName := LRoot;
    if TVerifyClient.Echo(LBase as TTlsLibSocketHandler, VERIFY_PORT, LError) <> 'verify' then
      raise Exception.Create('a server under the pinned root was not served: ' + LError);

    // a user class registered as the default is reached the same way
    LPreviousClass := TSSLSocketHandler.GetDefaultHandlerClass;
    TSSLSocketHandler.SetDefaultHandlerClass(TVerifySubclassHandler);
    try
      LBase := TSSLSocketHandler.GetDefaultHandler;
      LBase.VerifyPeerCert := False;
      if TVerifyClient.Echo(LBase as TTlsLibSocketHandler, VERIFY_PORT, LError) <> '' then
        raise Exception.Create('an untrusted server was served to a registered subclass');
      if Pos('no trust source was named', LError) = 0 then
        raise Exception.Create('the subclass refusal does not say no trust source was named: ' +
          LError);
    finally
      TSSLSocketHandler.SetDefaultHandlerClass(LPreviousClass);
    end;

    // a config supplied on the default handler is not in conflict with the base-typed False
    LBase := TSSLSocketHandler.GetDefaultHandler;
    LBase.VerifyPeerCert := False;
    (LBase as TTlsLibSocketHandler).ClientConfig := TTlsPresets.Compatible(LCrypto, LPkix).Client
      .WithServerVerification(TServerVerification.WebPki(LRootDer).Build).Build;
    if TVerifyClient.Echo(LBase as TTlsLibSocketHandler, VERIFY_PORT, LError) <> 'verify' then
      raise Exception.Create('a supplied client config was not served: ' + LError);

    // the config decides, so a refusal under it is not blamed on the base-typed write
    LBase := TSSLSocketHandler.GetDefaultHandler;
    LBase.VerifyPeerCert := False;
    (LBase as TTlsLibSocketHandler).ClientConfig := TTlsPresets.Compatible(LCrypto, LPkix).Client
      .WithServerVerification(TServerVerification.WebPki(LWrongRootDer).Build).Build;
    if TVerifyClient.Echo(LBase as TTlsLibSocketHandler, VERIFY_PORT, LError) <> '' then
      raise Exception.Create('a server outside the supplied config''s root was served');
    if (LError = '') or (Pos(BASE_WRITE_HINT, LError) > 0) then
      raise Exception.Create('the refusal under a supplied config is missing or carries the hint: ' +
        LError);

    // a failure unrelated to trust is not blamed on the base-typed write once the user set False
    LBase := TSSLSocketHandler.GetDefaultHandler;
    LBase.VerifyPeerCert := False;
    LHandler := LBase as TTlsLibSocketHandler;
    LHandler.VerifyPeerCert := False;
    LHandler.SSLType := stSSLv3;
    if TVerifyClient.Echo(LHandler, VERIFY_PORT, LError) <> '' then
      raise Exception.Create('a pinned unsupported protocol version was served');
    if (Pos('SSLType', LError) = 0) or (Pos(BASE_WRITE_HINT, LError) > 0) then
      raise Exception.Create('the version refusal is missing or carries the hint: ' + LError);
  finally
    LServer.Terminate;
    LServer.Free;
  end;
end;

{ TVerifyHonouredCheck }

class procedure TVerifyHonouredCheck.Run;
var
  LServer: TVerifyServerThread;
  LHandler: TTlsLibSocketHandler;
  LError: string;
begin
  LServer := TVerifyServerThread.Create(
    TDataEncoding.HexDecode(TVectorLocator.FieldHex('leaf_cert')),
    TDataEncoding.HexDecode(TVectorLocator.FieldHex('leaf_key')), VERIFY_PORT);
  try
    LServer.StartListening;

    // the default handler is one of ours, and a False set through our type is the bypass
    LHandler := TSSLSocketHandler.GetDefaultHandler as TTlsLibSocketHandler;
    LHandler.VerifyPeerCert := False;
    if TVerifyClient.Echo(LHandler, VERIFY_PORT, LError) <> 'verify' then
      raise Exception.Create('the default handler did not skip under its own False: ' + LError);

    LHandler := TTlsLibSocketHandler.Create;
    LHandler.VerifyPeerCert := False;
    if TVerifyClient.Echo(LHandler, VERIFY_PORT, LError) <> 'verify' then
      raise Exception.Create('a handler with VerifyPeerCert False did not skip: ' + LError);

    // a handler nobody touched verifies, and its refusal is not blamed on a reset
    LHandler := TTlsLibSocketHandler.Create;
    if TVerifyClient.Echo(LHandler, VERIFY_PORT, LError) <> '' then
      raise Exception.Create('an untrusted server was served to an untouched handler');
    if Pos('no trust source was named', LError) = 0 then
      raise Exception.Create('the refusal does not say no trust source was named: ' + LError);
    if Pos(BASE_WRITE_HINT, LError) > 0 then
      raise Exception.Create('an untouched handler''s refusal carries the hint: ' + LError);

    // the property is published, so a write by name reaches it
    LHandler := TTlsLibSocketHandler.Create;
    SetOrdProp(LHandler, 'VerifyPeerCert', 0);
    if TVerifyClient.Echo(LHandler, VERIFY_PORT, LError) <> 'verify' then
      raise Exception.Create('a write of VerifyPeerCert by name was not honoured: ' + LError);
  finally
    LServer.Terminate;
    LServer.Free;
  end;
end;

{ TSelfSignedLeafCheck }

class procedure TSelfSignedLeafCheck.Run;
var
  LServer: TVerifyServerThread;
  LHandler: TTlsLibSocketHandler;
  LSelfLeaf, LError: string;
begin
  LSelfLeaf := TVectorLocator.WriteDer('verify_self_leaf',
    TVectorLocator.FieldHex('otherhost_cert'));
  LServer := TVerifyServerThread.Create(
    TDataEncoding.HexDecode(TVectorLocator.FieldHex('otherhost_cert')),
    TDataEncoding.HexDecode(TVectorLocator.FieldHex('otherhost_key')), VERIFY_SELF_PORT);
  try
    LServer.StartListening;

    // the two handlers differ in CheckHostName alone
    LHandler := TTlsLibSocketHandler.Create;
    LHandler.CertificateData.TrustedCertificate.FileName := LSelfLeaf;
    LHandler.CheckHostName := False;
    if TVerifyClient.Echo(LHandler, VERIFY_SELF_PORT, LError) <> 'verify' then
      raise Exception.Create('a trusted self-signed leaf was not served: ' + LError);

    // the CA slot an fcl-web client fills from CertCAFileName takes the leaf the same way
    LHandler := TTlsLibSocketHandler.Create;
    LHandler.CertificateData.CertCA.FileName := LSelfLeaf;
    LHandler.CheckHostName := False;
    if TVerifyClient.Echo(LHandler, VERIFY_SELF_PORT, LError) <> 'verify' then
      raise Exception.Create('a self-signed leaf in the CA slot was not served: ' + LError);

    LHandler := TTlsLibSocketHandler.Create;
    LHandler.CertificateData.TrustedCertificate.FileName := LSelfLeaf;
    if TVerifyClient.Echo(LHandler, VERIFY_SELF_PORT, LError) <> '' then
      raise Exception.Create('a trusted leaf was served under a host it does not name');
    // the core reports a rejected name as it reports any rejected certificate
    if Pos(UNTRUSTED_CHAIN, LError) = 0 then
      raise Exception.Create('the refusal of a leaf under a host it does not name: ' + LError);
  finally
    LServer.Terminate;
    LServer.Free;
  end;
end;

{ TEarlyCloseCheck }

class procedure TEarlyCloseCheck.Run;
var
  LServer: TEarlyCloseServerThread;
  LReady, LSettled: TEvent;
  LSock: TInetSocket;
begin
  LReady := TEvent.Create(nil, True, False, '');
  LSettled := TEvent.Create(nil, True, False, '');
  try
    LServer := TEarlyCloseServerThread.Create(
      TDataEncoding.HexDecode(TVectorLocator.FieldHex('leaf_pfx')), LReady, LSettled);
    try
      LServer.Start;
      LReady.WaitFor(5000);
      if LServer.Error <> '' then
        raise Exception.Create(LServer.Error);
      LSock := TInetSocket.Create('127.0.0.1', EARLY_CLOSE_PORT);
      LSock.Free;
      if LSettled.WaitFor(10000) <> wrSignaled then
        raise Exception.Create('the server never finished its accept of an early-closed client ' +
          LServer.Error);
      if LServer.SettledMs > EARLY_CLOSE_LIMIT_MS then
        raise Exception.CreateFmt('the server took %d ms to give up on a client that closed ' +
          'before its ClientHello', [LServer.SettledMs]);
    finally
      LServer.Terminate;
      LServer.Free;
    end;
  finally
    LSettled.Free;
    LReady.Free;
  end;
end;

{ TMutualTlsCheck }

class function TMutualTlsCheck.Echo(const APfx: TBytes; const ARootFile: string;
  AWithIdentity: Boolean; out AError: string): string;
var
  LSock: TInetSocket;
  LHandler: TTlsLibSocketHandler;
  LBuf: TBytes;
  LN: Integer;
begin
  Result := '';
  AError := '';
  LHandler := TTlsLibSocketHandler.Create;
  LHandler.CertificateData.CertCA.FileName := ARootFile;
  if AWithIdentity then
  begin
    LHandler.CertificateData.PFX.Value := APfx;
    LHandler.CertificateData.KeyPassword := 'tlslib';
  end;
  LSock := TInetSocket.Create('localhost', MUTUAL_PORT, LHandler);
  try
    try
      LSock.Connect;
      LSock.IOTimeout := 2000;
      if AWithIdentity then
      begin
        LBuf := TBytes.Create(Ord('m'), Ord('u'), Ord('t'), Ord('u'), Ord('a'), Ord('l'));
        LSock.Write(LBuf[0], System.Length(LBuf));
      end;
      SetLength(LBuf, 64);
      // TLS 1.3 lets the client finish before the server judges its certificate: the answer is
      // the echo, which a rejected client never gets
      LN := LSock.Read(LBuf[0], System.Length(LBuf));
      if LN > 0 then
        SetString(Result, PAnsiChar(@LBuf[0]), LN);
    except
      on E: Exception do
        AError := E.Message + ' ' + LHandler.LastErrorDesc;
    end;
    // a failed read reports through the handler rather than raising
    if AError = '' then
      AError := LHandler.LastErrorDesc;
  finally
    LSock.Free;
  end;
end;

class function TMutualTlsCheck.RefusesTwoSources(const APfx: TBytes;
  const ARootFile: string): Boolean;
var
  LHandler: TTlsLibSocketHandler;
begin
  LHandler := TTlsLibSocketHandler.Create;
  try
    LHandler.CertificateData.CertCA.FileName := ARootFile;
    LHandler.CertificateData.PFX.Value := APfx;
    LHandler.CertificateData.Certificate.FileName := ARootFile;
    LHandler.Connect;
    Result := Pos('sets PFX together with Certificate', LHandler.LastErrorDesc) > 0;
  finally
    LHandler.Free;
  end;
end;

class procedure TMutualTlsCheck.Run;
var
  LServer: TMutualServerThread;
  LReady: TEvent;
  LPfx: TBytes;
  LRoot, LError: string;
begin
  LPfx := TDataEncoding.HexDecode(TVectorLocator.FieldHexFrom('ClientAuthChain.txt', 'leaf_pfx'));
  LRoot := TVectorLocator.WriteDer('mutual_root',
    TVectorLocator.FieldHexFrom('ClientAuthChain.txt', 'root_cert'));
  LReady := TEvent.Create(nil, True, False, '');
  try
    LServer := TMutualServerThread.Create(LPfx, LRoot, LReady);
    try
      LServer.Start;
      LReady.WaitFor(5000);
      if LServer.Error <> '' then
        raise Exception.Create(LServer.Error);
      if not RefusesTwoSources(LPfx, LRoot) then
        raise Exception.Create('a PFX beside a Certificate was not refused naming both');
      if Echo(LPfx, LRoot, False, LError) <> '' then
        raise Exception.Create('a client with no certificate was served');
      // the rejection is the peer's alert, not a timeout or a refused connection
      if Pos('the peer sent a fatal alert', LError) = 0 then
        raise Exception.Create('the client with no certificate was not sent an alert: ' + LError);
      if LServer.Attempts <> 1 then
        raise Exception.Create('the client with no certificate never reached the server');
      if Echo(LPfx, LRoot, True, LError) <> 'mutual' then
        raise Exception.Create('a client presenting the PFX identity was not served: ' + LError);
      LServer.WaitFor;
      if LServer.Error <> '' then
        raise Exception.Create(LServer.Error);
      if LServer.Served <> 1 then
        raise Exception.CreateFmt('the server served %d clients, expected 1', [LServer.Served]);
      if LServer.Attempts <> 2 then
        raise Exception.CreateFmt('the server saw %d connections, expected 2', [LServer.Attempts]);
    finally
      LServer.Terminate;
      LServer.Free;
    end;
  finally
    LReady.Free;
  end;
end;

{ TFclNetLoopbackExample }

class function TFclNetLoopbackExample.VersionText(const AVersion: TTlsVersion): string;
begin
  case AVersion.WireValue of
    TlsWireVersionTls13:
      Result := 'TLSv1.3';
    TlsWireVersionTls12:
      Result := 'TLSv1.2';
  else
    Result := 'unknown';
  end;
end;

class function TFclNetLoopbackExample.Run: Integer;
var
  LServer: TServerThread;
  LSock: TInetSocket;
  LHandler: TTlsLibSocketHandler;
  LReady: TEvent;
  LRoot, LEcho, LVersion: string;
  LOut: AnsiString;
  LBuf: TBytes;
  LN: Integer;
  LStart: TDateTime;
  LStallMs: Int64;
begin
  Result := 1;
  LEcho := '';
  LVersion := '';
  TVectorLocator.Locate;
  LReady := TEvent.Create(nil, True, False, '');
  try
    LRoot := TVectorLocator.WriteDer('root', TVectorLocator.FieldHex('root_cert'));

    LServer := TServerThread.Create(TDataEncoding.HexDecode(TVectorLocator.FieldHex('leaf_pfx')),
      LReady);
    try
      LServer.Start;
      LReady.WaitFor(5000);
      if LServer.Error <> '' then
        raise Exception.Create(LServer.Error);

      // the client: 'localhost' resolves to 127.0.0.1 (IPv4) and is also the name we verify the
      // leaf's SAN against; the pinned root is the trust source (fail-closed without one)
      LHandler := TTlsLibSocketHandler.Create;
      LHandler.CertificateData.CertCA.FileName := LRoot; // pinned root (verification is on by default)
      // no SNI on the wire, yet the leaf is still verified for 'localhost' (SendHostAsSNI is wire-only)
      LHandler.SendHostAsSNI := False;
      // the client offers one suite, so a negotiated AES-256 proves the list was honoured
      LHandler.CertificateData.CipherList := 'TLS_AES_256_GCM_SHA384';
      LSock := TInetSocket.Create('localhost', PORT, LHandler); // handler set => no auto-connect
      try
        try
          LSock.Connect; // TCP connect + our TLS handshake
        except
          // TInetSocket raises a generic connect error when our handshake refuses; surface why
          on E: ESocketError do
            raise Exception.Create('handshake failed: ' + LHandler.LastErrorDesc);
        end;
        LVersion := VersionText(LHandler.NegotiatedVersion); // read before LSock.Free drops the handler
        if LHandler.NegotiatedCipherSuite <> TCipherSuites13.Aes256GcmSha384 then
          raise Exception.CreateFmt('the CipherList was not honoured (suite $%.4x)',
            [LHandler.NegotiatedCipherSuite]);
        LOut := AnsiString(PING);
        LSock.Write(LOut[1], System.Length(LOut));
        SetLength(LBuf, 1024);
        LN := LSock.Read(LBuf[0], System.Length(LBuf));
        if LN > 0 then
          SetString(LEcho, PAnsiChar(@LBuf[0]), LN);
        // the server now sends part of a record and stalls: the socket timeout must bound the read
        LSock.IOTimeout := READ_CAP_MS;
        LStart := Now;
        LN := LSock.Read(LBuf[0], System.Length(LBuf));
        LStallMs := MilliSecondsBetween(Now, LStart);
        if (LN >= 0) or (LStallMs > STALL_LIMIT_MS) then
          raise Exception.CreateFmt('a stalled record was not bounded by IOTimeout (%d ms, read %d)',
            [LStallMs, LN]);
      finally
        LSock.Free; // frees the handler, flushes close_notify, closes the socket
      end;

      LServer.WaitFor;
      if LServer.Error <> '' then
        raise Exception.Create(LServer.Error);
      if LServer.PeerServerName <> '' then
        raise Exception.Create('the server saw an SNI though SendHostAsSNI was False: ' +
          LServer.PeerServerName);
      TMutualTlsCheck.Run;
      TEarlyCloseCheck.Run;
      TVerifyIgnoredCheck.Run;
      TVerifyHonouredCheck.Run;
      TSelfSignedLeafCheck.Run;
    finally
      LServer.Terminate;
      LServer.Free;
    end;

    if LEcho = PING then
    begin
      WriteLn('FclNet loopback PASS: ', LVersion, ' handshake + echo + a stalled record bounded in ',
        LStallMs, ' ms + client PFX identity authenticated + a reset VerifyPeerCert still verifies');
      Result := 0;
    end
    else
      WriteLn('FclNet loopback FAIL: echo="', LEcho, '"');
  except
    on E: Exception do
      WriteLn('FclNet loopback FAIL: ', E.ClassName, ': ', E.Message);
  end;
  LReady.Free;
end;

end.
