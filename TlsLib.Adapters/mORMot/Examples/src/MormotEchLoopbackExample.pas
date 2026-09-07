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
/// An Encrypted Client Hello (RFC 9849) loopback over mORMot's socket seam on 127.0.0.1. One ECH
/// key pair is generated in-process: the server loads its PEM into an ECH key store, the client
/// offers the matching ECHConfigList. Both are installed process-wide through
/// SetTlsLibMormotServerConfig/SetTlsLibMormotClientConfig (the mORMot config-in hatch). Each end
/// is created as the concrete TTlsLibNetTls (used via INetTls for the handshake) so its EchStatus
/// can be read, and both assert EchStatus = Accepted - proving the ECH path through the mORMot
/// adapter end to end. Shared by the FreePascal and Delphi example programs.
/// </summary>
unit MormotEchLoopbackExample;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

interface

type
  TMormotEchLoopbackExample = class sealed(TObject)
  public
    /// <summary>Runs the ECH loopback; returns 0 on success, 1 on failure.</summary>
    class function Run: Integer; static;
  end;

implementation

uses
  SysUtils,
  Classes,
  SyncObjs,
  mormot.core.base,
  mormot.net.sock,
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
  TlsLibMormotTls;

const
  PORT = '28453';
  HOST = '127.0.0.1';
  PING = 'ping from the mormot ech client';
  PUBLIC_NAME = 'cover.example';
  INNER_HOST = 'localhost';

var
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
  LListener, LClient: TNetSocket;
  LAddr: TNetAddr;
  LCtx: TNetTlsContext;
  LConcrete: TTlsLibNetTls;
  LTls: INetTls;
  LLastErr, LCipher: RawUtf8;
  LBuf: TBytes;
  LLen: Integer;
begin
  try
    // the server credential + ECH key store ride on the process-wide ServerConfig, so the
    // context carries no cert/trust fields
    FillCharFast(LCtx, SizeOf(LCtx), 0);
    if NewSocket(HOST, PORT, nlTcp, {dobind=}True, 3000, 3000, 3000, 0,
      LListener) <> nrOK then
      raise Exception.Create('server bind failed');
    GReady.SetEvent;
    if LListener.Accept(LClient, LAddr, {async=}False) <> nrOK then
      raise Exception.Create('accept failed');
    LConcrete := TTlsLibNetTls.Create;
    LTls := LConcrete; // used via INetTls; the interface owns it
    LTls.AfterAccept(LClient, LCtx, @LLastErr, @LCipher);
    GServerEch := LConcrete.EchStatus; // handshake done; capture before the echo
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

{ TMormotEchLoopbackExample }

class function TMormotEchLoopbackExample.Run: Integer;
var
  LProvider: ICryptoProvider;
  LEch: TEchKeyGenResult;
  LServerBuilder: ITlsServerConfigBuilder;
  LClientBuilder: ITlsClientConfigBuilder;
  LServer: TServerThread;
  LCtx: TNetTlsContext;
  LSock: TNetSocket;
  LConcrete: TTlsLibNetTls;
  LTls: INetTls;
  LClientEch: TEchStatus;
  LPing, LEcho: TBytes;
  LLen, LI: Integer;
  LOk: Boolean;
begin
  Result := 1;
  GServerError := '';
  GServerEch := TEchStatus.NotOffered;
  TVec.Locate;
  LProvider := TDefaultCryptoProvider.Create as ICryptoProvider;

  LEch := TEchKeyGenerator.Generate(LProvider, PUBLIC_NAME, 1,
    THpkeKem.DHKEM_X25519_HKDF_SHA256, THpkeKdf.HKDF_SHA256,
    THpkeAead.AES_128_GCM, 0);

  // build and install each config fully before starting the next builder (a Compatible builder
  // is endpoint-chosen once), then install them process-wide (the mORMot config-in hatch)
  LServerBuilder := TTlsPresets.Compatible(LProvider).Server
    .WithCredential(TVec.Bytes('leaf_cert'), TVec.Bytes('leaf_key'), '');
  LServerBuilder.Tls13.WithEchKeyStore(
    TInMemoryEchKeyStore.FromPem(LEch.Pem, LProvider));
  LServerBuilder.Tls13.WithEchTrialDecrypt(True);
  SetTlsLibMormotServerConfig(LServerBuilder.Build);

  LClientBuilder := TTlsPresets.Compatible(LProvider).Client
    .WithTrustAnchors(TVec.Bytes('root_cert'));
  LClientBuilder.WithNameCheck(True);
  LClientBuilder.Tls13.WithEncryptedClientHello(LEch.EchConfigList);
  SetTlsLibMormotClientConfig(LClientBuilder.Build);

  GReady := TEvent.Create(nil, True, False, '');
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
    LConcrete := TTlsLibNetTls.Create;
    LTls := LConcrete;
    // connect to 127.0.0.1 but the inner SNI (verified against the leaf's SAN) is 'localhost'
    LTls.AfterConnection(LSock, LCtx, INNER_HOST);
    LClientEch := LConcrete.EchStatus;

    LPing := nil;
    SetLength(LPing, System.Length(PING));
    for LI := 1 to System.Length(PING) do
      LPing[LI - 1] := Byte(Ord(PING[LI]));
    LLen := System.Length(LPing);
    LTls.Send(@LPing[0], LLen);
    SetLength(LEcho, 4096);
    LLen := System.Length(LEcho);
    LTls.Receive(@LEcho[0], LLen);

    LServer.WaitFor;
    if GServerError <> '' then
      raise Exception.Create('server: ' + GServerError);

    LOk := (LLen = System.Length(LPing)) and CompareMem(@LEcho[0], @LPing[0], LLen)
      and (LClientEch = TEchStatus.Accepted) and (GServerEch = TEchStatus.Accepted);
    if LOk then
    begin
      Writeln('mORMot ECH loopback PASS: handshake + echo, ECH accepted on both sides');
      Result := 0;
    end
    else
      Writeln('mORMot ECH loopback FAIL: clientEch=', Ord(LClientEch),
        ' serverEch=', Ord(GServerEch));
    LServer.Free;
  except
    on E: Exception do
      Writeln('mORMot ECH loopback FAIL: ', E.ClassName, ': ', E.Message);
  end;
  // clear the process-wide configs so no state leaks past the example
  SetTlsLibMormotClientConfig(nil);
  SetTlsLibMormotServerConfig(nil);
  GReady.Free;
end;

end.
