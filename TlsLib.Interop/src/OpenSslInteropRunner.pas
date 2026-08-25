{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit OpenSslInteropRunner;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

interface

uses
  SysUtils,
  Classes,
  TlpICryptoProvider,
  TlpTlsCredential,
  TlpNegotiationTypes,
  TlpISession,
  TlpSessionTicketKeys,
  TlpInMemorySessionCache,
  TlpITlsEngine,
  InteropSocket,
  InteropEngine,
  InteropCredentials,
  InteropPump,
  InteropUtils;

type
  /// <summary>
  /// Drives our engine against an openssl s_client / s_server peer over loopback,
  /// for the always-on lighter interop matrix. As the server it presents the EC
  /// P-256 test credential and echoes application data back verbatim; as the client
  /// it trusts a supplied CA/self-signed PEM, sends a line, and verifies the echo.
  /// The peer (openssl) is launched by the matrix script in the opposite role.
  /// </summary>
  TOpenSslInteropRunner = class sealed(TObject)
  strict private
    class function ArgValue(const AName: string; const ADefault: string): string; static;
    /// <summary>Maps a comma-separated list of group names (e.g. "X25519,X25519MLKEM768")
    /// to their IANA codepoints; the first is the most-preferred / key_share group.</summary>
    class function ParseGroups(const ASpec: string): TArray<UInt16>; static;
    class function RunServer(APort: Word; const ACredential: TTlsCredential;
      const AOcspStaple: TBytes; AAcceptCount: Int32;
      const AStek: ISessionTicketKeyManager;
      const AOfferedGroups: TArray<UInt16>): Int32; static;
    class function RunClient(APort: Word; const AHost, ACaPemFile, AMessage,
      AClientCredFile: string; AConnectionCount: Int32;
      const AOfferedGroups: TArray<UInt16>): Int32; static;
    /// <summary>One client connection over ASocket, using AOptions; returns 0 on a
    /// completed handshake + echoed application data.</summary>
    class function RunOneClient(const ASocket: TInteropSocket;
      const AProvider: ICryptoProvider; const AOptions: TInteropEngineOptions;
      const AMessage: string): Int32; static;
  public
    /// <summary>Parses --role/--port/... and runs one exchange; returns the exit code.</summary>
    class function Run: Int32; static;
  end;

implementation

{ TOpenSslInteropRunner }

class function TOpenSslInteropRunner.ArgValue(const AName: string;
  const ADefault: string): string;
var
  LI: Int32;
begin
  Result := ADefault;
  for LI := 1 to ParamCount - 1 do
    if ParamStr(LI) = AName then
      Exit(ParamStr(LI + 1));
end;

class function TOpenSslInteropRunner.ParseGroups(const ASpec: string): TArray<UInt16>;
var
  LNames: TStringList;
  LI: Int32;
  LCode: UInt16;
begin
  Result := nil;
  if Trim(ASpec) = '' then
    Exit;
  LNames := TStringList.Create;
  try
    LNames.StrictDelimiter := True;
    LNames.Delimiter := ',';
    LNames.DelimitedText := ASpec;
    for LI := 0 to LNames.Count - 1 do
    begin
      if not TNamedGroupCatalog.TryCode(Trim(LNames[LI]), LCode) then
        raise Exception.CreateFmt('unknown group name: %s', [LNames[LI]]);
      SetLength(Result, System.Length(Result) + 1);
      Result[System.High(Result)] := LCode;
    end;
  finally
    LNames.Free;
  end;
end;

class function TOpenSslInteropRunner.RunServer(APort: Word;
  const ACredential: TTlsCredential; const AOcspStaple: TBytes;
  AAcceptCount: Int32; const AStek: ISessionTicketKeyManager;
  const AOfferedGroups: TArray<UInt16>): Int32;
var
  LListener: TInteropListener;
  LSocket: TInteropSocket;
  LProvider: ICryptoProvider;
  LOptions: TInteropEngineOptions;
  LEngine: ITlsEngine;
  LResult: TInteropResult;
  LConn: Int32;
begin
  Result := 1;
  LProvider := TInteropEngine.DefaultProvider;
  LListener := TInteropListener.Bind('127.0.0.1', APort);
  try
    Writeln('listening on 127.0.0.1:', LListener.Port);
    Flush(Output);
    // accept one connection per exchange; a resumption run (AStek set) accepts several
    // over one shared STEK, so a later connection resumes an earlier one
    for LConn := 1 to AAcceptCount do
    begin
      LSocket := LListener.Accept;
      try
        LOptions := Default(TInteropEngineOptions);
        LOptions.Role := TInteropRole.Server;
        LOptions.HasCredential := True;
        LOptions.Credential := ACredential;
        LOptions.OcspStaple := AOcspStaple;
        LOptions.SessionTicketKeys := AStek;
        LOptions.OfferedGroups := AOfferedGroups;
        LEngine := TInteropEngine.Build(LProvider, LOptions);

        LResult := TInteropPump.DriveHandshake(LEngine, LSocket);
        if LResult.Status <> TInteropStatus.Ok then
        begin
          Writeln(ErrOutput, 'server handshake failed: ', LResult.Detail);
          Exit(1);
        end;
        Writeln('handshake complete; echoing');
        repeat
          LResult := TInteropPump.PumpAppData(LEngine, LSocket);
          if System.Length(LResult.Data) > 0 then
            TInteropPump.WriteAppData(LEngine, LSocket, LResult.Data);
        until LResult.Status <> TInteropStatus.Ok;
        if not (LResult.Status in [TInteropStatus.PeerClosed,
          TInteropStatus.TransportEof]) then
        begin
          Writeln(ErrOutput, 'server ended abnormally: ', LResult.Detail);
          Exit(1);
        end;
      finally
        LSocket.Free;
      end;
    end;
    Result := 0;
  finally
    LListener.Free;
  end;
end;

class function TOpenSslInteropRunner.RunClient(APort: Word; const AHost,
  ACaPemFile, AMessage, AClientCredFile: string; AConnectionCount: Int32;
  const AOfferedGroups: TArray<UInt16>): Int32;
var
  LSocket: TInteropSocket;
  LProvider: ICryptoProvider;
  LOptions: TInteropEngineOptions;
  LCache: ISessionCache;
  LConn: Int32;
begin
  Result := 1;
  LProvider := TInteropEngine.DefaultProvider;
  // one shared cache carries a ticket from an earlier connection so a later one resumes it
  LCache := nil;
  if AConnectionCount > 1 then
    LCache := TInMemorySessionCache.Create as ISessionCache;

  LOptions := Default(TInteropEngineOptions);
  LOptions.Role := TInteropRole.Client;
  LOptions.ServerName := AHost;
  LOptions.CheckServerName := True;
  LOptions.Trust := TInteropCredentials.TrustFromPem(LProvider, ACaPemFile);
  LOptions.SessionCache := LCache;
  LOptions.OfferedGroups := AOfferedGroups;
  // mutual TLS: present a client credential when the server requests one
  if AClientCredFile <> '' then
  begin
    LOptions.HasCredential := True;
    LOptions.Credential :=
      TInteropCredentials.ServerCredentialFromFieldFile(LProvider, AClientCredFile);
  end;

  for LConn := 1 to AConnectionCount do
  begin
    LSocket := TInteropSocket.Connect(AHost, APort);
    try
      Result := RunOneClient(LSocket, LProvider, LOptions, AMessage);
    finally
      LSocket.Free;
    end;
    if Result <> 0 then
      Exit;
  end;
end;

class function TOpenSslInteropRunner.RunOneClient(const ASocket: TInteropSocket;
  const AProvider: ICryptoProvider; const AOptions: TInteropEngineOptions;
  const AMessage: string): Int32;
var
  LEngine: ITlsEngine;
  LResult: TInteropResult;
  LSent, LGot: TBytes;
  LI: Int32;
begin
  Result := 1;
  LEngine := TInteropEngine.Build(AProvider, AOptions);

  LEngine.StartHandshake;
  LResult := TInteropPump.DriveHandshake(LEngine, ASocket);
  if LResult.Status <> TInteropStatus.Ok then
  begin
    Writeln(ErrOutput, 'client handshake failed: ', LResult.Detail);
    Exit(1);
  end;
  Writeln('handshake complete; sending');

  // a trailing newline lets a line-oriented openssl peer (s_server -rev) flush
  LSent := nil;
  SetLength(LSent, System.Length(AMessage) + 1);
  for LI := 1 to System.Length(AMessage) do
    LSent[LI - 1] := Byte(Ord(AMessage[LI]));
  LSent[System.High(LSent)] := 10;
  TInteropPump.WriteAppData(LEngine, ASocket, LSent);

  // read past any post-handshake records (NewSessionTicket) until the echo arrives
  LGot := nil;
  for LI := 0 to 7 do
  begin
    LResult := TInteropPump.PumpAppData(LEngine, ASocket);
    if System.Length(LResult.Data) > 0 then
    begin
      LGot := LResult.Data;
      Break;
    end;
    if LResult.Status <> TInteropStatus.Ok then
      Break;
  end;
  if System.Length(LGot) > 0 then
  begin
    Writeln('received ', System.Length(LGot), ' bytes back');
    Result := 0;
  end
  else
  begin
    Writeln(ErrOutput, 'client received no application data back');
    Result := 1;
  end;
  TInteropPump.Close(LEngine, ASocket);
end;

class function TOpenSslInteropRunner.Run: Int32;
var
  LRole, LStapleField: string;
  LPort: Word;
  LDataDir, LCredentialFile: string;
  LResumeCount: Int32;
  LStek: ISessionTicketKeyManager;
  LProvider: ICryptoProvider;
  LCredential: TTlsCredential;
  LStaple: TBytes;
  LFields: TStringList;
  LOfferedGroups: TArray<UInt16>;
begin
  LRole := ArgValue('--role', 'server');
  LPort := Word(StrToIntDef(ArgValue('--port', '0'), 0));
  LDataDir := ArgValue('--data-dir', '');
  if LDataDir = '' then
    LDataDir := TInteropUtils.LocateDataDir;
  LCredentialFile := LDataDir + PathDelim + 'Certs' + PathDelim + 'EcP256Chain.txt';
  // a resumption run serves ResumeCount+1 connections over one STEK (the peer's s_client
  // saves the session on the first and resumes it on the next)
  LResumeCount := StrToIntDef(ArgValue('--resume-count', '0'), 0);
  // --ocsp-staple names a field in Certs/OcspStapling.txt; when set the server serves the
  // leaf+issuer chain and staples that OCSP response
  LStapleField := ArgValue('--ocsp-staple', '');

  try
    // --groups names the offered named groups (comma-separated, most-preferred first); the
    // first is the key_share group, so "X25519,X25519MLKEM768" forces an HRR onto the hybrid
    LOfferedGroups := ParseGroups(ArgValue('--groups', ''));
    if LRole = 'client' then
      // --resume-count on a client means it makes ResumeCount+1 connections over one
      // shared cache, resuming a prior session on the later ones
      Result := RunClient(LPort, ArgValue('--host', 'localhost'),
        ArgValue('--ca', ''), ArgValue('--message', 'openssl interop hello'),
        ArgValue('--client-cred', ''), LResumeCount + 1, LOfferedGroups)
    else
    begin
      LStek := nil;
      if LResumeCount > 0 then
        LStek := TStekTicketKeyManager.Create(TInteropEngine.DefaultProvider.Primitives.GetRandom)
          as ISessionTicketKeyManager;
      LProvider := TInteropEngine.DefaultProvider;
      LStaple := nil;
      if LStapleField <> '' then
      begin
        LCredentialFile := LDataDir + PathDelim + 'Certs' + PathDelim +
          'OcspStapling.txt';
        LCredential := TInteropCredentials.ServerStaplingCredentialFromFieldFile(
          LProvider, LCredentialFile);
        LFields := TStringList.Create;
        try
          TInteropUtils.LoadFieldFile(LCredentialFile, LFields);
          LStaple := TInteropUtils.DecodeHex(LFields.Values[LStapleField]);
        finally
          LFields.Free;
        end;
      end
      else
        LCredential := TInteropCredentials.ServerCredentialFromFieldFile(
          LProvider, LCredentialFile);
      Result := RunServer(LPort, LCredential, LStaple, LResumeCount + 1, LStek,
        LOfferedGroups);
    end;
  except
    on E: Exception do
    begin
      Writeln(ErrOutput, E.ClassName, ': ', E.Message);
      Result := 1;
    end;
  end;
end;

end.
