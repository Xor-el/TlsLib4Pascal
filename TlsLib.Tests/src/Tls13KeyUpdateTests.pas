{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit Tls13KeyUpdateTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  Classes,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  TlpICertificateTrust,
  TlpCertificateVerifier,
  TlpTlsCredential,
  TlpTlsPresets,
  TlpTlsEngineFactory,
  TlpITlsEngine,
  TlsLibTestBase;

type
  TTestTls13KeyUpdate = class(TTlsLibAlgorithmTestCase)
  private
  const
    ServerHost = 'localhost';
  var
    FCerts: TStringList;
    function ServerCredential: TTlsCredential;
    function ClientTrust: ITrustAnchorStore;
    function NewClient: ITlsEngine;
    function NewServer: ITlsEngine;
    function Drain(const AEngine: ITlsEngine): TBytes;
    procedure Feed(const AEngine: ITlsEngine; const AWire: TBytes);
    procedure Pump(const ASrc, ADst: ITlsEngine);
    procedure Exchange(const AClient, AServer: ITlsEngine);
    function ReadAllApp(const AEngine: ITlsEngine): TBytes;
    /// <summary>Drains the event queue and counts the KeyUpdateReceived events.</summary>
    function CountKeyUpdateEvents(const AEngine: ITlsEngine): Int32;
    procedure CheckAppDataBothWays(const AClient, AServer: ITlsEngine;
      const AMsg: string);
    procedure Handshake(out AClient, AServer: ITlsEngine);
  published
    procedure TestClientKeyUpdateNoRequestRekeysServerRead;
    procedure TestClientKeyUpdateRequestedTriggersOneResponse;
    procedure TestServerInitiatedKeyUpdate;
    procedure TestRepeatedKeyUpdatesStayInSync;
    procedure TestConsecutiveKeyUpdateFloodIsRefused;
  end;

implementation

{ TTestTls13KeyUpdate }

function TTestTls13KeyUpdate.ServerCredential: TTlsCredential;
begin
  FCerts := LoadVectorFields('Certs/EcP256Chain.txt');
  try
    Result.CertificateChain := TArray<TBytes>.Create(
      DecodeHex(FCerts.Values['leaf_cert']));
    Result.PrivateKey := Provider.ImportSigningKey(DecodeHex(FCerts.Values['leaf_key']));
  finally
    FreeAndNil(FCerts);
  end;
end;

function TTestTls13KeyUpdate.ClientTrust: ITrustAnchorStore;
var
  LCerts: TStringList;
begin
  LCerts := LoadVectorFields('Certs/EcP256Chain.txt');
  try
    Result := TTrustAnchorStore.Create(
      TArray<TBytes>.Create(DecodeHex(LCerts.Values['root_cert']))) as ITrustAnchorStore;
  finally
    LCerts.Free;
  end;
end;

function TTestTls13KeyUpdate.NewClient: ITlsEngine;
begin
  // Hardened is TLS 1.3-only, the version that has KeyUpdate
  Result := TTlsEngineFactory.CreateClientEngine(
    TTlsPresets.Hardened(Provider).Client.WithTrustStore(ClientTrust).Build, ServerHost);
end;

function TTestTls13KeyUpdate.NewServer: ITlsEngine;
begin
  Result := TTlsEngineFactory.CreateServerEngine(
    TTlsPresets.Hardened(Provider).Server.WithCredential(ServerCredential).Build);
end;

function TTestTls13KeyUpdate.Drain(const AEngine: ITlsEngine): TBytes;
var
  LChunk: TBytes;
  LGot: Int32;
begin
  Result := nil;
  SetLength(LChunk, 65536);
  repeat
    LGot := AEngine.TakeOutgoing(LChunk, 0);
    if LGot > 0 then
      Result := ConcatBytes(Result, System.Copy(LChunk, 0, LGot));
  until LGot = 0;
end;

procedure TTestTls13KeyUpdate.Feed(const AEngine: ITlsEngine; const AWire: TBytes);
var
  LPos, LLen: Int32;
begin
  LPos := 0;
  while LPos + 5 <= System.Length(AWire) do
  begin
    LLen := (AWire[LPos + 3] shl 8) or AWire[LPos + 4];
    AEngine.ProcessInput(AWire, LPos, 5 + LLen);
    Inc(LPos, 5 + LLen);
  end;
end;

procedure TTestTls13KeyUpdate.Pump(const ASrc, ADst: ITlsEngine);
begin
  Feed(ADst, Drain(ASrc));
end;

procedure TTestTls13KeyUpdate.Exchange(const AClient, AServer: ITlsEngine);
begin
  // one full round-trip so an initiated KeyUpdate reaches the peer and any response returns
  Pump(AClient, AServer);
  Pump(AServer, AClient);
end;

function TTestTls13KeyUpdate.ReadAllApp(const AEngine: ITlsEngine): TBytes;
var
  LChunk: TBytes;
  LGot: Int32;
begin
  Result := nil;
  SetLength(LChunk, 65536);
  repeat
    LGot := AEngine.ReadAppData(LChunk, 0, System.Length(LChunk));
    if LGot > 0 then
      Result := ConcatBytes(Result, System.Copy(LChunk, 0, LGot));
  until LGot = 0;
end;

function TTestTls13KeyUpdate.CountKeyUpdateEvents(const AEngine: ITlsEngine): Int32;
var
  LEvent: ITlsEvent;
begin
  Result := 0;
  while AEngine.NextEvent(LEvent) do
    if LEvent.Kind = TTlsEventKind.KeyUpdateReceived then
      Inc(Result);
end;

procedure TTestTls13KeyUpdate.CheckAppDataBothWays(const AClient, AServer: ITlsEngine;
  const AMsg: string);
var
  LFromClient, LFromServer: TBytes;
begin
  LFromClient := DecodeHex('68656c6c6f2066726f6d2074686520636c69656e74');
  AClient.Write(LFromClient, 0, System.Length(LFromClient));
  Pump(AClient, AServer);
  CheckEqualBytes(AMsg + ': server reads client data under the current keys',
    LFromClient, ReadAllApp(AServer));
  LFromServer := DecodeHex('68656c6c6f2066726f6d2074686520736572766572');
  AServer.Write(LFromServer, 0, System.Length(LFromServer));
  Pump(AServer, AClient);
  CheckEqualBytes(AMsg + ': client reads server data under the current keys',
    LFromServer, ReadAllApp(AClient));
end;

procedure TTestTls13KeyUpdate.Handshake(out AClient, AServer: ITlsEngine);
var
  LIterations: Int32;
begin
  AClient := NewClient;
  AServer := NewServer;
  AClient.StartHandshake;
  LIterations := 0;
  while (AClient.IsHandshaking or AServer.IsHandshaking) and (LIterations < 16) do
  begin
    Exchange(AClient, AServer);
    Inc(LIterations);
  end;
  CheckFalse(AClient.IsHandshaking, 'the client completed the handshake');
  CheckFalse(AServer.IsHandshaking, 'the server completed the handshake');
  // clear the handshake-phase events (KeysInstalled, SessionTicketReceived, ...)
  CountKeyUpdateEvents(AClient);
  CountKeyUpdateEvents(AServer);
end;

procedure TTestTls13KeyUpdate.TestClientKeyUpdateNoRequestRekeysServerRead;
var
  LClient, LServer: ITlsEngine;
begin
  Handshake(LClient, LServer);
  // a plain KeyUpdate: the server rekeys its read epoch and does not respond
  LClient.RequestKeyUpdate(False);
  Exchange(LClient, LServer);
  CheckEquals(1, CountKeyUpdateEvents(LServer), 'the server saw one KeyUpdate');
  CheckEquals(0, CountKeyUpdateEvents(LClient),
    'the client got no response to update_not_requested');
  CheckFalse(LClient.IsTerminal, 'the client did not fail');
  CheckFalse(LServer.IsTerminal, 'the server did not fail');
  CheckAppDataBothWays(LClient, LServer, 'after a plain client KeyUpdate');
end;

procedure TTestTls13KeyUpdate.TestClientKeyUpdateRequestedTriggersOneResponse;
var
  LClient, LServer: ITlsEngine;
begin
  Handshake(LClient, LServer);
  // update_requested: the server rekeys read now and owes one coalesced response, which it
  // flushes just before its next application write (RFC 8446 4.6.3)
  LClient.RequestKeyUpdate(True);
  Exchange(LClient, LServer);
  CheckEquals(1, CountKeyUpdateEvents(LServer), 'the server saw one KeyUpdate');
  CheckFalse(LClient.IsTerminal, 'the client did not fail');
  CheckFalse(LServer.IsTerminal, 'the server did not fail');
  // the server's write in here carries the single responding KeyUpdate ahead of its data
  CheckAppDataBothWays(LClient, LServer, 'after a requested client KeyUpdate');
  CheckEquals(1, CountKeyUpdateEvents(LClient),
    'the server answered update_requested with exactly one KeyUpdate before its next write');
end;

procedure TTestTls13KeyUpdate.TestServerInitiatedKeyUpdate;
var
  LClient, LServer: ITlsEngine;
begin
  Handshake(LClient, LServer);
  // the server initiates; the client rekeys its read epoch
  LServer.RequestKeyUpdate(False);
  Exchange(LServer, LClient);
  CheckEquals(1, CountKeyUpdateEvents(LClient), 'the client saw the server KeyUpdate');
  CheckFalse(LClient.IsTerminal, 'the client did not fail');
  CheckAppDataBothWays(LClient, LServer, 'after a server-initiated KeyUpdate');
end;

procedure TTestTls13KeyUpdate.TestRepeatedKeyUpdatesStayInSync;
var
  LClient, LServer: ITlsEngine;
  LI: Int32;
begin
  // many requested updates over the life of a connection must stay in sync; application
  // traffic flows between them (as on a real connection), which also resets the consecutive
  // post-handshake flood bound so a long-lived exchange is never mistaken for a flood
  Handshake(LClient, LServer);
  for LI := 0 to 39 do
  begin
    LClient.RequestKeyUpdate(True);
    Exchange(LClient, LServer);
    CheckFalse(LClient.IsTerminal, 'the client stayed healthy across repeated updates');
    CheckFalse(LServer.IsTerminal, 'the server stayed healthy across repeated updates');
    CountKeyUpdateEvents(LClient);
    CountKeyUpdateEvents(LServer);
    CheckAppDataBothWays(LClient, LServer, 'between updates');
  end;
end;

procedure TTestTls13KeyUpdate.TestConsecutiveKeyUpdateFloodIsRefused;
var
  LClient, LServer: ITlsEngine;
  LI: Int32;
begin
  // a peer that streams KeyUpdates with no intervening application data is a DoS; past the
  // consecutive-post-handshake-message bound the connection is refused. update_not_requested
  // drives a one-directional flood at the client
  Handshake(LClient, LServer);
  for LI := 0 to 40 do
  begin
    LServer.RequestKeyUpdate(False);
    Pump(LServer, LClient);
  end;
  CheckTrue(LClient.IsTerminal, 'the client refuses a consecutive KeyUpdate flood');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestTls13KeyUpdate);
{$ELSE}
  RegisterTest(TTestTls13KeyUpdate.Suite);
{$ENDIF FPC}

end.
