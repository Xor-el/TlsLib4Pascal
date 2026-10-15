{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlsLibHandshakeTestBase;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  TlpTlsAlert,
  TlpICryptoProvider,
  TlpITlsEngine,
  TlpHandshakeEffect,
  TlpHandshakeMessage,
  TlpTlsCredential,
  TlpRecordHeader,
  TlsLibTestBase,
  TlsLibTestCertificates,
  TlsLibTestHandshakeDecoder;

type
  /// <summary>The helpers the handshake suites share; it has no tests and is never registered.</summary>
  TTlsLibHandshakeTestCase = class abstract(TTlsLibAlgorithmTestCase)
  protected
    // Everything AEngine has queued to send.
    function Drain(const AEngine: ITlsEngine): TBytes;
    // One record at a time, so an epoch installed by one record is active for the next.
    procedure Feed(const AEngine: ITlsEngine; const AWire: TBytes);
    // One ProcessInput for the whole buffer, so a flight may change epoch mid-buffer.
    procedure FeedCoalesced(const AEngine: ITlsEngine; const AWire: TBytes);
    procedure Pump(const ASrc, ADst: ITlsEngine);
    procedure PumpCoalesced(const ASrc, ADst: ITlsEngine);
    // Client to server then back, until neither is handshaking; stops silently after 16 rounds.
    procedure ExchangeFlights(const AClient, AServer: ITlsEngine);
    // Starts AClient's handshake, then ExchangeFlights.
    procedure RunHandshake(const AClient, AServer: ITlsEngine);
    function ReadAllApp(const AEngine: ITlsEngine): TBytes;
    function ReadAllEarly(const AEngine: ITlsEngine): TBytes;
    // ACount bytes of AByte.
    function Filled(AByte: Byte; ACount: Int32): TBytes;
    // The alert of the first Fail effect in AEffects, or False if none.
    function FailAlertOf(const AEffects: TArray<THandshakeEffect>;
      out AAlert: TTlsAlertDescription): Boolean;
    // Whether AEffects holds a Fail effect carrying AAlert.
    function HasFailAlert(const AEffects: TArray<THandshakeEffect>;
      AAlert: TTlsAlertDescription): Boolean;
    function FirstSendHandshake(const AEffects: TArray<THandshakeEffect>): TBytes;
    function AllSendHandshake(const AEffects: TArray<THandshakeEffect>): TArray<TBytes>;
    // AWire's first record with AExtra appended to its fragment and the record length adjusted.
    function FirstRecordWith(const AWire, AExtra: TBytes): TBytes;
    function ServerCredential: TTlsCredential; overload;
    function ServerCredential(const ACrypto: ICryptoProvider): TTlsCredential; overload;
    function ServerCredentialEd25519: TTlsCredential;
    function ServerCredentialEd448: TTlsCredential;
    // The client-auth leaf and key, with its root through ARoot.
    function ClientAuthCredential(out ARoot: TBytes): TTlsCredential;
    // The EcP256 server credential with its certificate chain replaced by AChain.
    function CredentialWithChain(const AChain: TArray<TBytes>): TTlsCredential;
    // Application data crosses in both directions between two established engines.
    procedure CheckAppDataFlows(const AClient, AServer: ITlsEngine);
    // Drives a handshake to completion; true when the server's first flight carried a Certificate.
    function DriveObservingServerCert(const AClient, AServer: ITlsEngine): Boolean;
  end;

implementation

{ TTlsLibHandshakeTestCase }

function TTlsLibHandshakeTestCase.Drain(const AEngine: ITlsEngine): TBytes;
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

procedure TTlsLibHandshakeTestCase.Feed(const AEngine: ITlsEngine; const AWire: TBytes);
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

procedure TTlsLibHandshakeTestCase.FeedCoalesced(const AEngine: ITlsEngine;
  const AWire: TBytes);
begin
  if System.Length(AWire) > 0 then
    AEngine.ProcessInput(AWire, 0, System.Length(AWire));
end;

procedure TTlsLibHandshakeTestCase.Pump(const ASrc, ADst: ITlsEngine);
begin
  Feed(ADst, Drain(ASrc));
end;

procedure TTlsLibHandshakeTestCase.PumpCoalesced(const ASrc, ADst: ITlsEngine);
begin
  FeedCoalesced(ADst, Drain(ASrc));
end;

procedure TTlsLibHandshakeTestCase.ExchangeFlights(const AClient, AServer: ITlsEngine);
var
  LIterations: Int32;
begin
  LIterations := 0;
  while (AClient.IsHandshaking or AServer.IsHandshaking) and (LIterations < 16) do
  begin
    Pump(AClient, AServer);
    Pump(AServer, AClient);
    Inc(LIterations);
  end;
end;

procedure TTlsLibHandshakeTestCase.RunHandshake(const AClient, AServer: ITlsEngine);
begin
  AClient.StartHandshake;
  ExchangeFlights(AClient, AServer);
end;

function TTlsLibHandshakeTestCase.ReadAllApp(const AEngine: ITlsEngine): TBytes;
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

function TTlsLibHandshakeTestCase.ReadAllEarly(const AEngine: ITlsEngine): TBytes;
var
  LChunk: TBytes;
  LGot: Int32;
begin
  Result := nil;
  SetLength(LChunk, 65536);
  repeat
    LGot := AEngine.ReadEarlyData(LChunk, 0, System.Length(LChunk));
    if LGot > 0 then
      Result := ConcatBytes(Result, System.Copy(LChunk, 0, LGot));
  until LGot = 0;
end;

function TTlsLibHandshakeTestCase.Filled(AByte: Byte; ACount: Int32): TBytes;
var
  LI: Int32;
begin
  Result := nil;
  SetLength(Result, ACount);
  for LI := 0 to ACount - 1 do
    Result[LI] := AByte;
end;

function TTlsLibHandshakeTestCase.FailAlertOf(const AEffects: TArray<THandshakeEffect>;
  out AAlert: TTlsAlertDescription): Boolean;
var
  LEffect: THandshakeEffect;
begin
  Result := False;
  AAlert := TTlsAlertDescription.CloseNotify;
  for LEffect in AEffects do
    if LEffect.Kind = THandshakeEffectKind.Fail then
    begin
      AAlert := LEffect.Alert;
      Exit(True);
    end;
end;

function TTlsLibHandshakeTestCase.HasFailAlert(const AEffects: TArray<THandshakeEffect>;
  AAlert: TTlsAlertDescription): Boolean;
var
  LEffect: THandshakeEffect;
begin
  Result := False;
  for LEffect in AEffects do
    if (LEffect.Kind = THandshakeEffectKind.Fail) and (LEffect.Alert = AAlert) then
      Result := True;
end;

function TTlsLibHandshakeTestCase.FirstSendHandshake(
  const AEffects: TArray<THandshakeEffect>): TBytes;
var
  LEffect: THandshakeEffect;
begin
  Result := nil;
  for LEffect in AEffects do
    if LEffect.Kind = THandshakeEffectKind.SendHandshake then
      Exit(LEffect.Bytes);
end;

function TTlsLibHandshakeTestCase.AllSendHandshake(
  const AEffects: TArray<THandshakeEffect>): TArray<TBytes>;
var
  LEffect: THandshakeEffect;
  LCount: Int32;
begin
  Result := nil;
  LCount := 0;
  for LEffect in AEffects do
    if LEffect.Kind = THandshakeEffectKind.SendHandshake then
    begin
      SetLength(Result, LCount + 1);
      Result[LCount] := LEffect.Bytes;
      Inc(LCount);
    end;
end;

function TTlsLibHandshakeTestCase.FirstRecordWith(const AWire, AExtra: TBytes): TBytes;
var
  LLen: Int32;
begin
  LLen := (AWire[3] shl 8) or AWire[4];
  Result := ConcatBytes(System.Copy(AWire, 0, TRecordLimits.HeaderLength + LLen), AExtra);
  Inc(LLen, System.Length(AExtra));
  Result[3] := Byte(LLen shr 8);
  Result[4] := Byte(LLen);
end;

function TTlsLibHandshakeTestCase.ServerCredential: TTlsCredential;
begin
  Result := ServerCredential(Crypto);
end;

function TTlsLibHandshakeTestCase.ServerCredential(const ACrypto: ICryptoProvider)
  : TTlsCredential;
begin
  Result.CertificateChain := TArray<TBytes>.Create(
    TTlsLibTestCertificates.Field('Certs/EcP256Chain.txt', 'leaf_cert'));
  Result.PrivateKey := ACrypto.Signing.ImportSigningKey(
    TTlsLibTestCertificates.Field('Certs/EcP256Chain.txt', 'leaf_key'), nil);
end;

function TTlsLibHandshakeTestCase.ServerCredentialEd25519: TTlsCredential;
begin
  Result.CertificateChain := TArray<TBytes>.Create(
    TTlsLibTestCertificates.Field('Certs/Ed25519Chain.txt', 'leaf_cert'));
  Result.PrivateKey := Crypto.Signing.ImportSigningKey(
    TTlsLibTestCertificates.Field('Certs/Ed25519Chain.txt', 'leaf_key'), nil);
end;

function TTlsLibHandshakeTestCase.ServerCredentialEd448: TTlsCredential;
begin
  Result.CertificateChain := TArray<TBytes>.Create(
    TTlsLibTestCertificates.Field('Certs/Ed448Chain.txt', 'leaf_cert'));
  Result.PrivateKey := Crypto.Signing.ImportSigningKey(
    TTlsLibTestCertificates.Field('Certs/Ed448Chain.txt', 'leaf_key'), nil);
end;

function TTlsLibHandshakeTestCase.ClientAuthCredential(out ARoot: TBytes): TTlsCredential;
begin
  ARoot := TTlsLibTestCertificates.Field('Certs/ClientAuthChain.txt', 'root_cert');
  Result.CertificateChain := TArray<TBytes>.Create(
    TTlsLibTestCertificates.Field('Certs/ClientAuthChain.txt', 'leaf_cert'));
  Result.PrivateKey := Crypto.Signing.ImportSigningKey(
    TTlsLibTestCertificates.Field('Certs/ClientAuthChain.txt', 'leaf_key'), nil);
end;

function TTlsLibHandshakeTestCase.CredentialWithChain(
  const AChain: TArray<TBytes>): TTlsCredential;
begin
  Result := ServerCredential;
  Result.CertificateChain := AChain;
end;

procedure TTlsLibHandshakeTestCase.CheckAppDataFlows(const AClient, AServer: ITlsEngine);
var
  LFromClient, LFromServer: TBytes;
begin
  LFromClient := DecodeHex('68656c6c6f2066726f6d2074686520636c69656e74');
  AClient.Write(LFromClient, 0, System.Length(LFromClient));
  Pump(AClient, AServer);
  CheckEqualBytes('the server decrypts the client application data', LFromClient,
    ReadAllApp(AServer));
  LFromServer := DecodeHex('68656c6c6f2066726f6d2074686520736572766572');
  AServer.Write(LFromServer, 0, System.Length(LFromServer));
  Pump(AServer, AClient);
  CheckEqualBytes('the client decrypts the server application data', LFromServer,
    ReadAllApp(AClient));
end;

function TTlsLibHandshakeTestCase.DriveObservingServerCert(
  const AClient, AServer: ITlsEngine): Boolean;
var
  LFlight: TBytes;
  LRecordPos, LMsgPos, LMsgLen: Int32;
begin
  AClient.StartHandshake;
  Pump(AClient, AServer);
  LFlight := Drain(AServer);
  Result := TTlsLibTestHandshakeDecoder.FindPlaintextHandshakeMessage(LFlight,
    Ord(TTlsHandshakeType.Certificate), LRecordPos, LMsgPos, LMsgLen);
  Feed(AClient, LFlight);
  ExchangeFlights(AClient, AServer);
end;

end.
