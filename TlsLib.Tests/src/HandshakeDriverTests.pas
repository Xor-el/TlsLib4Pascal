{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit HandshakeDriverTests;

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
  TlpTlsAlert,
  TlpTlsVersion,
  TlpSecretBuffer,
  TlpCryptoAlgorithms,
  TlpIKeySchedule,
  TlpTls13KeySchedule,
  TlpNegotiationTypes,
  TlpRecordLayer,
  TlpITlsEngine,
  TlpHandshakeMessage,
  TlpIHandshakeChannel,
  TlpHandshakeChannel,
  TlpIHandshakeMachine,
  TlpHandshakeEffect,
  TlpHandshakeDriver,
  Tls13ClientReplayTests,
  TlsLibTestBase;

type
  TRecordingSink = class(TInterfacedObject, IHandshakeSink)
  strict private
  var
    FEventCount: Int32;
    FLastEvent: TTlsEventKind;
    FEstablished: Boolean;
    FFailed: Boolean;
    FFailedAlert: TTlsAlertDescription;
  public
    procedure OnHandshakeEvent(AEvent: TTlsEventKind);
    procedure OnAlpnSelected(const AProtocol: string);
    procedure OnOcspStapleReceived(const AStaple: TBytes);
    procedure OnHandshakeEstablished;
    procedure OnHandshakeFailed(AAlert: TTlsAlertDescription);
    property EventCount: Int32 read FEventCount;
    property LastEvent: TTlsEventKind read FLastEvent;
    property Established: Boolean read FEstablished;
    property Failed: Boolean read FFailed;
    property FailedAlert: TTlsAlertDescription read FFailedAlert;
  end;

  TTestHandshakeDriver = class(TTlsLibAlgorithmTestCase)
  private
    function DefaultSuite: TTlsCipherSuite;
    function TakeOutgoing(const ALayer: TRecordLayer): TBytes;
  published
    procedure TestChannelSendsHandshakeRecord;
    procedure TestChannelSendsChangeCipherSpec;
    procedure TestChannelReassemblesInbound;
    procedure TestDriverInstallKeysDecryptsRfc8448Record;
    procedure TestDriverReportsOutcomesToSink;
  end;

implementation

{ TRecordingSink }

procedure TRecordingSink.OnHandshakeEvent(AEvent: TTlsEventKind);
begin
  Inc(FEventCount);
  FLastEvent := AEvent;
end;

procedure TRecordingSink.OnOcspStapleReceived(const AStaple: TBytes);
begin
end;

procedure TRecordingSink.OnAlpnSelected(const AProtocol: string);
begin
end;

procedure TRecordingSink.OnHandshakeEstablished;
begin
  FEstablished := True;
end;

procedure TRecordingSink.OnHandshakeFailed(AAlert: TTlsAlertDescription);
begin
  FFailed := True;
  FFailedAlert := AAlert;
end;

{ TTestHandshakeDriver }

function TTestHandshakeDriver.DefaultSuite: TTlsCipherSuite;
begin
  Result.Common.Code := TCipherSuites13.Aes128GcmSha256;
  Result.Common.Hash := THashAlgorithm.SHA_256;
  Result.Common.Aead := TAeadAlgorithm.AES_128_GCM;
  Result.Common.KeyLength := 16;
  Result.Protocol := TSuiteProtocol.Tls13;
  Result.KeyExchange := TKeyExchangeMethod.Decoupled;
  Result.Auth := TAuthMethod.Decoupled;
  Result.Prf := THashAlgorithm.SHA_256;
end;

function TTestHandshakeDriver.TakeOutgoing(const ALayer: TRecordLayer): TBytes;
begin
  Result := ALayer.TakeOutgoing;
end;

procedure TTestHandshakeDriver.TestChannelSendsHandshakeRecord;
var
  LLayer: TRecordLayer;
  LChannel: IHandshakeChannel;
  LWire: TBytes;
begin
  LLayer := TRecordLayer.Create;
  try
    LChannel := THandshakeChannel.Create(LLayer);
    LChannel.SendHandshake(DecodeHex('0102030405'));
    LWire := TakeOutgoing(LLayer);
    // a plaintext handshake record: type 22, version 0x0303, length 5, body
    CheckEqualBytes('handshake record', DecodeHex('160303000501 02030405'), LWire);
  finally
    LChannel := nil;
    LLayer.Free;
  end;
end;

procedure TTestHandshakeDriver.TestChannelSendsChangeCipherSpec;
var
  LLayer: TRecordLayer;
  LChannel: IHandshakeChannel;
begin
  LLayer := TRecordLayer.Create;
  try
    LChannel := THandshakeChannel.Create(LLayer);
    LChannel.SendChangeCipherSpec;
    // type 20 (0x14), version 0x0303, length 1, body 0x01
    CheckEqualBytes('CCS record', DecodeHex('140303000101'), TakeOutgoing(LLayer));
  finally
    LChannel := nil;
    LLayer.Free;
  end;
end;

procedure TTestHandshakeDriver.TestChannelReassemblesInbound;
var
  LLayer: TRecordLayer;
  LChannel: THandshakeChannel;
  LFramed: TBytes;
  LMessage: TTlsHandshakeMessage;
begin
  LLayer := TRecordLayer.Create;
  LChannel := THandshakeChannel.Create(LLayer);
  try
    // a framed Finished message (type 20, uint24 length 2, body)
    LFramed := DecodeHex('1400000201 02');
    LChannel.AppendInbound(LFramed, 0, System.Length(LFramed));
    CheckTrue(LChannel.ReceiveHandshake(LMessage), 'a message reassembles');
    CheckEquals(20, LMessage.TypeByte, 'finished type');
    CheckEqualBytes('body', DecodeHex('0102'), LMessage.Body);
    CheckFalse(LChannel.ReceiveHandshake(LMessage), 'nothing more');
  finally
    LChannel.Free;
    LLayer.Free;
  end;
end;

procedure TTestHandshakeDriver.TestDriverInstallKeysDecryptsRfc8448Record;
var
  LVec, LRec: TStringList;
  LSchedule: ITls13KeySchedule;
  LLayer: TRecordLayer;
  LDriver: THandshakeDriver;
  LRecord: TBytes;
  LFragment: TTlsRecordFragment;
begin
  LVec := LoadVectorFields('Rfc8448/Tls13KeySchedule.txt');
  LRec := LoadVectorFields('Rfc8448/Tls13RecordFinished.txt');
  LLayer := TRecordLayer.Create;
  LDriver := nil;
  try
    LSchedule := TTls13KeySchedule.Create(Provider, THashAlgorithm.SHA_256, 16);
    LSchedule.SetSharedSecret(TSecretBuffer.From(DecodeHex(LVec.Values['shared_secret'])));
    LSchedule.DeriveEpochSecrets(TTlsEpoch.Handshake,
      DecodeHex(LVec.Values['hash_ch_sh']));

    // install the READ side (from the client's handshake traffic secret) through the
    // driver into a standalone record layer - the engine no longer exposes an
    // installer seam that a caller could take a counted reference to
    LDriver := THandshakeDriver.Create(
      THandshakeChannel.Create(LLayer) as IHandshakeChannel,
      TRecordLayerInstaller.Create(LLayer) as IRecordEpochInstaller, Provider,
      TSilentSink.Create as IHandshakeSink);
    LDriver.Apply(THandshakeEffects.InstallKeys(LSchedule.TrafficKeys(
      TTlsEpoch.Handshake, TTlsDirection.ClientWrite), TRecordSide.ReadSide,
      DefaultSuite.Common.Aead, TTlsVersion.Tls13));

    LRecord := DecodeHex(LRec.Values['record']);
    LLayer.ProcessInput(LRecord, 0, System.Length(LRecord));
    CheckTrue(LLayer.NextIncoming(LFragment), 'the record decrypts to a fragment');
    CheckEqualBytes('the driver-installed keys decrypt the RFC 8448 record',
      DecodeHex(LRec.Values['plaintext']), LFragment.Data);
  finally
    LDriver.Free;
    LLayer.Free;
    LVec.Free;
    LRec.Free;
  end;
end;

procedure TTestHandshakeDriver.TestDriverReportsOutcomesToSink;
var
  LLayer: TRecordLayer;
  LDriver: THandshakeDriver;
  LSink: TRecordingSink;
  LSinkRef: IHandshakeSink;
begin
  LLayer := TRecordLayer.Create;
  LSink := TRecordingSink.Create;
  LSinkRef := LSink;
  LDriver := THandshakeDriver.Create(THandshakeChannel.Create(LLayer) as IHandshakeChannel, nil,
    Provider, LSinkRef);
  try
    LDriver.Apply(THandshakeEffects.RaiseEvent(TTlsEventKind.KeysInstalled));
    LDriver.Apply(THandshakeEffects.HandshakeEstablished);
    LDriver.Apply(THandshakeEffects.Fail(TTlsAlertDescription.DecodeError));
    LDriver.Apply(THandshakeEffects.SendChangeCipherSpec);

    CheckEquals(1, LSink.EventCount, 'one event raised');
    CheckEquals(Ord(TTlsEventKind.KeysInstalled), Ord(LSink.LastEvent), 'the event');
    CheckTrue(LSink.Established, 'handshake established');
    CheckTrue(LSink.Failed, 'failure reported');
    CheckEquals(Ord(TTlsAlertDescription.DecodeError), Ord(LSink.FailedAlert), 'alert');
    // the CCS effect reached the record layer
    CheckEqualBytes('CCS emitted', DecodeHex('140303000101'), TakeOutgoing(LLayer));
  finally
    LDriver.Free;
    LLayer.Free;
  end;
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestHandshakeDriver);
{$ELSE}
  RegisterTest(TTestHandshakeDriver.Suite);
{$ENDIF FPC}

end.
