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
  TlpTlsLibExceptions,
  TlpTlsContentType,
  TlpTlsVersion,
  TlpSecretBuffer,
  TlpCryptoDomainTypes,
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
    function SampleTrafficKeys: ITrafficKeys;
    function DriverOver(const ALayer: TRecordLayer): THandshakeDriver;
    function ReadInstallAlert(const AVersion: TTlsVersion;
      out AAlert: TTlsAlertDescription): Boolean;
  published
    procedure TestChannelSendsHandshakeRecord;
    procedure TestChannelSendsChangeCipherSpec;
    procedure TestChannelReassemblesInbound;
    procedure TestDriverInstallKeysDecryptsRfc8448Record;
    procedure TestDriverReportsOutcomesToSink;
    procedure TestDriverArmsTls12ReadInstallButInstallsTls13Immediately;
    procedure TestDriverWriteInstallIsImmediate;
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

function TTestHandshakeDriver.SampleTrafficKeys: ITrafficKeys;
var
  LSchedule: ITls13KeySchedule;
  LHash: TBytes;
begin
  // any valid epoch keys; the routing tests only care where the driver installs them, not what
  LSchedule := TTls13KeySchedule.Create(Provider, THashAlgorithm.SHA_256, 16);
  LSchedule.SetSharedSecret(TSecretBuffer.From(DecodeHex(
    '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')));
  SetLength(LHash, 32);
  LSchedule.DeriveEpochSecrets(TTlsEpoch.Handshake, LHash);
  Result := LSchedule.TrafficKeys(TTlsEpoch.Handshake, TTlsDirection.ServerWrite);
end;

function TTestHandshakeDriver.DriverOver(const ALayer: TRecordLayer): THandshakeDriver;
begin
  Result := THandshakeDriver.Create(
    THandshakeChannel.Create(ALayer) as IHandshakeChannel,
    TRecordLayerInstaller.Create(ALayer) as IRecordEpochInstaller, Provider,
    TSilentSink.Create as IHandshakeSink);
end;

function TTestHandshakeDriver.ReadInstallAlert(const AVersion: TTlsVersion;
  out AAlert: TTlsAlertDescription): Boolean;
var
  LLayer: TRecordLayer;
  LDriver: THandshakeDriver;
  LFrag: TTlsRecordFragment;
begin
  // apply a ReadSide install of the given version, then feed a plaintext handshake record and
  // return the fatal alert it provokes. Tls12 arms (guard -> unexpected_message); Tls13 installs
  // the real epoch immediately (the plaintext record fails AEAD -> bad_record_mac).
  Result := False;
  AAlert := TTlsAlertDescription.CloseNotify;
  LLayer := TRecordLayer.Create;
  LDriver := DriverOver(LLayer);
  try
    LDriver.Apply(THandshakeEffects.InstallKeys(SampleTrafficKeys, TRecordSide.ReadSide,
      DefaultSuite.Common.Aead, AVersion));
    try
      LLayer.ProcessInput(DecodeHex('160303000401020304'), 0, 9);
      LLayer.NextIncoming(LFrag);
    except
      on E: EFatalAlertTlsLibException do
      begin
        Result := True;
        AAlert := E.AlertDescription;
      end;
    end;
  finally
    LDriver.Free;
    LLayer.Free;
  end;
end;

procedure TTestHandshakeDriver.TestDriverArmsTls12ReadInstallButInstallsTls13Immediately;
var
  LAlert: TTlsAlertDescription;
begin
  // a TLS 1.2 read install is armed for the peer's change_cipher_spec: the read epoch stays null,
  // so a plaintext handshake record before the CCS trips the armed-epoch guard.
  CheckTrue(ReadInstallAlert(TTlsVersion.Tls12, LAlert), 'a Tls12 read install arms and rejects');
  CheckEquals(Ord(TTlsAlertDescription.UnexpectedMessage), Ord(LAlert),
    'a plaintext handshake record while armed is unexpected_message');
  // a TLS 1.3 read install is immediate: the same plaintext record hits the real AEAD epoch and
  // fails to authenticate, proving it was installed rather than armed.
  CheckTrue(ReadInstallAlert(TTlsVersion.Tls13, LAlert), 'a Tls13 read install is immediate');
  CheckEquals(Ord(TTlsAlertDescription.BadRecordMac), Ord(LAlert),
    'an immediate Tls13 read epoch fails the plaintext record under AEAD');
end;

procedure TTestHandshakeDriver.TestDriverWriteInstallIsImmediate;
var
  LLayer: TRecordLayer;
  LDriver: THandshakeDriver;
  LWire: TBytes;
begin
  // the write side is never armed (the driver routes only the read side by version; each endpoint
  // switches its own write epoch when it sends its CCS): a write install takes effect at once, so
  // the next write is protected (expanded by the AEAD tag), not a bare plaintext framing.
  LLayer := TRecordLayer.Create;
  LDriver := DriverOver(LLayer);
  try
    LDriver.Apply(THandshakeEffects.InstallKeys(SampleTrafficKeys, TRecordSide.WriteSide,
      DefaultSuite.Common.Aead, TTlsVersion.Tls13));
    LLayer.Write(TTlsContentType.ApplicationData, DecodeHex('0102030405'), 0, 5);
    LWire := TakeOutgoing(LLayer);
    // a plaintext framing of 5 bytes would be 10 bytes (5 header + 5 body); an AEAD record is
    // larger (inner content-type byte + 16-byte tag)
    CheckTrue(System.Length(LWire) > 10, 'the write epoch is protected immediately');
  finally
    LDriver.Free;
    LLayer.Free;
  end;
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
