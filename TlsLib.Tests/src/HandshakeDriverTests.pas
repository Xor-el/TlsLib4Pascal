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
  TlpTrustPolicy,
  TlpHandshakeMessage,
  TlpIHandshakeChannel,
  TlpHandshakeChannel,
  TlpIHandshakeMachine,
  TlpHandshakeEffect,
  TlpHandshakeDriver,
  MockSink,
  MockRecordInstaller,
  TlsLibTestBase;

type
  TTestHandshakeDriver = class(TTlsLibAlgorithmTestCase)
  private
    function DefaultSuite: TTlsCipherSuite;
    function TakeOutgoing(const ALayer: TRecordLayer): TBytes;
    function SampleSchedule: ITls13KeySchedule;
    function DriverOver(const ALayer: TRecordLayer;
      const ASink: IHandshakeSink): THandshakeDriver;
    function ReadInstallAlert(const AVersion: TTlsVersion;
      out AAlert: TTlsAlertDescription): Boolean;
  published
    procedure TestChannelSendsHandshakeRecord;
    procedure TestDriverSendsChangeCipherSpecThroughTheRecordCompanion;
    procedure TestChannelReassemblesInbound;
    procedure TestDriverInstallKeysDecryptsRfc8448Record;
    procedure TestRecordOnlyEffectsFailClosedWithoutTheRecordCompanion;
    procedure TestTls12ReadInstallFailsClosedWithoutTheRecordCompanion;
    procedure TestKeyOnlyInstallerStillInstallsASecret;
    procedure TestDriverReportsOutcomesToSink;
    procedure TestDriverForwardsTheFailReasonToTheSink;
    procedure TestTryFromExceptionCarriesTheFatalAlertMessage;
    procedure TestTryFromExceptionCarriesThePeerInputMessage;
    procedure TestDriverFailsClosedOnUndeliverableVerdictPark;
    procedure TestUndeliverableVerdictParkSaysWhy;
    procedure TestDriverArmsTls12ReadInstallButInstallsTls13Immediately;
    procedure TestDriverWriteInstallIsImmediate;
  end;

implementation

resourcestring
  SProbeReason = 'probe abort';

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
var
  LChunk: TBytes;
  LN: Int32;
begin
  Result := nil;
  repeat
    LChunk := nil;
    SetLength(LChunk, 4096);
    LN := ALayer.TakeOutgoing(LChunk, 0);
    if LN > 0 then
      Result := ConcatBytes(Result, System.Copy(LChunk, 0, LN));
  until LN <= 0;
end;

function TTestHandshakeDriver.SampleSchedule: ITls13KeySchedule;
var
  LHash: TBytes;
begin
  // any valid epoch secrets; the routing tests only care where the driver installs them, not what
  Result := TTls13KeySchedule.Create(Crypto, DefaultSuite.Common.Code,
    DefaultSuite.Common.Hash, DefaultSuite.Common.KeyLength, DefaultSuite.Common.Aead);
  Result.SetSharedSecret(TSecretBuffer.From(DecodeHex(
    '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')));
  SetLength(LHash, 32);
  Result.DeriveEpochSecrets(TTlsEpoch.Handshake, LHash);
end;

function TTestHandshakeDriver.DriverOver(const ALayer: TRecordLayer;
  const ASink: IHandshakeSink): THandshakeDriver;
begin
  Result := THandshakeDriver.Create(
    THandshakeChannel.Create(ALayer) as IHandshakeChannel,
    TRecordLayerInstaller.Create(ALayer, Crypto) as IEpochKeyInstaller, ASink);
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
  LDriver := DriverOver(LLayer, TMockHandshakeSink.Create as IHandshakeSink);
  try
    if AVersion.Equals(TTlsVersion.Tls12) then
      LDriver.Apply(THandshakeEffects.InstallKeys(
        SampleSchedule.TrafficKeys(TTlsEpoch.Handshake, TTlsDirection.ServerWrite),
        TRecordSide.ReadSide, DefaultSuite.Common.Aead, AVersion, TTlsEpoch.Application))
    else
      LDriver.Apply(THandshakeEffects.InstallSecret(
        SampleSchedule.TrafficSecret(TTlsEpoch.Handshake, TTlsDirection.ServerWrite),
        TRecordSide.ReadSide, TTlsEpoch.Application));
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
  LDriver := DriverOver(LLayer, TMockHandshakeSink.Create as IHandshakeSink);
  try
    LDriver.Apply(THandshakeEffects.InstallSecret(
      SampleSchedule.TrafficSecret(TTlsEpoch.Handshake, TTlsDirection.ServerWrite),
      TRecordSide.WriteSide, TTlsEpoch.Application));
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

procedure TTestHandshakeDriver.TestDriverSendsChangeCipherSpecThroughTheRecordCompanion;
var
  LLayer: TRecordLayer;
  LDriver: THandshakeDriver;
begin
  LLayer := TRecordLayer.Create;
  LDriver := DriverOver(LLayer, TMockHandshakeSink.Create as IHandshakeSink);
  try
    LDriver.Apply(THandshakeEffects.SendChangeCipherSpec);
    // type 20 (0x14), version 0x0303, length 1, body 0x01
    CheckEqualBytes('CCS record', DecodeHex('140303000101'), TakeOutgoing(LLayer));
  finally
    LDriver.Free;
    LLayer.Free;
  end;
end;

procedure TTestHandshakeDriver.TestRecordOnlyEffectsFailClosedWithoutTheRecordCompanion;
var
  LLayer: TRecordLayer;
  LEffects: TArray<THandshakeEffect>;
  LEffect: THandshakeEffect;
  LDriver: THandshakeDriver;
  LSink: TMockHandshakeSink;
  LSinkRef: IHandshakeSink;
begin
  LEffects := TArray<THandshakeEffect>.Create(
    THandshakeEffects.SendChangeCipherSpec,
    THandshakeEffects.SetRecordSizeLimit(1, 1),
    THandshakeEffects.SkipEarlyData(1),
    THandshakeEffects.SetEarlyDataLimit(1),
    THandshakeEffects.RevertWriteToPlaintext,
    THandshakeEffects.SetEarlyReadEpoch(True, 1));
  LLayer := TRecordLayer.Create;
  try
    for LEffect in LEffects do
    begin
      // a key-only installer: the record companion is absent, so each record-only effect must
      // be refused rather than silently dropped
      LSink := TMockHandshakeSink.Create;
      LSinkRef := LSink;
      LDriver := THandshakeDriver.Create(
        THandshakeChannel.Create(LLayer) as IHandshakeChannel,
        TRecordLayerKeyInstaller.Create(LLayer, Crypto) as IEpochKeyInstaller, LSinkRef);
      try
        LDriver.Apply(LEffect);
        CheckTrue(LSink.Failed, 'effect kind ' + IntToStr(Ord(LEffect.Kind)) + ' fails closed');
        CheckEquals(Ord(TTlsAlertDescription.InternalError), Ord(LSink.FailedAlert),
          'the failure is internal_error: our side cannot carry the effect');
      finally
        LDriver.Free;
      end;
    end;
    CheckEquals(0, System.Length(TakeOutgoing(LLayer)), 'nothing reached the record layer');
  finally
    LLayer.Free;
  end;
end;

procedure TTestHandshakeDriver.TestTls12ReadInstallFailsClosedWithoutTheRecordCompanion;
var
  LLayer: TRecordLayer;
  LDriver: THandshakeDriver;
  LSink: TMockHandshakeSink;
  LSinkRef: IHandshakeSink;
begin
  // the TLS 1.2 read switch waits for the peer's change_cipher_spec, a record-layer control
  LLayer := TRecordLayer.Create;
  LSink := TMockHandshakeSink.Create;
  LSinkRef := LSink;
  LDriver := THandshakeDriver.Create(
    THandshakeChannel.Create(LLayer) as IHandshakeChannel,
    TRecordLayerKeyInstaller.Create(LLayer, Crypto) as IEpochKeyInstaller, LSinkRef);
  try
    LDriver.Apply(THandshakeEffects.InstallKeys(
      SampleSchedule.TrafficKeys(TTlsEpoch.Handshake, TTlsDirection.ServerWrite),
      TRecordSide.ReadSide, DefaultSuite.Common.Aead, TTlsVersion.Tls12, TTlsEpoch.Application));
    CheckTrue(LSink.Failed, 'a TLS 1.2 read install without the companion fails closed');
    CheckEquals(Ord(TTlsAlertDescription.InternalError), Ord(LSink.FailedAlert),
      'the failure is internal_error');
  finally
    LDriver.Free;
    LLayer.Free;
  end;
end;

procedure TTestHandshakeDriver.TestKeyOnlyInstallerStillInstallsASecret;
var
  LLayer: TRecordLayer;
  LDriver: THandshakeDriver;
  LSink: TMockHandshakeSink;
  LSinkRef: IHandshakeSink;
begin
  // the key path must not depend on the record companion
  LLayer := TRecordLayer.Create;
  LSink := TMockHandshakeSink.Create;
  LSinkRef := LSink;
  LDriver := THandshakeDriver.Create(
    THandshakeChannel.Create(LLayer) as IHandshakeChannel,
    TRecordLayerKeyInstaller.Create(LLayer, Crypto) as IEpochKeyInstaller, LSinkRef);
  try
    LDriver.Apply(THandshakeEffects.InstallSecret(
      SampleSchedule.TrafficSecret(TTlsEpoch.Handshake, TTlsDirection.ServerWrite),
      TRecordSide.WriteSide, TTlsEpoch.Application));
    CheckFalse(LSink.Failed, 'a secret install needs no record companion');
    LLayer.Write(TTlsContentType.ApplicationData, DecodeHex('0102030405'), 0, 5);
    CheckTrue(System.Length(TakeOutgoing(LLayer)) > 10, 'the write epoch is protected');
  finally
    LDriver.Free;
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
    LSchedule := TTls13KeySchedule.Create(Crypto, DefaultSuite.Common.Code,
      DefaultSuite.Common.Hash, DefaultSuite.Common.KeyLength, DefaultSuite.Common.Aead);
    LSchedule.SetSharedSecret(TSecretBuffer.From(DecodeHex(LVec.Values['shared_secret'])));
    LSchedule.DeriveEpochSecrets(TTlsEpoch.Handshake,
      DecodeHex(LVec.Values['hash_ch_sh']));

    // install the READ side (from the client's handshake traffic secret) through the
    // driver into a standalone record layer - the engine exposes no installer seam to callers
    LDriver := DriverOver(LLayer, TMockHandshakeSink.Create as IHandshakeSink);
    LDriver.Apply(THandshakeEffects.InstallSecret(LSchedule.TrafficSecret(
      TTlsEpoch.Handshake, TTlsDirection.ClientWrite), TRecordSide.ReadSide,
      TTlsEpoch.Handshake));

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
  LSink: TMockHandshakeSink;
  LSinkRef: IHandshakeSink;
begin
  LLayer := TRecordLayer.Create;
  LSink := TMockHandshakeSink.Create;
  LSinkRef := LSink;
  LDriver := THandshakeDriver.Create(THandshakeChannel.Create(LLayer) as IHandshakeChannel, nil,
    LSinkRef);
  try
    LDriver.Apply(THandshakeEffects.RaiseEvent(TTlsEventKind.SessionTicketReceived));
    LDriver.Apply(THandshakeEffects.HandshakeEstablished);
    LDriver.Apply(THandshakeEffects.Fail(TTlsAlertDescription.DecodeError, SProbeReason));

    CheckEquals(1, LSink.EventCount, 'one event raised');
    CheckEquals(Ord(TTlsEventKind.SessionTicketReceived), Ord(LSink.LastEvent), 'the event');
    CheckTrue(LSink.Established, 'handshake established');
    CheckTrue(LSink.Failed, 'failure reported');
    CheckEquals(Ord(TTlsAlertDescription.DecodeError), Ord(LSink.FailedAlert), 'alert');
  finally
    LDriver.Free;
    LLayer.Free;
  end;
end;

procedure TTestHandshakeDriver.TestDriverFailsClosedOnUndeliverableVerdictPark;
var
  LLayer: TRecordLayer;
  LDriver: THandshakeDriver;
  LSink: TMockHandshakeSink;
  LSinkRef: IHandshakeSink;
begin
  // the mock sink carries no verdict handling: a park it cannot deliver would wedge the
  // handshake forever, so the driver must fail it closed instead
  LLayer := TRecordLayer.Create;
  LSink := TMockHandshakeSink.Create;
  LSinkRef := LSink;
  LDriver := THandshakeDriver.Create(THandshakeChannel.Create(LLayer) as IHandshakeChannel, nil,
    LSinkRef);
  try
    LDriver.Apply(THandshakeEffects.AwaitCertificateVerdict(
      TArray<TBytes>.Create(DecodeHex('3003020100')), nil, 'localhost', nil,
      TRevocationPosture.Soft));
    CheckTrue(LSink.Failed, 'an undeliverable verdict park fails the handshake');
    CheckEquals(Ord(TTlsAlertDescription.InternalError), Ord(LSink.FailedAlert),
      'the failure is internal_error: our side could not carry the park');
  finally
    LDriver.Free;
    LLayer.Free;
  end;
end;

procedure TTestHandshakeDriver.TestDriverForwardsTheFailReasonToTheSink;
var
  LLayer: TRecordLayer;
  LDriver: THandshakeDriver;
  LSink: TMockHandshakeSink;
  LSinkRef: IHandshakeSink;
begin
  LLayer := TRecordLayer.Create;
  LSink := TMockHandshakeSink.Create;
  LSinkRef := LSink;
  LDriver := THandshakeDriver.Create(THandshakeChannel.Create(LLayer) as IHandshakeChannel, nil,
    LSinkRef);
  try
    LDriver.Apply(THandshakeEffects.Fail(TTlsAlertDescription.DecodeError, SProbeReason));
    CheckEquals(SProbeReason, LSink.FailedReason, 'the effect reason reaches the sink');
  finally
    LDriver.Free;
    LLayer.Free;
  end;
end;

procedure TTestHandshakeDriver.TestTryFromExceptionCarriesTheFatalAlertMessage;
var
  LError: Exception;
  LEffect: THandshakeEffect;
begin
  LError := EFatalAlertTlsLibException.CreateRes(TTlsAlertDescription.HandshakeFailure,
    @SProbeReason);
  try
    CheckTrue(THandshakeEffects.TryFromException(LError, LEffect), 'the fatal alert maps to Fail');
    CheckEquals(SProbeReason, LEffect.Reason, 'the exception message is the reason');
  finally
    LError.Free;
  end;
end;

procedure TTestHandshakeDriver.TestTryFromExceptionCarriesThePeerInputMessage;
var
  LError: Exception;
  LEffect: THandshakeEffect;
begin
  LError := EPeerInputTlsLibException.CreateRes(@SProbeReason);
  try
    CheckTrue(THandshakeEffects.TryFromException(LError, LEffect), 'peer input maps to Fail');
    CheckEquals(Ord(TTlsAlertDescription.IllegalParameter), Ord(LEffect.Alert),
      'peer input stays illegal_parameter');
    CheckEquals(SProbeReason, LEffect.Reason, 'the exception message is the reason');
  finally
    LError.Free;
  end;
end;

procedure TTestHandshakeDriver.TestUndeliverableVerdictParkSaysWhy;
var
  LLayer: TRecordLayer;
  LDriver: THandshakeDriver;
  LSink: TMockHandshakeSink;
  LSinkRef: IHandshakeSink;
begin
  LLayer := TRecordLayer.Create;
  LSink := TMockHandshakeSink.Create;
  LSinkRef := LSink;
  LDriver := THandshakeDriver.Create(THandshakeChannel.Create(LLayer) as IHandshakeChannel, nil,
    LSinkRef);
  try
    LDriver.Apply(THandshakeEffects.AwaitCertificateVerdict(
      TArray<TBytes>.Create(DecodeHex('3003020100')), nil, 'localhost', nil,
      TRevocationPosture.Soft));
    CheckEquals('the handshake parked for a certificate verdict that nothing can deliver',
      LSink.FailedReason, 'the failure says the park could not be delivered');
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
