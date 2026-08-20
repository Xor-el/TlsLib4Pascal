{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ScheduleInstallTests;

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
  TlpTlsLibExceptions,
  TlpTlsContentType,
  TlpTlsVersion,
  TlpSecretBuffer,
  TlpICryptoProvider,
  TlpCryptoAlgorithms,
  TlpIRecordProtection,
  TlpRecordProtectionFactory,
  TlpIKeySchedule,
  TlpTls13KeySchedule,
  TlpTls12KeySchedule,
  TlpITlsEngine,
  TlpTlsEngine,
  TlsLibTestBase;

type
  TTestScheduleInstall = class(TTlsLibAlgorithmTestCase)
  private
    function NextKind(const AEngine: ITlsEngine; out AEvent: ITlsEvent): Boolean;
    function ReadAllApp(const AEngine: ITlsEngine): TBytes;
  published
    procedure TestTls13InstalledScheduleDecryptsRfc8448RecordThroughEngine;
    procedure TestTls12InstalledScheduleRoundTripsThroughEngine;
    procedure TestUnsupportedVersionRejected;
  end;

implementation

const
  Tls12PreMasterHex = '0102030405060708090a0b0c0d0e0f10' +
    '1112131415161718191a1b1c1d1e1f20';
  Tls12ClientRandomHex = 'a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf';
  Tls12ServerRandomHex = 'c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf';

{ TTestScheduleInstall }

function TTestScheduleInstall.NextKind(const AEngine: ITlsEngine;
  out AEvent: ITlsEvent): Boolean;
begin
  Result := AEngine.NextEvent(AEvent);
end;

function TTestScheduleInstall.ReadAllApp(const AEngine: ITlsEngine): TBytes;
var
  LChunk: TBytes;
  LN: Int32;
begin
  Result := nil;
  repeat
    LChunk := nil;
    SetLength(LChunk, 4096);
    LN := AEngine.ReadAppData(LChunk, 0, 4096);
    if LN > 0 then
      Result := ConcatBytes(Result, System.Copy(LChunk, 0, LN));
  until LN <= 0;
end;

procedure TTestScheduleInstall.TestTls13InstalledScheduleDecryptsRfc8448RecordThroughEngine;
var
  LSched: ITls13KeySchedule;
  LKeys: ITrafficKeys;
  LProt: IRecordProtection;
  LEngineObj: TTlsEngine;
  LEngine: ITlsEngine;
  LVec, LRec: TStringList;
  LRecord: TBytes;
  LEvent: ITlsEvent;
  LHsEvent: IHandshakeDataEvent;
begin
  LVec := LoadVectorFields('Rfc8448/Tls13KeySchedule.txt');
  LRec := LoadVectorFields('Rfc8448/Tls13RecordFinished.txt');
  try
    // derive the RFC 8448 client handshake epoch and route its keys through the
    // install-path factory into the engine's read side
    LSched := TTls13KeySchedule.Create(Provider, THashAlgorithm.SHA_256, 16);
    LSched.SetSharedSecret(TSecretBuffer.From(DecodeHex(LVec.Values['shared_secret'])));
    LSched.DeriveEpochSecrets(TTlsEpoch.Handshake, DecodeHex(LVec.Values['hash_ch_sh']));
    LKeys := LSched.TrafficKeys(TTlsEpoch.Handshake, TTlsDirection.ClientWrite);
    LProt := TRecordProtectionFactory.Build(TTlsVersion.Tls13, LKeys,
      Provider.CreateAead(TAeadAlgorithm.AES_128_GCM));

    LEngineObj := TTlsEngine.Create;
    LEngine := LEngineObj;
    // the engine no longer exposes an installer interface; the concrete install
    // method the handshake bridge uses is called directly here
    LEngineObj.InstallReadProtection(LProt);
    CheckTrue(NextKind(LEngine, LEvent), 'install queues an event');
    CheckEquals(Ord(TTlsEventKind.KeysInstalled), Ord(LEvent.Kind),
      'keys-installed event on install');

    LRecord := DecodeHex(LRec.Values['record']);
    CheckEquals(Ord(TTlsOutcome.Advanced),
      Ord(LEngine.ProcessInput(LRecord, 0, System.Length(LRecord))),
      'the record advances the engine');
    CheckTrue(NextKind(LEngine, LEvent), 'a fragment surfaces');
    CheckEquals(Ord(TTlsEventKind.HandshakeFragment), Ord(LEvent.Kind),
      'the decrypted record is a handshake fragment');
    CheckTrue(Supports(LEvent, IHandshakeDataEvent, LHsEvent), 'carries the fragment');
    CheckEqualBytes('the engine decrypts the RFC 8448 Finished',
      DecodeHex(LRec.Values['plaintext']), LHsEvent.Data);
  finally
    LVec.Free;
    LRec.Free;
  end;
end;

procedure TTestScheduleInstall.TestTls12InstalledScheduleRoundTripsThroughEngine;
var
  LSched: ITls12KeySchedule;
  LKeys: ITrafficKeys;
  LSender, LReceiver: IRecordProtection;
  LEngineObj: TTlsEngine;
  LEngine: ITlsEngine;
  LPlain, LWire: TBytes;
  LEvent: ITlsEvent;
begin
  // derive the TLS 1.2 application keys, install the read side through the factory,
  // and confirm a record the same keys produced surfaces as application data
  LSched := TTls12KeySchedule.Create(Provider, THashAlgorithm.SHA_256, 16,
    TAeadAlgorithm.AES_128_GCM);
  LSched.SetPreMasterSecret(TSecretBuffer.From(DecodeHex(Tls12PreMasterHex)));
  LSched.SetRandoms(DecodeHex(Tls12ClientRandomHex), DecodeHex(Tls12ServerRandomHex));
  LSched.DeriveMasterSecret;
  LSched.DeriveKeyBlock;
  LKeys := LSched.TrafficKeys(TTlsEpoch.Application, TTlsDirection.ClientWrite);

  LSender := TRecordProtectionFactory.Build(TTlsVersion.Tls12, LKeys,
    Provider.CreateAead(TAeadAlgorithm.AES_128_GCM));
  LReceiver := TRecordProtectionFactory.Build(TTlsVersion.Tls12, LKeys,
    Provider.CreateAead(TAeadAlgorithm.AES_128_GCM));

  LEngineObj := TTlsEngine.Create;
  LEngine := LEngineObj;
  LEngineObj.InstallReadProtection(LReceiver);
  CheckTrue(NextKind(LEngine, LEvent), 'install queues an event');
  CheckEquals(Ord(TTlsEventKind.KeysInstalled), Ord(LEvent.Kind), 'keys-installed');

  LPlain := DecodeHex('746c7320312e32206170702064617461'); // "tls 1.2 app data"
  LWire := LSender.Protect(TTlsContentType.ApplicationData, LPlain, 0,
    System.Length(LPlain));
  CheckEquals(Ord(TTlsOutcome.Advanced),
    Ord(LEngine.ProcessInput(LWire, 0, System.Length(LWire))), 'advanced');
  CheckEqualBytes('the engine decrypts the TLS 1.2 record', LPlain, ReadAllApp(LEngine));
end;

procedure TTestScheduleInstall.TestUnsupportedVersionRejected;
var
  LSched: ITls13KeySchedule;
  LKeys: ITrafficKeys;
  LRaised: Boolean;
begin
  LSched := TTls13KeySchedule.Create(Provider, THashAlgorithm.SHA_256, 16);
  LSched.SetSharedSecret(TSecretBuffer.From(DecodeHex('00')));
  LSched.DeriveEpochSecrets(TTlsEpoch.Handshake, DecodeHex('00'));
  LKeys := LSched.TrafficKeys(TTlsEpoch.Handshake, TTlsDirection.ClientWrite);
  LRaised := False;
  try
    // 0x0301 is a legacy record version, never a negotiable protocol
    TRecordProtectionFactory.Build(TTlsVersion.LegacyRecordInitial, LKeys,
      Provider.CreateAead(TAeadAlgorithm.AES_128_GCM));
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'an unsupported protocol version is rejected');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestScheduleInstall);
{$ELSE}
  RegisterTest(TTestScheduleInstall.Suite);
{$ENDIF FPC}

end.
