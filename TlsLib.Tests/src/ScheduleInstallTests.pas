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
  TlpCryptoDomainTypes,
  TlpIRecordProtection,
  TlpRecordProtectionFactory,
  TlpIKeySchedule,
  TlpTls13KeySchedule,
  TlpTls12KeySchedule,
  TlpRecordLayer,
  TlsLibTestBase;

type
  TTestScheduleInstall = class(TTlsLibAlgorithmTestCase)
  published
    procedure TestTls13InstalledScheduleDecryptsRfc8448RecordThroughRecordLayer;
    procedure TestTls12InstalledScheduleRoundTripsThroughRecordLayer;
    procedure TestUnsupportedVersionRejected;
  end;

implementation

const
  Tls12PreMasterHex = '0102030405060708090a0b0c0d0e0f10' +
    '1112131415161718191a1b1c1d1e1f20';
  Tls12ClientRandomHex = 'a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf';
  Tls12ServerRandomHex = 'c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf';

{ TTestScheduleInstall }

procedure TTestScheduleInstall.TestTls13InstalledScheduleDecryptsRfc8448RecordThroughRecordLayer;
var
  LSched: ITls13KeySchedule;
  LKeys: ITrafficKeys;
  LProt: IRecordProtection;
  LLayer: TRecordLayer;
  LVec, LRec: TStringList;
  LRecord: TBytes;
  LFragment: TTlsRecordFragment;
begin
  LVec := LoadVectorFields('Rfc8448/Tls13KeySchedule.txt');
  LRec := LoadVectorFields('Rfc8448/Tls13RecordFinished.txt');
  try
    // derive the RFC 8448 client handshake epoch and route its keys through the
    // install-path factory into the record layer's read side
    LSched := TTls13KeySchedule.Create(Crypto, THashAlgorithm.SHA_256, 16);
    LSched.SetSharedSecret(TSecretBuffer.From(DecodeHex(LVec.Values['shared_secret'])));
    LSched.DeriveEpochSecrets(TTlsEpoch.Handshake, DecodeHex(LVec.Values['hash_ch_sh']));
    LKeys := LSched.TrafficKeys(TTlsEpoch.Handshake, TTlsDirection.ClientWrite);
    LProt := TRecordProtectionFactory.Build(TTlsVersion.Tls13, LKeys,
      Crypto.Primitives.CreateAead(TAeadAlgorithm.AES_128_GCM));

    LLayer := TRecordLayer.Create;
    try
      LLayer.SetReadProtection(LProt);
      LRecord := DecodeHex(LRec.Values['record']);
      LLayer.ProcessInput(LRecord, 0, System.Length(LRecord));
      CheckTrue(LLayer.NextIncoming(LFragment), 'the framed record decrypts');
      CheckEquals(Ord(TTlsContentType.Handshake), Ord(LFragment.ContentType),
        'the decrypted record is a handshake fragment');
      CheckEqualBytes('the record layer decrypts the RFC 8448 Finished',
        DecodeHex(LRec.Values['plaintext']), LFragment.Data);
    finally
      LLayer.Free;
    end;
  finally
    LVec.Free;
    LRec.Free;
  end;
end;

procedure TTestScheduleInstall.TestTls12InstalledScheduleRoundTripsThroughRecordLayer;
var
  LSched: ITls12KeySchedule;
  LKeys: ITrafficKeys;
  LSender, LReceiver: IRecordProtection;
  LLayer: TRecordLayer;
  LPlain, LWire: TBytes;
  LFragment: TTlsRecordFragment;
begin
  // derive the TLS 1.2 application keys, install the read side, and confirm a record
  // the same keys produced surfaces as application data
  LSched := TTls12KeySchedule.Create(Crypto, THashAlgorithm.SHA_256, 16,
    TAeadAlgorithm.AES_128_GCM);
  LSched.SetPreMasterSecret(TSecretBuffer.From(DecodeHex(Tls12PreMasterHex)));
  LSched.SetRandoms(DecodeHex(Tls12ClientRandomHex), DecodeHex(Tls12ServerRandomHex));
  LSched.DeriveMasterSecret;
  LSched.DeriveKeyBlock;
  LKeys := LSched.TrafficKeys(TTlsEpoch.Application, TTlsDirection.ClientWrite);

  LSender := TRecordProtectionFactory.Build(TTlsVersion.Tls12, LKeys,
    Crypto.Primitives.CreateAead(TAeadAlgorithm.AES_128_GCM));
  LReceiver := TRecordProtectionFactory.Build(TTlsVersion.Tls12, LKeys,
    Crypto.Primitives.CreateAead(TAeadAlgorithm.AES_128_GCM));

  LLayer := TRecordLayer.Create;
  try
    LLayer.SetReadProtection(LReceiver);
    LPlain := DecodeHex('746c7320312e32206170702064617461'); // "tls 1.2 app data"
    LWire := LSender.Protect(TTlsContentType.ApplicationData, LPlain, 0,
      System.Length(LPlain));
    LLayer.ProcessInput(LWire, 0, System.Length(LWire));
    CheckTrue(LLayer.NextIncoming(LFragment), 'the framed record decrypts');
    CheckEquals(Ord(TTlsContentType.ApplicationData), Ord(LFragment.ContentType),
      'the decrypted record is application data');
    CheckEqualBytes('the record layer decrypts the TLS 1.2 record', LPlain,
      LFragment.Data);
  finally
    LLayer.Free;
  end;
end;

procedure TTestScheduleInstall.TestUnsupportedVersionRejected;
var
  LSched: ITls13KeySchedule;
  LKeys: ITrafficKeys;
  LRaised: Boolean;
begin
  LSched := TTls13KeySchedule.Create(Crypto, THashAlgorithm.SHA_256, 16);
  LSched.SetSharedSecret(TSecretBuffer.From(DecodeHex('00')));
  LSched.DeriveEpochSecrets(TTlsEpoch.Handshake, DecodeHex('00'));
  LKeys := LSched.TrafficKeys(TTlsEpoch.Handshake, TTlsDirection.ClientWrite);
  LRaised := False;
  try
    // 0x0301 is a legacy record version, never a negotiable protocol
    TRecordProtectionFactory.Build(TTlsVersion.LegacyRecordInitial, LKeys,
      Crypto.Primitives.CreateAead(TAeadAlgorithm.AES_128_GCM));
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
