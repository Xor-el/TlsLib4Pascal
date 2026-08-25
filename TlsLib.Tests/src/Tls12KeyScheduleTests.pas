{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit Tls12KeyScheduleTests;

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
  TlpTlsContentType,
  TlpISecretBuffer,
  TlpSecretBuffer,
  TlpICryptoProvider,
  TlpCryptoAlgorithms,
  TlpIRecordProtection,
  TlpRecordProtection,
  TlpIKeySchedule,
  TlpTls12KeySchedule,
  TlsLibTestBase;

type
  TTestTls12KeySchedule = class(TTlsLibAlgorithmTestCase)
  private
    function NewSchedule: ITls12KeySchedule;
  published
    procedure TestPrfSha256KnownAnswer;
    procedure TestMasterSecretAndKeyBlockRoundTrip;
    procedure TestExtendedMasterSecretChangesTheMaster;
    procedure TestVerifyDataComputeAndReject;
    procedure TestExporterIsDeterministic;
  end;

implementation

const
  // fixed, arbitrary handshake inputs for the derivation round-trips
  PreMasterHex = '0102030405060708090a0b0c0d0e0f101112131415161718' +
    '1112131415161718191a1b1c1d1e1f20';
  ClientRandomHex = 'a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf';
  ServerRandomHex = 'c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf';
  SessionHashHex = 'e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff';

{ TTestTls12KeySchedule }

function TTestTls12KeySchedule.NewSchedule: ITls12KeySchedule;
begin
  // TLS_ECDHE_..._WITH_AES_128_GCM_SHA256: PRF SHA-256, 16-byte key, 4-byte GCM salt
  Result := TTls12KeySchedule.Create(Provider, THashAlgorithm.SHA_256, 16,
    TAeadAlgorithm.AES_128_GCM);
  Result.SetPreMasterSecret(TSecretBuffer.From(DecodeHex(PreMasterHex)));
  Result.SetRandoms(DecodeHex(ClientRandomHex), DecodeHex(ServerRandomHex));
end;

procedure TTestTls12KeySchedule.TestPrfSha256KnownAnswer;
var
  LVec: TStringList;
  LOutput: TBytes;
begin
  LVec := LoadVectorFields('Tls12/PrfSha256.txt');
  try
    LOutput := TTls12Prf.Compute(Provider, THashAlgorithm.SHA_256,
      TSecretBuffer.From(DecodeHex(LVec.Values['secret'])),
      LVec.Values['label'], DecodeHex(LVec.Values['seed']),
      StrToInt(LVec.Values['length']));
    CheckEqualBytes('PRF-SHA256 output', DecodeHex(LVec.Values['output']), LOutput);
  finally
    LVec.Free;
  end;
end;

procedure TTestTls12KeySchedule.TestMasterSecretAndKeyBlockRoundTrip;
var
  LSched: ITls12KeySchedule;
  LKeys: ITrafficKeys;
  LSender, LReceiver: IRecordProtection;
  LPlain, LRecord, LRoundTrip: TBytes;
  LType: TTlsContentType;
begin
  LSched := NewSchedule;
  LSched.DeriveMasterSecret;
  LSched.DeriveKeyBlock;
  // the client write (key, salt) must drive TLS 1.2 AEAD record protection
  LKeys := LSched.TrafficKeys(TTlsEpoch.Application, TTlsDirection.ClientWrite);
  LSender := TTls12RecordProtection.Create(LKeys.Key, LKeys.Iv,
    Provider.Primitives.CreateAead(TAeadAlgorithm.AES_128_GCM));
  LReceiver := TTls12RecordProtection.Create(LKeys.Key, LKeys.Iv,
    Provider.Primitives.CreateAead(TAeadAlgorithm.AES_128_GCM));
  LPlain := DecodeHex('141516171819');
  LRecord := LSender.Protect(TTlsContentType.ApplicationData, LPlain, 0,
    System.Length(LPlain));
  LRoundTrip := LReceiver.Unprotect(LRecord, 0, System.Length(LRecord), LType);
  CheckEqualBytes('derived keys round-trip a record', LPlain, LRoundTrip);
  CheckEquals(Ord(TTlsContentType.ApplicationData), Ord(LType), 'content type');
end;

procedure TTestTls12KeySchedule.TestExtendedMasterSecretChangesTheMaster;
var
  LPlain, LEms: ITls12KeySchedule;
  LHash: TBytes;
begin
  // same inputs, plain vs Extended Master Secret -> different verify_data
  LHash := DecodeHex(SessionHashHex);
  LPlain := NewSchedule;
  LPlain.DeriveMasterSecret;
  LEms := NewSchedule;
  LEms.DeriveExtendedMasterSecret(DecodeHex(SessionHashHex));
  CheckFalse(AreEqual(
    LPlain.ComputeVerifyData(TTlsDirection.ClientWrite, LHash),
    LEms.ComputeVerifyData(TTlsDirection.ClientWrite, LHash)),
    'EMS derives a different master secret');
end;

procedure TTestTls12KeySchedule.TestVerifyDataComputeAndReject;
var
  LSched: ITls12KeySchedule;
  LHash, LVerifyData, LTampered: TBytes;
begin
  LSched := NewSchedule;
  LSched.DeriveMasterSecret;
  LHash := DecodeHex(SessionHashHex);
  LVerifyData := LSched.ComputeVerifyData(TTlsDirection.ClientWrite, LHash);
  CheckEquals(12, System.Length(LVerifyData), 'verify_data is 12 bytes');
  CheckTrue(LSched.VerifyFinished(TTlsDirection.ClientWrite, LHash, LVerifyData),
    'genuine verify_data accepted');
  LTampered := System.Copy(LVerifyData);
  LTampered[0] := Byte(LTampered[0] xor $01);
  CheckFalse(LSched.VerifyFinished(TTlsDirection.ClientWrite, LHash, LTampered),
    'a wrong MAC is rejected');
  // a client Finished must not verify as a server Finished (label separation)
  CheckFalse(LSched.VerifyFinished(TTlsDirection.ServerWrite, LHash, LVerifyData),
    'client and server verify_data are distinct');
end;

procedure TTestTls12KeySchedule.TestExporterIsDeterministic;
var
  LSched: ITls12KeySchedule;
  LFirst, LSecond: TBytes;
begin
  LSched := NewSchedule;
  LSched.DeriveMasterSecret;
  LFirst := LSched.ExportKeyingMaterial('EXPORTER-test', DecodeHex('00010203'), True, 32);
  LSecond := LSched.ExportKeyingMaterial('EXPORTER-test', DecodeHex('00010203'), True, 32);
  CheckEquals(32, System.Length(LFirst), 'requested length honored');
  CheckEqualBytes('exporter is deterministic', LFirst, LSecond);
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestTls12KeySchedule);
{$ELSE}
  RegisterTest(TTestTls12KeySchedule.Suite);
{$ENDIF FPC}

end.
