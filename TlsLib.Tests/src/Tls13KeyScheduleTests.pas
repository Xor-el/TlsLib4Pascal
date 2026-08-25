{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit Tls13KeyScheduleTests;

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
  TlpHkdfLabel,
  TlpIKeySchedule,
  TlpTls13KeySchedule,
  TlpITranscriptHash,
  TlpTranscriptHash,
  TlpISession,
  TlpSession,
  TlpExternalPskImporter,
  TlsLibTestBase;

type
  TTestTls13KeySchedule = class(TTlsLibAlgorithmTestCase)
  private
    FVec: TStringList;
    function NewSchedule: TTls13KeySchedule;
    function NewResumptionSchedule(const APsk: ISecretBuffer;
      const ASharedSecret: TBytes): ITls13KeySchedule;
    function Bytes(const AName: string): TBytes;
    function ToBytes(const ASecret: ISecretBuffer): TBytes;
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestSecretTreeRfc8448;
    procedure TestTrafficKeysRfc8448;
    procedure TestClientFinishedVerifyDataRfc8448;
    procedure TestFinishedRoundTripAndRejectsWrongMac;
    procedure TestDerivedKeysDecryptRfc8448Record;
    procedure TestKeyUpdateAdvancesTheKey;
    procedure TestExporterIsDeterministic;
    procedure TestBinderKeyResumptionVsExternalDiffer;
    procedure TestBinderRoundTripConstantTime;
    procedure TestPskDheKeAgreesOnBothSides;
    procedure TestPskDheKeDiffersFromPskKe;
    procedure TestPartialTranscriptForBinder;
    procedure TestExternalPskImporterIdentityAndBinder;
  end;

implementation

{ TTestTls13KeySchedule }

procedure TTestTls13KeySchedule.SetUp;
begin
  inherited SetUp;
  FVec := LoadVectorFields('Rfc8448/Tls13KeySchedule.txt');
end;

procedure TTestTls13KeySchedule.TearDown;
begin
  FVec.Free;
  inherited TearDown;
end;

function TTestTls13KeySchedule.Bytes(const AName: string): TBytes;
begin
  Result := DecodeHex(FVec.Values[AName]);
end;

function TTestTls13KeySchedule.ToBytes(const ASecret: ISecretBuffer): TBytes;
begin
  Result := ASecret.ToBytes;
end;

function TTestTls13KeySchedule.NewSchedule: TTls13KeySchedule;
begin
  // the RFC 8448 sample suite is TLS_AES_128_GCM_SHA256
  Result := TTls13KeySchedule.Create(Provider, THashAlgorithm.SHA_256, 16);
  Result.SetSharedSecret(TSecretBuffer.From(Bytes('shared_secret')));
end;

function TTestTls13KeySchedule.NewResumptionSchedule(const APsk: ISecretBuffer;
  const ASharedSecret: TBytes): ITls13KeySchedule;
begin
  Result := TTls13KeySchedule.Create(Provider, THashAlgorithm.SHA_256, 16);
  Result.SetPsk(APsk);
  if System.Length(ASharedSecret) > 0 then
    Result.SetSharedSecret(TSecretBuffer.From(ASharedSecret));
end;

procedure TTestTls13KeySchedule.TestSecretTreeRfc8448;
var
  LHkdf: IHkdf;
  LZeros: ISecretBuffer;
  LEmptyHash: TBytes;
  LEarly, LDerived, LHandshake, LMaster: ISecretBuffer;
  LResumption: ITls13KeySchedule;
begin
  // recompute the RFC 8448 secret tree through the public HKDF seam and pin every
  // node against the published bytes - no reaching into the schedule's internals
  LHkdf := Provider.Primitives.CreateHkdf(THashAlgorithm.SHA_256);
  LZeros := TSecretBuffer.Allocate(32);
  LEmptyHash := Provider.Primitives.CreateHash(THashAlgorithm.SHA_256).DoFinal;

  LEarly := LHkdf.Extract(nil, LZeros); // 0-PSK: salt and IKM are HashLen zeros
  CheckEqualBytes('early secret', Bytes('early_secret'), ToBytes(LEarly));

  LDerived := THkdfLabel.DeriveSecret(LHkdf, LEarly, 'derived', LEmptyHash);
  LHandshake := LHkdf.Extract(ToBytes(LDerived),
    TSecretBuffer.From(Bytes('shared_secret')));
  CheckEqualBytes('handshake secret', Bytes('handshake_secret'), ToBytes(LHandshake));

  LDerived := THkdfLabel.DeriveSecret(LHkdf, LHandshake, 'derived', LEmptyHash);
  LMaster := LHkdf.Extract(ToBytes(LDerived), LZeros);
  CheckEqualBytes('master secret', Bytes('master_secret'), ToBytes(LMaster));

  CheckEqualBytes('c hs traffic', Bytes('c_hs_traffic'), ToBytes(
    THkdfLabel.DeriveSecret(LHkdf, LHandshake, 'c hs traffic', Bytes('hash_ch_sh'))));
  CheckEqualBytes('s hs traffic', Bytes('s_hs_traffic'), ToBytes(
    THkdfLabel.DeriveSecret(LHkdf, LHandshake, 's hs traffic', Bytes('hash_ch_sh'))));
  CheckEqualBytes('c ap traffic', Bytes('c_ap_traffic'), ToBytes(
    THkdfLabel.DeriveSecret(LHkdf, LMaster, 'c ap traffic', Bytes('hash_ch_sf'))));
  CheckEqualBytes('s ap traffic', Bytes('s_ap_traffic'), ToBytes(
    THkdfLabel.DeriveSecret(LHkdf, LMaster, 's ap traffic', Bytes('hash_ch_sf'))));
  CheckEqualBytes('exporter master', Bytes('exp_master'), ToBytes(
    THkdfLabel.DeriveSecret(LHkdf, LMaster, 'exp master', Bytes('hash_ch_sf'))));

  // the resumption master secret is the schedule's own public output
  LResumption := NewSchedule;
  CheckEqualBytes('resumption master', Bytes('res_master'),
    ToBytes(LResumption.ResumptionMasterSecret(Bytes('hash_ch_cf'))));
end;

procedure TTestTls13KeySchedule.TestTrafficKeysRfc8448;
var
  LSched: ITls13KeySchedule;
  LKeys: ITrafficKeys;
begin
  LSched := NewSchedule;
  LSched.DeriveEpochSecrets(TTlsEpoch.Handshake, Bytes('hash_ch_sh'));
  LSched.DeriveEpochSecrets(TTlsEpoch.Application, Bytes('hash_ch_sf'));

  LKeys := LSched.TrafficKeys(TTlsEpoch.Handshake, TTlsDirection.ClientWrite);
  CheckEqualBytes('c hs key', Bytes('c_hs_key'), ToBytes(LKeys.Key));
  CheckEqualBytes('c hs iv', Bytes('c_hs_iv'), ToBytes(LKeys.Iv));

  LKeys := LSched.TrafficKeys(TTlsEpoch.Handshake, TTlsDirection.ServerWrite);
  CheckEqualBytes('s hs key', Bytes('s_hs_key'), ToBytes(LKeys.Key));
  CheckEqualBytes('s hs iv', Bytes('s_hs_iv'), ToBytes(LKeys.Iv));

  LKeys := LSched.TrafficKeys(TTlsEpoch.Application, TTlsDirection.ClientWrite);
  CheckEqualBytes('c ap key', Bytes('c_ap_key'), ToBytes(LKeys.Key));
  CheckEqualBytes('c ap iv', Bytes('c_ap_iv'), ToBytes(LKeys.Iv));

  LKeys := LSched.TrafficKeys(TTlsEpoch.Application, TTlsDirection.ServerWrite);
  CheckEqualBytes('s ap key', Bytes('s_ap_key'), ToBytes(LKeys.Key));
  CheckEqualBytes('s ap iv', Bytes('s_ap_iv'), ToBytes(LKeys.Iv));
end;

procedure TTestTls13KeySchedule.TestClientFinishedVerifyDataRfc8448;
var
  LSched: ITls13KeySchedule;
begin
  LSched := NewSchedule;
  LSched.DeriveEpochSecrets(TTlsEpoch.Handshake, Bytes('hash_ch_sh'));
  // the client Finished is over Transcript-Hash(ClientHello..server Finished)
  CheckEqualBytes('client verify_data', Bytes('client_verify_data'),
    LSched.ComputeVerifyData(TTlsDirection.ClientWrite, Bytes('hash_ch_sf')));
  CheckTrue(LSched.VerifyFinished(TTlsDirection.ClientWrite, Bytes('hash_ch_sf'),
    Bytes('client_verify_data')), 'genuine verify_data accepted');
end;

procedure TTestTls13KeySchedule.TestFinishedRoundTripAndRejectsWrongMac;
var
  LSched: ITls13KeySchedule;
  LHash, LVerifyData, LTampered: TBytes;
begin
  LSched := NewSchedule;
  LSched.DeriveEpochSecrets(TTlsEpoch.Handshake, Bytes('hash_ch_sh'));
  LHash := Bytes('hash_ch_sf');
  // server direction compute -> verify round-trip (constant-time path)
  LVerifyData := LSched.ComputeVerifyData(TTlsDirection.ServerWrite, LHash);
  CheckTrue(LSched.VerifyFinished(TTlsDirection.ServerWrite, LHash, LVerifyData),
    'server verify_data round-trips');
  LTampered := System.Copy(LVerifyData);
  LTampered[0] := Byte(LTampered[0] xor $01);
  CheckFalse(LSched.VerifyFinished(TTlsDirection.ServerWrite, LHash, LTampered),
    'a wrong MAC is rejected');
end;

procedure TTestTls13KeySchedule.TestDerivedKeysDecryptRfc8448Record;
var
  LSched: ITls13KeySchedule;
  LKeys: ITrafficKeys;
  LProt: IRecordProtection;
  LRec: TStringList;
  LRecord, LPlain: TBytes;
  LType: TTlsContentType;
begin
  LSched := NewSchedule;
  LSched.DeriveEpochSecrets(TTlsEpoch.Handshake, Bytes('hash_ch_sh'));
  // the schedule-derived client handshake keys must decrypt the RFC 8448 record
  LKeys := LSched.TrafficKeys(TTlsEpoch.Handshake, TTlsDirection.ClientWrite);
  LProt := TTls13RecordProtection.Create(LKeys.Key, LKeys.Iv,
    Provider.Primitives.CreateAead(TAeadAlgorithm.AES_128_GCM));
  LRec := LoadVectorFields('Rfc8448/Tls13RecordFinished.txt');
  try
    LRecord := DecodeHex(LRec.Values['record']);
    LPlain := LProt.Unprotect(LRecord, 0, System.Length(LRecord), LType);
    CheckEqualBytes('decrypted client Finished',
      DecodeHex(LRec.Values['plaintext']), LPlain);
    CheckEquals(Ord(TTlsContentType.Handshake), Ord(LType), 'inner type');
  finally
    LRec.Free;
  end;
end;

procedure TTestTls13KeySchedule.TestKeyUpdateAdvancesTheKey;
var
  LSched: ITls13KeySchedule;
  LBefore, LAfter: TBytes;
begin
  LSched := NewSchedule;
  LSched.DeriveEpochSecrets(TTlsEpoch.Application, Bytes('hash_ch_sf'));
  LBefore := ToBytes(LSched.TrafficKeys(TTlsEpoch.Application,
    TTlsDirection.ClientWrite).Key);
  LSched.AdvanceKeyUpdate(TTlsDirection.ClientWrite);
  LAfter := ToBytes(LSched.TrafficKeys(TTlsEpoch.Application,
    TTlsDirection.ClientWrite).Key);
  CheckFalse(AreEqual(LBefore, LAfter), 'a key update changes the traffic key');
end;

procedure TTestTls13KeySchedule.TestExporterIsDeterministic;
var
  LSched: ITls13KeySchedule;
  LFirst, LSecond: TBytes;
begin
  LSched := NewSchedule;
  LSched.DeriveEpochSecrets(TTlsEpoch.Application, Bytes('hash_ch_sf'));
  LFirst := LSched.ExportKeyingMaterial('EXPORTER-test', DecodeHex('00010203'), True, 32);
  LSecond := LSched.ExportKeyingMaterial('EXPORTER-test', DecodeHex('00010203'), True, 32);
  CheckEquals(32, System.Length(LFirst), 'requested length honored');
  CheckEqualBytes('exporter is deterministic', LFirst, LSecond);
end;

procedure TTestTls13KeySchedule.TestBinderKeyResumptionVsExternalDiffer;
var
  LSched: ITls13KeySchedule;
  LPsk: ISecretBuffer;
begin
  LPsk := TSecretBuffer.From(DecodeHex('0102030405060708090A0B0C0D0E0F10'));
  LSched := NewResumptionSchedule(LPsk, nil);
  // "res binder", "ext binder" and "imp binder" derive distinct binder keys from one
  // early secret, so a key provisioned for one role cannot be replayed in another
  CheckFalse(AreEqual(ToBytes(LSched.BinderKey(TPskBinderKind.Resumption)),
    ToBytes(LSched.BinderKey(TPskBinderKind.External))),
    'the resumption and external binder keys differ');
  CheckFalse(AreEqual(ToBytes(LSched.BinderKey(TPskBinderKind.External)),
    ToBytes(LSched.BinderKey(TPskBinderKind.Imported))),
    'the external and imported binder keys differ');
end;

procedure TTestTls13KeySchedule.TestBinderRoundTripConstantTime;
var
  LSched: ITls13KeySchedule;
  LPsk: ISecretBuffer;
  LTruncatedHash, LBinder, LTampered: TBytes;
begin
  LPsk := TSecretBuffer.From(DecodeHex('AABBCCDDEEFF00112233445566778899'));
  LSched := NewResumptionSchedule(LPsk, nil);
  LTruncatedHash := Provider.Primitives.CreateHash(THashAlgorithm.SHA_256).DoFinal;
  LBinder := LSched.ComputeBinder(TPskBinderKind.Resumption, LTruncatedHash);
  CheckTrue(LSched.VerifyBinder(TPskBinderKind.Resumption, LTruncatedHash, LBinder),
    'a genuine binder verifies');
  LTampered := System.Copy(LBinder);
  LTampered[0] := Byte(LTampered[0] xor $01);
  CheckFalse(LSched.VerifyBinder(TPskBinderKind.Resumption, LTruncatedHash, LTampered),
    'a tampered binder is rejected');
end;

procedure TTestTls13KeySchedule.TestPskDheKeAgreesOnBothSides;
var
  LClient, LServer: ITls13KeySchedule;
  LPsk: ISecretBuffer;
  LShared, LHash, LTrunc: TBytes;
begin
  // the client and server, given the same resumption PSK and the same fresh (EC)DHE
  // shared secret, derive identical binder, traffic keys and Finished verify_data
  LPsk := TSecretBuffer.From(DecodeHex('1122334455667788990011223344556677889900AABBCCDD'));
  LShared := DecodeHex('9FA1E9C3B6D2074F5E8A0C1D2B3A4958677685948382718065544332211009FF');
  LHash := Bytes('hash_ch_sh');
  LTrunc := Provider.Primitives.CreateHash(THashAlgorithm.SHA_256).DoFinal;

  LClient := NewResumptionSchedule(LPsk, LShared);
  LServer := NewResumptionSchedule(LPsk, LShared);

  CheckEqualBytes('both sides compute the same binder',
    LClient.ComputeBinder(TPskBinderKind.Resumption, LTrunc),
    LServer.ComputeBinder(TPskBinderKind.Resumption, LTrunc));
  CheckTrue(LServer.VerifyBinder(TPskBinderKind.Resumption, LTrunc,
    LClient.ComputeBinder(TPskBinderKind.Resumption, LTrunc)),
    'the server verifies the client binder');

  LClient.DeriveEpochSecrets(TTlsEpoch.Handshake, LHash);
  LServer.DeriveEpochSecrets(TTlsEpoch.Handshake, LHash);
  CheckEqualBytes('c hs keys agree',
    ToBytes(LClient.TrafficKeys(TTlsEpoch.Handshake, TTlsDirection.ClientWrite).Key),
    ToBytes(LServer.TrafficKeys(TTlsEpoch.Handshake, TTlsDirection.ClientWrite).Key));
  CheckEqualBytes('s hs keys agree',
    ToBytes(LClient.TrafficKeys(TTlsEpoch.Handshake, TTlsDirection.ServerWrite).Key),
    ToBytes(LServer.TrafficKeys(TTlsEpoch.Handshake, TTlsDirection.ServerWrite).Key));
end;

procedure TTestTls13KeySchedule.TestPskDheKeDiffersFromPskKe;
var
  LDhe, LKe: ITls13KeySchedule;
  LPsk: ISecretBuffer;
  LShared, LHash: TBytes;
begin
  // folding a fresh (EC)DHE secret in (psk_dhe_ke) must change the handshake keys
  // versus PSK-only (psk_ke) - proving the shared secret is actually composed
  LPsk := TSecretBuffer.From(DecodeHex('00112233445566778899AABBCCDDEEFF'));
  LShared := DecodeHex('DEADBEEFCAFEBABE0011223344556677889900AABBCCDDEEFF0102030405060708');
  LHash := Bytes('hash_ch_sh');
  LDhe := NewResumptionSchedule(LPsk, LShared);
  LKe := NewResumptionSchedule(LPsk, nil);
  LDhe.DeriveEpochSecrets(TTlsEpoch.Handshake, LHash);
  LKe.DeriveEpochSecrets(TTlsEpoch.Handshake, LHash);
  CheckFalse(AreEqual(
    ToBytes(LDhe.TrafficKeys(TTlsEpoch.Handshake, TTlsDirection.ClientWrite).Key),
    ToBytes(LKe.TrafficKeys(TTlsEpoch.Handshake, TTlsDirection.ClientWrite).Key)),
    'psk_dhe_ke keys differ from psk_ke keys');
end;

procedure TTestTls13KeySchedule.TestPartialTranscriptForBinder;
var
  LTranscript: ITranscriptHash;
  LPrefix, LViaTranscript, LManual: TBytes;
begin
  // HashPrefixExcludingBinders(prefix) == Hash(running transcript || prefix)
  LTranscript := TTranscriptHash.Create(Provider.Primitives.CreateHash(THashAlgorithm.SHA_256));
  LTranscript.Update(DecodeHex('AABBCCDD')); // some prior transcript bytes
  LPrefix := DecodeHex('0100000504030201'); // a partial ClientHello prefix
  LViaTranscript := LTranscript.HashPrefixExcludingBinders(LPrefix);
  // recompute manually: the same prior bytes then the prefix
  LManual := Provider.Primitives.CreateHash(THashAlgorithm.SHA_256).DoFinal; // placeholder
  LTranscript.Update(LPrefix);
  LManual := LTranscript.CurrentHash;
  CheckEqualBytes('the partial-transcript hash matches feeding the prefix',
    LManual, LViaTranscript);
end;

procedure TTestTls13KeySchedule.TestExternalPskImporterIdentityAndBinder;
var
  LSpec: TExternalPsk;
  LImp256, LImp384: IPreSharedKey;
  LExternalId, LExpectedId, LTrunc, LImpBinder: TBytes;
  LClient, LServer: ITls13KeySchedule;
begin
  LExternalId := TBytes.Create($61, $62); // "ab"
  // ImportedIdentity (RFC 9258 5.1): uint16-len external_identity, uint16-len context,
  // uint16 target_protocol (TLS 1.3 = 0x0304), uint16 target_kdf (HKDF-SHA256 = 0x0001)
  LExpectedId := TBytes.Create($00, $02, $61, $62, $00, $00, $03, $04, $00, $01);
  CheckEqualBytes('the imported identity is laid out per RFC 9258 5.1', LExpectedId,
    TExternalPskImporter.ImportedIdentity(LExternalId, nil, $0304, $0001));

  LSpec.Identity := LExternalId;
  LSpec.Secret := TSecretBuffer.From(DecodeHex('00112233445566778899AABBCCDDEEFF'));
  LSpec.Context := nil;
  LSpec.Hash := THashAlgorithm.SHA_256;
  LImp256 := TExternalPskImporter.Import(Provider, LSpec, $0304, THashAlgorithm.SHA_256);
  LImp384 := TExternalPskImporter.Import(Provider, LSpec, $0304, THashAlgorithm.SHA_384);
  // importing the same secret for a different target hash yields a distinct wire identity
  // (its target_kdf differs) and a distinct bound hash
  CheckFalse(AreEqual(LImp256.Identity, LImp384.Identity),
    'the SHA-256 and SHA-384 imports carry distinct identities');
  CheckEquals(Ord(THashAlgorithm.SHA_256), Ord(LImp256.Hash), 'SHA-256 import bound hash');
  CheckEquals(Ord(THashAlgorithm.SHA_384), Ord(LImp384.Hash), 'SHA-384 import bound hash');

  // the "imp binder" (RFC 9258 6) over the imported key round-trips between the two sides,
  // and is distinct from a resumption ("res binder") over the same key
  LClient := TTls13KeySchedule.Create(Provider, LImp256.Hash, 16);
  LClient.SetPsk(LImp256.Key);
  LServer := TTls13KeySchedule.Create(Provider, LImp256.Hash, 16);
  LServer.SetPsk(LImp256.Key);
  LTrunc := Provider.Primitives.CreateHash(THashAlgorithm.SHA_256).DoFinal;
  LImpBinder := LClient.ComputeBinder(TPskBinderKind.Imported, LTrunc);
  CheckTrue(LServer.VerifyBinder(TPskBinderKind.Imported, LTrunc, LImpBinder),
    'the imported-PSK binder round-trips between client and server');
  CheckFalse(AreEqual(LImpBinder,
    LClient.ComputeBinder(TPskBinderKind.Resumption, LTrunc)),
    'the imported and resumption binders differ for the same key');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestTls13KeySchedule);
{$ELSE}
  RegisterTest(TTestTls13KeySchedule.Suite);
{$ENDIF FPC}

end.
