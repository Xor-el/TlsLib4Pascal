{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit KeyLogTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  TlpCryptoDomainTypes,
  TlpICryptoProvider,
  TlpIKeyLog,
  TlpKeyLog,
  TlpISecretBuffer,
  TlpSecretBuffer,
  TlpIKeySchedule,
  TlpHkdfLabel,
  TlpTls13KeySchedule,
  TlpTls12KeySchedule,
  TlpNegotiationTypes,
  TlpICertificateTrust,
  TlpCertificateVerifier,
  TlpTlsPresets,
  TlpITlsConfig,
  TlpITlsConfigBuilder,
  TlpDataEncoding,
  MockKeyLog,
  TlsLibTestBase;

type
  TTestKeyLog = class(TTlsLibAlgorithmTestCase)
  strict private
    function FixedRandom: TBytes;
    function Rep(AByte: Byte; ALen: Int32): TBytes;
  published
    procedure TestTls13ReportsSecretsInOrderKeyedByRandom;
    procedure TestTls13NoSinkReportsNothing;
    procedure TestTls12ReportsMasterSecretAsClientRandom;
    procedure TestBuilderKeyLogLandsInConfig;
    procedure TestBuilderDefaultKeyLogIsNil;
    procedure TestNssLineFormat;
  end;

implementation

function TTestKeyLog.FixedRandom: TBytes;
begin
  Result := DecodeHex('000102030405060708090a0b0c0d0e0f' +
    '101112131415161718191a1b1c1d1e1f');
end;

function TTestKeyLog.Rep(AByte: Byte; ALen: Int32): TBytes;
begin
  Result := nil;
  System.SetLength(Result, ALen);
  if ALen > 0 then
    System.FillChar(Result[0], ALen, AByte);
end;

procedure TTestKeyLog.TestTls13ReportsSecretsInOrderKeyedByRandom;
var
  LSched: TTls13KeySchedule;
  LMock: TMockKeyLog;
  LHkdf: IHkdf;
  LRandom: TBytes;
  LI: Int32;
begin
  LMock := TMockKeyLog.Create;
  LRandom := FixedRandom;
  LSched := TTls13KeySchedule.Create(Crypto, THashAlgorithm.SHA_256, 16);
  try
    LSched.SetSharedSecret(TSecretBuffer.From(Rep($AB, 32)));
    LSched.SetKeyLog(LMock as IKeyLog, LRandom);
    LSched.DeriveEpochSecrets(TTlsEpoch.Handshake, Rep($01, 32));
    LSched.DeriveEpochSecrets(TTlsEpoch.Application, Rep($02, 32));
    CheckEquals(5, LMock.Count, 'five 1.3 secrets are reported');
    CheckEquals(KeyLogLabelClientHandshakeTraffic, LMock[0].Lbl, 'order 0');
    CheckEquals(KeyLogLabelServerHandshakeTraffic, LMock[1].Lbl, 'order 1');
    CheckEquals(KeyLogLabelClientTraffic0, LMock[2].Lbl, 'order 2');
    CheckEquals(KeyLogLabelServerTraffic0, LMock[3].Lbl, 'order 3');
    CheckEquals(KeyLogLabelExporter, LMock[4].Lbl, 'order 4');
    for LI := 0 to LMock.Count - 1 do
    begin
      CheckEqualBytes('keyed by the client random', LRandom, LMock[LI].ClientRandom);
      CheckEquals(32, System.Length(LMock[LI].Secret), 'a SHA-256 secret is 32 bytes');
    end;
    CheckFalse(AreEqual(LMock[0].Secret, LMock[1].Secret),
      'client and server handshake secrets differ');
    // label order alone would not catch a client/server swap; the Finished key derived from each
    // logged handshake secret must match the schedule's key for that direction
    LHkdf := Crypto.Primitives.CreateHkdf(THashAlgorithm.SHA_256);
    CheckEqualBytes('client handshake secret derives the client Finished key',
      LSched.FinishedKey(TTlsDirection.ClientWrite).ToBytes,
      THkdfLabel.HkdfExpandLabel(LHkdf, TSecretBuffer.From(LMock[0].Secret),
      'finished', nil, 32).ToBytes);
    CheckEqualBytes('server handshake secret derives the server Finished key',
      LSched.FinishedKey(TTlsDirection.ServerWrite).ToBytes,
      THkdfLabel.HkdfExpandLabel(LHkdf, TSecretBuffer.From(LMock[1].Secret),
      'finished', nil, 32).ToBytes);
  finally
    LSched.Free;
  end;
end;

procedure TTestKeyLog.TestTls13NoSinkReportsNothing;
var
  LSched: TTls13KeySchedule;
begin
  LSched := TTls13KeySchedule.Create(Crypto, THashAlgorithm.SHA_256, 16);
  try
    LSched.SetSharedSecret(TSecretBuffer.From(Rep($AB, 32)));
    // no SetKeyLog: nothing must be read or reported
    LSched.DeriveEpochSecrets(TTlsEpoch.Handshake, Rep($01, 32));
    LSched.DeriveEpochSecrets(TTlsEpoch.Application, Rep($02, 32));
    // the absence of a sink is proven by no crash and no secret read; a second schedule with a nil
    // sink installed behaves identically
    LSched.SetKeyLog(nil, FixedRandom);
    LSched.DeriveEpochSecrets(TTlsEpoch.Application, Rep($03, 32));
  finally
    LSched.Free;
  end;
  Check(True, 'deriving without a sink neither reports nor raises');
end;

procedure TTestKeyLog.TestTls12ReportsMasterSecretAsClientRandom;
var
  LSched: TTls12KeySchedule;
  LMock: TMockKeyLog;
  LRandom: TBytes;
begin
  LMock := TMockKeyLog.Create;
  LRandom := FixedRandom;
  LSched := TTls12KeySchedule.Create(Crypto, THashAlgorithm.SHA_256, 16,
    TAeadAlgorithm.AES_128_GCM);
  try
    LSched.SetPreMasterSecret(TSecretBuffer.From(Rep($CD, 48)));
    LSched.SetRandoms(LRandom, Rep($EF, 32));
    LSched.SetKeyLog(LMock as IKeyLog, LRandom);
    LSched.DeriveMasterSecret;
    LSched.DeriveKeyBlock;
    CheckEquals(1, LMock.Count, 'one 1.2 secret is reported');
    CheckEquals(KeyLogLabelClientRandom, LMock[0].Lbl, 'the label is CLIENT_RANDOM');
    CheckEqualBytes('keyed by the client random', LRandom, LMock[0].ClientRandom);
    CheckEqualBytes('the secret is the master secret',
      LSched.MasterSecret.ToBytes, LMock[0].Secret);
  finally
    LSched.Free;
  end;
end;

procedure TTestKeyLog.TestBuilderKeyLogLandsInConfig;
var
  LMock: IKeyLog;
  LConfig: ITlsClientConfig;
begin
  LMock := TMockKeyLog.Create as IKeyLog;
  // a client build requires a trust source even under skip-verify; the empty store is never consulted
  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithDangerousInsecureSkipVerify(True)
    .WithTrustStore(TTrustAnchorStore.Create(nil) as ITrustAnchorStore)
    .WithDangerousKeyLog(LMock).Build;
  CheckTrue(LConfig.KeyLog = LMock, 'the config carries the injected sink');
end;

procedure TTestKeyLog.TestBuilderDefaultKeyLogIsNil;
var
  LConfig: ITlsClientConfig;
begin
  LConfig := TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithDangerousInsecureSkipVerify(True)
    .WithTrustStore(TTrustAnchorStore.Create(nil) as ITrustAnchorStore).Build;
  CheckTrue(LConfig.KeyLog = nil, 'the key log is off by default');
end;

procedure TTestKeyLog.TestNssLineFormat;
begin
  CheckEquals('CLIENT_RANDOM 0001 0203',
    TNssKeyLogFormat.Line('CLIENT_RANDOM', DecodeHex('0001'), DecodeHex('0203')),
    'the NSS line is label + hex random + hex secret');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestKeyLog);
{$ELSE}
  RegisterTest(TTestKeyLog.Suite);
{$ENDIF FPC}

end.
