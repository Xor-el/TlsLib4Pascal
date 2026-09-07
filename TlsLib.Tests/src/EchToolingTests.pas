{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit EchToolingTests;

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
  TlpISecretBuffer,
  TlpIWireWriter,
  TlpWireWriter,
  TlpWireVectorMarker,
  TlpEchConfig,
  TlpInMemoryEchKeyStore,
  TlpIEch,
  TlpEchConfigFromSvcb,
  TlpEchKeyGen,
  TlpTlsLibExceptions,
  TlsLibTestBase;

type
  /// <summary>
  /// The out-of-core ECH tooling: the EchKeyGen generator (its PEM loads back through
  /// the server key store and the key pair it produced actually seals/opens) and the
  /// HTTPS/SVCB ECHConfigList extractor.
  /// </summary>
  TTestEchTooling = class(TTlsLibAlgorithmTestCase)
  strict private
    function BuildHttpsRdata(APriority: UInt16; AIncludeEch: Boolean;
      const AEchConfigList: TBytes): TBytes;
    function BuildEchConfigFor(out APublicKey: TBytes;
      out APrivateKey: ISecretBuffer): TEchConfig;
  published
    procedure TestKeyGenPemRoundTripsThroughStore;
    procedure TestKeyGenKeyPairSealsAndOpens;
    procedure TestSvcbExtractsEchConfigList;
    procedure TestSvcbAliasModeHasNoEch;
    procedure TestSvcbWithoutEchParamReturnsFalse;
    procedure TestSvcbRejectsOutOfOrderKeys;
    procedure TestSvcbRejectsDuplicateKeys;
    procedure TestSvcbRejectsTrailingBytes;
    procedure TestSvcbRejectsEmptyEchValue;
    procedure TestPemKeyMismatchRejected;
    procedure TestFromConfigKeyMismatchRejected;
    procedure TestStoreWithNoRetryEntriesRejected;
    procedure TestFromConfigSkipsUnsupportedVersion;
    procedure TestFromConfigAllUnsupportedRejected;
    procedure TestKeyMismatchDetectedPastExportOnlySuite;
  end;

implementation

{ TTestEchTooling }

function TTestEchTooling.BuildHttpsRdata(APriority: UInt16;
  AIncludeEch: Boolean; const AEchConfigList: TBytes): TBytes;
var
  LWriter: IWireWriter;
begin
  // RFC 9460 sec. 2.2: SvcPriority, an (empty root ".") TargetName, then SvcParams; the
  // "ech" SvcParam (key 5) carries the opaque ECHConfigList
  LWriter := TWireWriter.Create;
  LWriter.WriteUInt16(APriority);
  LWriter.WriteUInt8(0);
  if AIncludeEch then
  begin
    LWriter.WriteUInt16(5);
    LWriter.WriteUInt16(UInt16(System.Length(AEchConfigList)));
    LWriter.WriteBytes(AEchConfigList);
  end
  else
  begin
    // an "alpn" SvcParam (key 1) instead, so the record is well-formed but ech-less
    LWriter.WriteUInt16(1);
    LWriter.WriteUInt16(3);
    LWriter.WriteBytes(TBytes.Create(2, Ord('h'), Ord('2')));
  end;
  Result := LWriter.ToBytes;
end;

procedure TTestEchTooling.TestKeyGenPemRoundTripsThroughStore;
var
  LGen: TEchKeyGenResult;
  LStore: IEchServerKeyStore;
  LEntries: TArray<TEchKeyEntry>;
begin
  LGen := TEchKeyGenerator.Generate(Provider, 'public.example', 42,
    THpkeKem.DHKEM_X25519_HKDF_SHA256, THpkeKdf.HKDF_SHA256,
    THpkeAead.AES_128_GCM, 64);
  // the generated PEM loads through the server key store (PKCS#8 private key + ECHCONFIG)
  LStore := TInMemoryEchKeyStore.FromPem(LGen.Pem, Provider);
  LEntries := LStore.Entries;
  CheckEquals(1, System.Length(LEntries), 'the store parsed one ECH config');
  CheckEquals(42, LEntries[0].Config.ConfigId, 'the config id round-tripped');
  CheckEquals('public.example', LEntries[0].Config.PublicName,
    'the public_name round-tripped');
  CheckTrue(LEntries[0].RecipientKey <> nil, 'the recipient key was imported');
  // loaded configs are flagged is_retry, so the store's retry_configs re-encode to the
  // exact ECHConfigList the tool emitted (a byte-level encode round-trip)
  CheckEqualBytes('retry_configs equals the generated ECHConfigList',
    LGen.EchConfigList, LStore.RetryConfigs);
end;

procedure TTestEchTooling.TestKeyGenKeyPairSealsAndOpens;
var
  LGen: TEchKeyGenResult;
  LStore: IEchServerKeyStore;
  LEntry: TEchKeyEntry;
  LSuite: IHpkeSuite;
  LSealer: IHpkeSealer;
  LOpener: IHpkeOpener;
  LEnc, LPlain, LCipher, LOut: TBytes;
begin
  LGen := TEchKeyGenerator.Generate(Provider, 'public.example', 5,
    THpkeKem.DHKEM_X25519_HKDF_SHA256, THpkeKdf.HKDF_SHA256,
    THpkeAead.AES_128_GCM, 0);
  LStore := TInMemoryEchKeyStore.FromPem(LGen.Pem, Provider);
  LEntry := LStore.Entries[0];
  CheckTrue(LEntry.Config.TrySelectSuite(Provider, LSuite),
    'the config advertises a supported suite');
  // seal to the generated public key, open with the imported private key: a mismatch
  // (a wrong PKCS#8 encode/decode) would fail the AEAD authentication
  LSuite.SetupSealer(LEntry.Config.PublicKey, LEntry.Config.HpkeInfo, LEnc, LSealer);
  LPlain := TBytes.Create(1, 2, 3, 4, 5, 6, 7, 8);
  LCipher := LSealer.Seal(nil, LPlain);
  LOpener := LEntry.RecipientKey.SetupOpener(LSuite, LEnc, LEntry.Config.HpkeInfo);
  LOut := LOpener.Open(nil, LCipher);
  CheckEqualBytes('the generated key pair seals and opens', LPlain, LOut);
end;

procedure TTestEchTooling.TestSvcbExtractsEchConfigList;
var
  LGen: TEchKeyGenResult;
  LRdata, LOut: TBytes;
begin
  LGen := TEchKeyGenerator.Generate(Provider, 'public.example', 1,
    THpkeKem.DHKEM_X25519_HKDF_SHA256, THpkeKdf.HKDF_SHA256,
    THpkeAead.AES_128_GCM, 0);
  LRdata := BuildHttpsRdata(1, True, LGen.EchConfigList);
  CheckTrue(TEchConfigFromSvcb.TryFromServiceBinding(LRdata, LOut),
    'the ech SvcParam was found');
  CheckEqualBytes('the extracted ECHConfigList matches', LGen.EchConfigList, LOut);
end;

procedure TTestEchTooling.TestSvcbAliasModeHasNoEch;
var
  LRdata, LOut: TBytes;
begin
  // priority 0 is AliasMode and carries no SvcParams
  LRdata := BuildHttpsRdata(0, False, nil);
  CheckFalse(TEchConfigFromSvcb.TryFromServiceBinding(LRdata, LOut),
    'AliasMode yields no ECHConfigList');
end;

procedure TTestEchTooling.TestSvcbWithoutEchParamReturnsFalse;
var
  LRdata, LOut: TBytes;
begin
  LRdata := BuildHttpsRdata(1, False, nil);
  CheckFalse(TEchConfigFromSvcb.TryFromServiceBinding(LRdata, LOut),
    'a record with no ech SvcParam yields no ECHConfigList');
end;

procedure TTestEchTooling.TestSvcbRejectsOutOfOrderKeys;
var
  LWriter: IWireWriter;
  LOut: TBytes;
begin
  // SvcParams must be strictly ascending by key (RFC 9460 sec. 2.2): key 6 before key 5 (ech)
  // is descending and must be rejected even though an ech param is present
  LWriter := TWireWriter.Create;
  LWriter.WriteUInt16(1);  // ServiceMode priority
  LWriter.WriteUInt8(0);   // empty TargetName
  LWriter.WriteUInt16(6);  // key 6
  LWriter.WriteUInt16(0);
  LWriter.WriteUInt16(5);  // ech
  LWriter.WriteUInt16(2);
  LWriter.WriteBytes(TBytes.Create($AB, $CD));
  CheckFalse(TEchConfigFromSvcb.TryFromServiceBinding(LWriter.ToBytes, LOut),
    'descending SvcParam keys are rejected');
end;

procedure TTestEchTooling.TestSvcbRejectsDuplicateKeys;
var
  LWriter: IWireWriter;
  LOut: TBytes;
begin
  // a duplicated key breaks strictly-ascending order and is rejected
  LWriter := TWireWriter.Create;
  LWriter.WriteUInt16(1);
  LWriter.WriteUInt8(0);
  LWriter.WriteUInt16(1);  // key 1
  LWriter.WriteUInt16(0);
  LWriter.WriteUInt16(1);  // key 1 again
  LWriter.WriteUInt16(0);
  CheckFalse(TEchConfigFromSvcb.TryFromServiceBinding(LWriter.ToBytes, LOut),
    'duplicate SvcParam keys are rejected');
end;

procedure TTestEchTooling.TestSvcbRejectsTrailingBytes;
var
  LWriter: IWireWriter;
  LOut: TBytes;
begin
  // a stray byte past the last SvcParam means the RDATA was not consumed exactly
  LWriter := TWireWriter.Create;
  LWriter.WriteUInt16(1);
  LWriter.WriteUInt8(0);
  LWriter.WriteUInt16(5);  // ech
  LWriter.WriteUInt16(2);
  LWriter.WriteBytes(TBytes.Create($AB, $CD));
  LWriter.WriteUInt8($FF); // trailing byte
  CheckFalse(TEchConfigFromSvcb.TryFromServiceBinding(LWriter.ToBytes, LOut),
    'a trailing byte after the SvcParams is rejected');
end;

procedure TTestEchTooling.TestSvcbRejectsEmptyEchValue;
var
  LWriter: IWireWriter;
  LOut: TBytes;
begin
  // an ech SvcParam with a zero-length value carries no ECHConfigList: it must read as
  // absent, never as a usable config, so the client cannot silently fall back to a plaintext
  // ClientHello that exposes the true SNI
  LWriter := TWireWriter.Create;
  LWriter.WriteUInt16(1);
  LWriter.WriteUInt8(0);
  LWriter.WriteUInt16(5);  // ech
  LWriter.WriteUInt16(0);  // empty value
  CheckFalse(TEchConfigFromSvcb.TryFromServiceBinding(LWriter.ToBytes, LOut),
    'an empty ech SvcParam value yields no usable config');
end;

procedure TTestEchTooling.TestPemKeyMismatchRejected;
var
  LGen1, LGen2: TEchKeyGenResult;
  LBlocks1, LBlocks2, LMixed: TArray<TPemBlock>;
  LMixedPem: TBytes;
  LRaised: Boolean;

  function FindBlock(const ABlocks: TArray<TPemBlock>;
    const AType: string): TPemBlock;
  var
    LI: Int32;
  begin
    Result := Default(TPemBlock);
    for LI := 0 to System.High(ABlocks) do
      if ABlocks[LI].PemType = AType then
        Exit(ABlocks[LI]);
  end;

begin
  // pair one config's PRIVATE KEY with a different config's ECHCONFIG: the store must reject the
  // mismatch at load, not accept a store that would silently reject every ECH handshake
  LGen1 := TEchKeyGenerator.Generate(Provider, 'a.example', 1,
    THpkeKem.DHKEM_X25519_HKDF_SHA256, THpkeKdf.HKDF_SHA256,
    THpkeAead.AES_128_GCM, 0);
  LGen2 := TEchKeyGenerator.Generate(Provider, 'b.example', 2,
    THpkeKem.DHKEM_X25519_HKDF_SHA256, THpkeKdf.HKDF_SHA256,
    THpkeAead.AES_128_GCM, 0);
  LBlocks1 := Provider.Pem.ReadBlocks(LGen1.Pem);
  LBlocks2 := Provider.Pem.ReadBlocks(LGen2.Pem);
  SetLength(LMixed, 2);
  LMixed[0] := FindBlock(LBlocks1, 'PRIVATE KEY');
  LMixed[1] := FindBlock(LBlocks2, 'ECHCONFIG');
  LMixedPem := Provider.Pem.WriteBlocks(LMixed);
  LRaised := False;
  try
    TInMemoryEchKeyStore.FromPem(LMixedPem, Provider);
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a PEM pairing a mismatched private key and config is rejected');
end;

function TTestEchTooling.BuildEchConfigFor(out APublicKey: TBytes;
  out APrivateKey: ISecretBuffer): TEchConfig;
var
  LSuite: TEchCipherSuite;
begin
  Provider.Hpke.GenerateKeyPair(THpkeKem.DHKEM_X25519_HKDF_SHA256,
    APublicKey, APrivateKey);
  LSuite.KdfId := THpkeKdf.HKDF_SHA256;
  LSuite.AeadId := THpkeAead.AES_128_GCM;
  Result := TEchConfig.Build(TEchConfig.SupportedVersion, 1,
    THpkeKem.DHKEM_X25519_HKDF_SHA256, APublicKey,
    TArray<TEchCipherSuite>.Create(LSuite), 0,
    TEncoding.ASCII.GetBytes('a.example'), nil);
end;

procedure TTestEchTooling.TestFromConfigKeyMismatchRejected;
var
  LPub1, LPub2: TBytes;
  LSk1, LSk2: ISecretBuffer;
  LConfig: TEchConfig;
  LConfigList: TBytes;
  LRaised: Boolean;
begin
  LConfig := BuildEchConfigFor(LPub1, LSk1);
  BuildEchConfigFor(LPub2, LSk2); // a second, unrelated key pair
  LConfigList := TEchConfigList.Encode(TArray<TEchConfig>.Create(LConfig));
  LRaised := False;
  try
    // the config's public key is LPub1, but LSk2 is a different key
    TInMemoryEchKeyStore.FromConfig(LConfigList, LSk2, Provider);
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised,
    'FromConfig rejects a private key that does not match the config public key');
end;

procedure TTestEchTooling.TestStoreWithNoRetryEntriesRejected;
var
  LPub: TBytes;
  LSk: ISecretBuffer;
  LEntries: TArray<TEchKeyEntry>;
  LRaised: Boolean;
begin
  SetLength(LEntries, 1);
  LEntries[0].Config := BuildEchConfigFor(LPub, LSk);
  LEntries[0].RecipientKey := Provider.Hpke.ImportRecipientKey(
    THpkeKem.DHKEM_X25519_HKDF_SHA256, LSk);
  LEntries[0].IsRetry := False; // a store that advertises no retry_configs
  LRaised := False;
  try
    TInMemoryEchKeyStore.Create(LEntries);
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised,
    'a non-empty store with no is_retry entry is rejected (RFC 9849 7.1)');
end;

procedure TTestEchTooling.TestFromConfigSkipsUnsupportedVersion;
var
  LPub: TBytes;
  LSk: ISecretBuffer;
  LSupported, LStale: TEchConfig;
  LSuite: TEchCipherSuite;
  LConfigList: TBytes;
  LStore: IEchServerKeyStore;
begin
  LSupported := BuildEchConfigFor(LPub, LSk);
  LSuite.KdfId := THpkeKdf.HKDF_SHA256;
  LSuite.AeadId := THpkeAead.AES_128_GCM;
  // a config of a version this library does not model, sharing the same key
  LStale := TEchConfig.Build(UInt16($FE0C), 2, THpkeKem.DHKEM_X25519_HKDF_SHA256,
    LPub, TArray<TEchCipherSuite>.Create(LSuite), 0,
    TEncoding.ASCII.GetBytes('b.example'), nil);
  LConfigList := TEchConfigList.Encode(
    TArray<TEchConfig>.Create(LStale, LSupported));
  LStore := TInMemoryEchKeyStore.FromConfig(LConfigList, LSk, Provider);
  CheckEquals(1, System.Length(LStore.Entries),
    'only the supported-version config becomes a key');
end;

procedure TTestEchTooling.TestFromConfigAllUnsupportedRejected;
var
  LPub: TBytes;
  LSk: ISecretBuffer;
  LStale: TEchConfig;
  LSuite: TEchCipherSuite;
  LConfigList: TBytes;
  LRaised: Boolean;
begin
  BuildEchConfigFor(LPub, LSk);
  LSuite.KdfId := THpkeKdf.HKDF_SHA256;
  LSuite.AeadId := THpkeAead.AES_128_GCM;
  LStale := TEchConfig.Build(UInt16($FE0C), 2, THpkeKem.DHKEM_X25519_HKDF_SHA256,
    LPub, TArray<TEchCipherSuite>.Create(LSuite), 0,
    TEncoding.ASCII.GetBytes('b.example'), nil);
  LConfigList := TEchConfigList.Encode(TArray<TEchConfig>.Create(LStale));
  LRaised := False;
  try
    // a list with no config of a version this library serves must not yield an empty store
    TInMemoryEchKeyStore.FromConfig(LConfigList, LSk, Provider);
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a list of only unsupported-version configs is rejected');
end;

procedure TTestEchTooling.TestKeyMismatchDetectedPastExportOnlySuite;
var
  LPub1, LPub2: TBytes;
  LSk1, LSk2: ISecretBuffer;
  LSuites: TArray<TEchCipherSuite>;
  LConfig: TEchConfig;
  LConfigList: TBytes;
  LRaised: Boolean;
begin
  BuildEchConfigFor(LPub1, LSk1);          // key pair 1
  BuildEchConfigFor(LPub2, LSk2);          // key pair 2 (mismatched)
  SetLength(LSuites, 2);
  LSuites[0].KdfId := THpkeKdf.HKDF_SHA256; // export-only listed first
  LSuites[0].AeadId := THpkeAead.EXPORT_ONLY;
  LSuites[1].KdfId := THpkeKdf.HKDF_SHA256;
  LSuites[1].AeadId := THpkeAead.AES_128_GCM;
  LConfig := TEchConfig.Build(TEchConfig.SupportedVersion, 1,
    THpkeKem.DHKEM_X25519_HKDF_SHA256, LPub1, LSuites, 0,
    TEncoding.ASCII.GetBytes('a.example'), nil);
  LConfigList := TEchConfigList.Encode(TArray<TEchConfig>.Create(LConfig));
  LRaised := False;
  try
    // the check must skip the export-only suite and still detect the mismatched key
    TInMemoryEchKeyStore.FromConfig(LConfigList, LSk2, Provider);
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised,
    'a mismatched key is detected using the first real suite, past an export-only one');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestEchTooling);
{$ELSE}
  RegisterTest(TTestEchTooling.Suite);
{$ENDIF FPC}

end.
