{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit EchClientEngineTests;

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
  TlpCryptoDomainTypes,
  TlpICryptoProvider,
  TlpISecretBuffer,
  TlpIClock,
  TlpClock,
  TlpNamedGroups,
  TlpNegotiationTypes,
  TlpCipherSuiteRegistry,
  TlpCoreExtensions,
  TlpWireReader,
  TlpHandshakeMessage,
  TlpHandshakeMessages,
  TlpHandshakeEffect,
  TlpTls13ClientStateMachine,
  TlpServerName,
  TlpEchConfig,
  TlpExtensionVector,
  TlpEchExtension,
  TlpEchOuterExtensions,
  TlpEchClient,
  TlpEchClientOrchestrator,
  TlpIEchClientOrchestrator,
  MockCryptoProvider,
  TlpEchServer,
  TlpInMemoryEchKeyStore,
  TlpEchKeyGen,
  TlpIEch,
  TlpTlsLibExceptions,
  TlsLibTestBase,
  TlsLibTestHandshakeDecoder;

type
  /// <summary>
  /// Drives the real TLS 1.3 client machine with an ECH policy and inspects the
  /// ClientHelloOuter it emits: the outer carries the public_name, the true SNI never
  /// appears in the clear, and the sealed payload decrypts (with the config's private
  /// key) and reconstructs to a ClientHelloInner carrying the real SNI.
  /// </summary>
  TTestEchClientEngine = class(TTlsLibAlgorithmTestCase)
  private
    FVec: TStringList;
    function BaseParams(const AEchConfigList: TBytes): TClientHandshakeParams;
    function OuterClientHello: TBytes;
    // decode + vector-parse the framed outer once, then drive ProcessOuter (its new triple)
    function ProcessOuterFramed(const AEch: IEchServerHandshake;
      const AFramed: TBytes): TEchStatus;
    // seals AEncoded into the outer's ech extension with ASealer and returns the framed outer
    function SealOuter(var AOuter: TTlsClientHello; var AEntries: TExtensionVector;
      var AEch: TEchOuterClientHello; const ASealer: IHpkeSealer;
      const AEncoded: TBytes): TBytes;
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestOuterHidesRealSniAndDecryptsToInner;
    procedure TestUnusableConfigFailsClosed;
    procedure TestRetryChecksTheWireConfigIdNotTheEntrys;
    procedure TestGreaseDegradesWhenProviderLacksX25519;
    procedure TestEmptyConfigListWithoutGreaseFailsClosed;
    procedure TestServerRetryOuterBeforeAcceptFailsLoud;
    procedure TestServerRetryOuterAfterRejectFailsLoud;
    procedure TestServerProcessOuterEmptyVectorIsNotOffered;
    procedure TestUsableEchWithTls12OfferRejected;
  end;

implementation

const
  RealSni = 'secret.internal.example';
  PublicName = 'cover.example';

{ TTestEchClientEngine }

procedure TTestEchClientEngine.SetUp;
begin
  inherited SetUp;
  FVec := LoadVectorFields('Certs/Ech.txt');
end;

procedure TTestEchClientEngine.TearDown;
begin
  FVec.Free;
  inherited TearDown;
end;

function TTestEchClientEngine.BaseParams(
  const AEchConfigList: TBytes): TClientHandshakeParams;
begin
  Result := Default(TClientHandshakeParams);
  Result.Crypto := Crypto;
  Result.Inspector := Pkix.Certificates;
  Result.Clock := TSystemClock.Create;
  Result.Group := TNamedGroups.CreateX25519(Crypto);
  Result.GroupCode := TNamedGroupCatalog.X25519;
  Result.CipherSuites := TCipherSuiteRegistry.CreateDefault(Crypto);
  Result.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  Result.OfferedSuites := TArray<UInt16>.Create(TCipherSuites13.Aes128GcmSha256);
  Result.OfferedSchemes :=
    TArray<UInt16>.Create(TSignatureSchemes.EcdsaSecp256r1Sha256);
  Result.ClientRandom := DecodeHex(
    '1111111111111111111111111111111111111111111111111111111111111111');
  Result.LegacySessionId := DecodeHex(
    '3333333333333333333333333333333333333333333333333333333333333333');
  Result.ServerName := RealSni;
  Result.ExpectedServerName := TServerName.DnsName(RealSni);
  Result.EchPolicy := TEchClientPolicy.Create(Crypto, AEchConfigList, False, False)
    as IEchClientPolicy;
end;

function TTestEchClientEngine.OuterClientHello: TBytes;
var
  LMachine: TTls13ClientStateMachine;
  LEffects: TArray<THandshakeEffect>;
  LI: Int32;
begin
  Result := nil;
  LMachine := TTls13ClientStateMachine.Create(
    BaseParams(DecodeHex(FVec.Values['config_list'])));
  try
    LEffects := LMachine.Start;
    for LI := 0 to System.High(LEffects) do
      if LEffects[LI].Kind = THandshakeEffectKind.SendHandshake then
        Exit(LEffects[LI].Bytes);
  finally
    LMachine.Free;
  end;
end;

procedure TTestEchClientEngine.TestOuterHidesRealSniAndDecryptsToInner;
var
  LOuterFramed, LOuterBody, LAad, LEncoded: TBytes;
  LOuter: TTlsClientHello;
  LEntries, LEncEntries, LReconstructed: TExtensionVector;
  LSni, LEch: TExtensionEntry;
  LType: TEchClientHelloType;
  LOuterEch: TEchOuterClientHello;
  LReader, LSessReader: TWireReader;
  LConfigs: TArray<TEchConfig>;
  LConfig: TEchConfig;
  LSuite: IHpkeSuite;
  LSk: ISecretBuffer;
  LOpener: IHpkeOpener;
  LI: Int32;
  LRealSniBytes: TBytes;
begin
  LOuterFramed := OuterClientHello;
  CheckTrue(System.Length(LOuterFramed) > 0, 'the client emitted a ClientHello');

  // the real SNI must never appear in the cleartext ClientHelloOuter
  SetLength(LRealSniBytes, System.Length(RealSni));
  for LI := 1 to System.Length(RealSni) do
    LRealSniBytes[LI - 1] := Byte(Ord(RealSni[LI]));
  CheckFalse(ContainsBytes(LOuterFramed, LRealSniBytes),
    'the true SNI is not in the outer ClientHello');

  LOuterBody := System.Copy(LOuterFramed, 4, System.Length(LOuterFramed) - 4);
  LOuter := THandshakeMessages.DecodeClientHello(LOuterBody);
  LEntries := TExtensionVector.Parse(LOuter.Extensions);

  // the outer offers the public_name
  CheckTrue(LEntries.TryFind(TExtensionTypes.ServerName, LSni), 'outer has SNI');
  CheckEquals(PublicName, TTlsLibTestHandshakeDecoder.ServerNameHost(LSni.Data), 'the outer SNI is the public_name');

  // decode the outer encrypted_client_hello extension
  CheckTrue(LEntries.TryFind(TExtensionTypes.EncryptedClientHello, LEch),
    'outer has an ech extension');
  TEchExtension.Decode(LEch.Data, LType, LOuterEch);
  CheckEquals(Ord(TEchClientHelloType.Outer), Ord(LType), 'it is the outer form');

  // rebuild the ClientHelloOuterAAD: the outer body with the ech payload zeroed
  FillChar(LOuterEch.Payload[0], System.Length(LOuterEch.Payload), 0);
  LEntries.SetData(LEntries.IndexOf(TExtensionTypes.EncryptedClientHello),
    TEchExtension.EncodeOuter(LOuterEch));
  LOuter.Extensions := LEntries.Encode;
  LAad := THandshakeMessages.EncodeClientHello(LOuter);

  // decrypt with the config's private key and the config's HPKE info
  LConfigs := TEchConfigList.Parse(DecodeHex(FVec.Values['config_list']));
  LConfig := LConfigs[0];
  TEchExtension.Decode(LEch.Data, LType, LOuterEch); // re-decode for the real payload
  LSuite := Crypto.Hpke.Suite(LConfig.KemId, LOuterEch.CipherSuite.KdfId,
    LOuterEch.CipherSuite.AeadId);
  LSk := Crypto.Hpke.ImportPrivateKey(THpkeKem.DHKEM_X25519_HKDF_SHA256,
    DecodeHex(FVec.Values['config_private_key']));
  LOpener := Crypto.Hpke.ImportRecipientKey(LSuite.Kem, LSk)
    .SetupOpener(LSuite, LOuterEch.Enc, LConfig.HpkeInfo);
  LEncoded := LOpener.Open(LAad, LOuterEch.Payload);

  // parse the encoded inner: empty session_id, then reconstruct against the outer
  LReader := TWireReader.Create(LEncoded);
  LReader.Skip(2);
  LReader.Skip(32);
  LSessReader := LReader.OpenVector(1);
  CheckEquals(0, LSessReader.Remaining, 'the encoded inner session_id is empty');
  LSessReader := LReader.OpenVector(2); // cipher_suites (advance)
  LSessReader := LReader.OpenVector(1); // compression (advance)
  LEncEntries := TExtensionVector.ParseFrom(LReader);
  LReconstructed := TEchOuterExtensions.Reconstruct(LEntries, LEncEntries);

  // the reconstructed inner carries the real SNI
  CheckTrue(LReconstructed.TryFind(TExtensionTypes.ServerName, LSni),
    'the inner has a server_name');
  CheckEquals(RealSni, TTlsLibTestHandshakeDecoder.ServerNameHost(LSni.Data),
    'the reconstructed inner SNI is the real host');
end;

procedure TTestEchClientEngine.TestUnusableConfigFailsClosed;
var
  LSuite: TEchCipherSuite;
  LConfig: TEchConfig;
  LBadList, LPublicName, LDummyKey: TBytes;
  LMachine: TTls13ClientStateMachine;
  LI: Int32;
  LRaised: Boolean;
begin
  // a config the provider cannot use (here an unknown KEM) with GREASE off: the client must fail
  // closed at construction rather than silently send the true SNI in the clear (RFC 9849 sec. 6.1)
  SetLength(LPublicName, System.Length(PublicName));
  for LI := 1 to System.Length(PublicName) do
    LPublicName[LI - 1] := Byte(Ord(PublicName[LI]));
  SetLength(LDummyKey, 32);
  LSuite.KdfId := 1;
  LSuite.AeadId := 1;
  LConfig := TEchConfig.Build(TEchConfig.SupportedVersion, 7, $0099, LDummyKey,
    TArray<TEchCipherSuite>.Create(LSuite), 0, LPublicName, nil);
  LBadList := TEchConfigList.Encode(TArray<TEchConfig>.Create(LConfig));

  LRaised := False;
  LMachine := nil;
  try
    try
      LMachine := TTls13ClientStateMachine.Create(BaseParams(LBadList));
    except
      on E: EArgumentTlsLibException do
        LRaised := True;
    end;
  finally
    LMachine.Free;
  end;
  CheckTrue(LRaised, 'an all-unusable ECH config with GREASE off fails closed');
end;

procedure TTestEchClientEngine.TestGreaseDegradesWhenProviderLacksX25519;
var
  LCrypto: ICryptoProvider;
  LOrchestrator: IEchClientOrchestrator;
begin
  // GREASE imitates an X25519 suite; a provider that cannot build X25519 sends no decoy instead of
  // failing the handshake (the orchestrator's contract)
  LCrypto := TMissingAeadProvider.Create(Crypto, TKeyAgreementAlgorithm.X25519) as ICryptoProvider;
  CheckEquals(0, System.Length(LCrypto.Hpke.RandomEncapsulation(
    THpkeKem.DHKEM_X25519_HKDF_SHA256)), 'no encapsulation without the KEM primitive');
  LOrchestrator := TEchClientOrchestrator.Create(LCrypto,
    TEchClientPolicy.Create(LCrypto, nil, True, False) as IEchClientPolicy);
  CheckFalse(LOrchestrator.Grease, 'no decoy is offered, and nothing raised');
end;

procedure TTestEchClientEngine.TestEmptyConfigListWithoutGreaseFailsClosed;
var
  LRaised: Boolean;
begin
  // an empty ECHConfigList with GREASE off would silently send the true SNI: reject it at
  // configuration time rather than fall back to cleartext
  LRaised := False;
  try
    TEchClientPolicy.Create(Crypto, nil, False, False);
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'an empty ECHConfigList with GREASE off fails closed');
end;

procedure TTestEchClientEngine.TestServerRetryOuterBeforeAcceptFailsLoud;
var
  LGen: TEchKeyGenResult;
  LStore: IEchServerKeyStore;
  LEch: IEchServerHandshake;
  LRaised: Boolean;
begin
  // ProcessRetryOuter is only valid after an accepted first ClientHelloOuter; calling it up front
  // is a programming error that must fail loud, not access a nil opener
  LGen := TEchKeyGenerator.Generate(Crypto, 'public.example', 'origin.example', $AA,
    THpkeKem.DHKEM_X25519_HKDF_SHA256, THpkeKdf.HKDF_SHA256, THpkeAead.AES_128_GCM, 0);
  LStore := TInMemoryEchKeyStore.FromPem(LGen.Pem, Crypto);
  LEch := TEchServerHandshake.Create(Crypto, TEchServerPolicy.Keyed(Crypto, LStore, False))
    as IEchServerHandshake;
  LRaised := False;
  try
    LEch.ProcessRetryOuter(OuterClientHello);
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'ProcessRetryOuter without an accepted CH1 fails loud');
end;

procedure TTestEchClientEngine.TestServerRetryOuterAfterRejectFailsLoud;
var
  LGen: TEchKeyGenResult;
  LStore: IEchServerKeyStore;
  LEch: IEchServerHandshake;
  LRaised: Boolean;
begin
  // a store whose key cannot open the outer ech rejects it; ProcessRetryOuter must then fail loud
  // rather than dereference a suite left set with a nil opener
  LGen := TEchKeyGenerator.Generate(Crypto, 'public.example', 'origin.example', $BB,
    THpkeKem.DHKEM_X25519_HKDF_SHA256, THpkeKdf.HKDF_SHA256, THpkeAead.AES_128_GCM, 0);
  LStore := TInMemoryEchKeyStore.FromPem(LGen.Pem, Crypto);
  LEch := TEchServerHandshake.Create(Crypto, TEchServerPolicy.Keyed(Crypto, LStore, True))
    as IEchServerHandshake;
  CheckTrue(ProcessOuterFramed(LEch, OuterClientHello) = TEchStatus.Rejected,
    'the mismatched store rejects the outer ech');
  LRaised := False;
  try
    LEch.ProcessRetryOuter(OuterClientHello);
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'ProcessRetryOuter after a reject fails loud');
end;

function TTestEchClientEngine.ProcessOuterFramed(const AEch: IEchServerHandshake;
  const AFramed: TBytes): TEchStatus;
var
  LOuter: TTlsClientHello;
  LEntries: TExtensionVector;
begin
  LOuter := THandshakeMessages.DecodeClientHello(
    System.Copy(AFramed, 4, System.Length(AFramed) - 4));
  LEntries := TExtensionVector.Parse(LOuter.Extensions);
  Result := AEch.ProcessOuter(AFramed, LOuter, LEntries);
end;

function TTestEchClientEngine.SealOuter(var AOuter: TTlsClientHello;
  var AEntries: TExtensionVector; var AEch: TEchOuterClientHello;
  const ASealer: IHpkeSealer; const AEncoded: TBytes): TBytes;
var
  LIdx: Int32;
  LAad: TBytes;
begin
  LIdx := AEntries.IndexOf(TExtensionTypes.EncryptedClientHello);
  // the AAD is the outer with the payload zeroed at its final length (RFC 9849 sec. 5.2)
  AEch.Payload := nil;
  System.SetLength(AEch.Payload, System.Length(AEncoded) + 16);
  AEntries.SetData(LIdx, TEchExtension.EncodeOuter(AEch));
  AOuter.Extensions := AEntries.Encode;
  LAad := THandshakeMessages.EncodeClientHello(AOuter);
  AEch.Payload := ASealer.Seal(LAad, AEncoded);
  AEntries.SetData(LIdx, TEchExtension.EncodeOuter(AEch));
  AOuter.Extensions := AEntries.Encode;
  Result := THandshakeFraming.Frame(TTlsHandshakeType.ClientHello,
    THandshakeMessages.EncodeClientHello(AOuter));
end;

procedure TTestEchClientEngine.TestRetryChecksTheWireConfigIdNotTheEntrys;
var
  LOuterFramed, LOuterBody, LAad, LEncoded, LEnc, LRetryFramed: TBytes;
  LOuter: TTlsClientHello;
  LEntries: TExtensionVector;
  LEch: TExtensionEntry;
  LType: TEchClientHelloType;
  LOuterEch: TEchOuterClientHello;
  LConfig: TEchConfig;
  LSuite: IHpkeSuite;
  LSk: ISecretBuffer;
  LOpener: IHpkeOpener;
  LSealer: IHpkeSealer;
  LStore: IEchServerKeyStore;
  LServer: IEchServerHandshake;
  LWireId: Byte;
begin
  // a client that ignores the config identifiers randomizes config_id on the first hello and must
  // keep that value on the retry (RFC 9849 sec. 6.1.1, 7.1.1); a trial-decrypting server compares
  // the retry with what it was sent, not with the id of the key-store entry that opened it
  LOuterFramed := OuterClientHello;
  LOuterBody := System.Copy(LOuterFramed, 4, System.Length(LOuterFramed) - 4);
  LOuter := THandshakeMessages.DecodeClientHello(LOuterBody);
  LEntries := TExtensionVector.Parse(LOuter.Extensions);
  CheckTrue(LEntries.TryFind(TExtensionTypes.EncryptedClientHello, LEch), 'outer has an ech extension');
  TEchExtension.Decode(LEch.Data, LType, LOuterEch);
  LConfig := TEchConfigList.Parse(DecodeHex(FVec.Values['config_list']))[0];
  LSuite := Crypto.Hpke.Suite(LConfig.KemId, LOuterEch.CipherSuite.KdfId,
    LOuterEch.CipherSuite.AeadId);
  LSk := Crypto.Hpke.ImportPrivateKey(THpkeKem.DHKEM_X25519_HKDF_SHA256,
    DecodeHex(FVec.Values['config_private_key']));

  // recover the encoded inner the real client sealed
  FillChar(LOuterEch.Payload[0], System.Length(LOuterEch.Payload), 0);
  LEntries.SetData(LEntries.IndexOf(TExtensionTypes.EncryptedClientHello),
    TEchExtension.EncodeOuter(LOuterEch));
  LOuter.Extensions := LEntries.Encode;
  LAad := THandshakeMessages.EncodeClientHello(LOuter);
  TEchExtension.Decode(LEch.Data, LType, LOuterEch);
  LOpener := Crypto.Hpke.ImportRecipientKey(LSuite.Kem, LSk)
    .SetupOpener(LSuite, LOuterEch.Enc, LConfig.HpkeInfo);
  LEncoded := LOpener.Open(LAad, LOuterEch.Payload);

  // reseal it under a wire config_id that is not the entry's
  LWireId := Byte(LOuterEch.ConfigId xor 1);
  LOuterEch.ConfigId := LWireId;
  LSuite.SetupSealer(LConfig.PublicKey, LConfig.HpkeInfo, LEnc, LSealer);
  LOuterEch.Enc := LEnc;
  LStore := TInMemoryEchKeyStore.FromConfig(DecodeHex(FVec.Values['config_list']), LSk, Crypto);
  LServer := TEchServerHandshake.Create(Crypto, TEchServerPolicy.Keyed(Crypto, LStore, True))
    as IEchServerHandshake;
  CheckTrue(ProcessOuterFramed(LServer, SealOuter(LOuter, LEntries, LOuterEch, LSealer, LEncoded)) =
    TEchStatus.Accepted, 'the trial-decrypting server opens the first hello');

  // the retry keeps the wire id, cipher_suite and an empty enc, sealed at the next sequence number
  LOuterEch.Enc := nil;
  LRetryFramed := SealOuter(LOuter, LEntries, LOuterEch, LSealer, LEncoded);
  CheckTrue(LServer.ProcessRetryOuter(LRetryFramed) = TEchStatus.Accepted,
    'the retry that keeps the wire config_id is accepted');
end;

procedure TTestEchClientEngine.TestServerProcessOuterEmptyVectorIsNotOffered;
var
  LGen: TEchKeyGenResult;
  LStore: IEchServerKeyStore;
  LEch: IEchServerHandshake;
  LOuter: TTlsClientHello;
begin
  // an empty outer extension vector (a legacy <=TLS 1.2 shape) offers no ech: NotOffered, no decrypt
  LGen := TEchKeyGenerator.Generate(Crypto, 'public.example', 'origin.example', $CC,
    THpkeKem.DHKEM_X25519_HKDF_SHA256, THpkeKdf.HKDF_SHA256, THpkeAead.AES_128_GCM, 0);
  LStore := TInMemoryEchKeyStore.FromPem(LGen.Pem, Crypto);
  LEch := TEchServerHandshake.Create(Crypto, TEchServerPolicy.Keyed(Crypto, LStore, False))
    as IEchServerHandshake;
  LOuter := THandshakeMessages.DecodeClientHello(
    System.Copy(OuterClientHello, 4, System.Length(OuterClientHello) - 4));
  CheckTrue(LEch.ProcessOuter(OuterClientHello, LOuter, TExtensionVector.Empty)
    = TEchStatus.NotOffered, 'an empty extension vector offers no ech');
end;

procedure TTestEchClientEngine.TestUsableEchWithTls12OfferRejected;
var
  LParams: TClientHandshakeParams;
  LRaised: Boolean;
begin
  // the SNI-exposure guard: a usable ECH config can never ride a ClientHello that also offers TLS
  // 1.2 (ECH is 1.3-only, RFC 9849 sec. 6.1), so the 1.3 machine ctor must refuse the pairing
  LParams := BaseParams(DecodeHex(FVec.Values['config_list']));
  LParams.AlsoOfferTls12 := True;
  LRaised := False;
  try
    TTls13ClientStateMachine.Create(LParams).Free;
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a usable ECH config paired with a 1.2 offer is rejected');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestEchClientEngine);
{$ELSE}
  RegisterTest(TTestEchClientEngine.Suite);
{$ENDIF FPC}

end.
