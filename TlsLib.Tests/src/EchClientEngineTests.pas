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
  TlpExtensionContext,
  TlpITlsExtension,
  TlpExtensionBlockCodec,
  TlpNegotiationPolicy,
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
  TlpTlsVersion,
  TlpTlsAlert,
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
    // carrying ALegacyVersion (also in the AAD)
    function SealOuter(var AOuter: TTlsClientHello; var AEntries: TExtensionVector;
      var AEch: TEchOuterClientHello; const ASealer: IHpkeSealer;
      const AEncoded: TBytes; ALegacyVersion: UInt16): TBytes;
    // a trial-decrypting server for the real client's outer, plus the outer's decrypted
    // EncodedClientHelloInner and a sealer to reseal it under a wire config_id that is not the entry's
    procedure PrepareReseal(out AServer: IEchServerHandshake; out AOuter: TTlsClientHello;
      out AEntries: TExtensionVector; out AEch: TEchOuterClientHello;
      out ASealer: IHpkeSealer; out AEncoded: TBytes);
    // the alert a trial-decrypting server raises when the real client's sealed inner has its
    // AExtType extension replaced by AData (CloseNotify when nothing is raised)
    function TamperedInnerAlert(AExtType: UInt16; const AData: TBytes): TTlsAlertDescription;
    // a GREASE client's effects on a cookie-only HelloRetryRequest carrying AEchBody as its ech
    function GreaseClientHrrEffects(const AEchBody: TBytes): TArray<THandshakeEffect>;
  protected
    procedure SetUp; override;
  published
    procedure TestOuterHidesRealSniAndDecryptsToInner;
    procedure TestUnusableConfigFailsClosed;
    procedure TestRetryChecksTheWireConfigIdNotTheEntrys;
    procedure TestAcceptedOuterWithLegacyVersion0304AbortsProtocolVersion;
    procedure TestRetryOuterWithLegacyVersion0304AbortsProtocolVersion;
    procedure TestGreaseDegradesWhenProviderLacksX25519;
    procedure TestGreaseSuiteIsCommonlyDeployed;
    procedure TestEmptyConfigListWithoutGreaseFailsClosed;
    procedure TestMalformedConfigListIsAConfigurationError;
    procedure TestServerRetryOuterBeforeAcceptFailsLoud;
    procedure TestServerRetryOuterAfterRejectFailsLoud;
    procedure TestServerProcessOuterEmptyVectorIsNotOffered;
    procedure TestInnerEchWithTrailingByteIsIllegalParameter;
    procedure TestInnerEchEmptyBodyIsIllegalParameter;
    procedure TestInnerEchTruncatedOuterFormIsIllegalParameter;
    procedure TestWellFormedInnerEchIsAccepted;
    procedure TestEmptyInnerSupportedVersionsIsDecodeError;
    procedure TestUsableEchWithTls12OfferRejected;
    procedure TestGreaseClientRejectsHrrEchOfWrongLengthWithDecodeError;
    procedure TestGreaseClientIgnoresWellFormedHrrEchAndRetries;
  end;

implementation

const
  RealSni = 'secret.internal.example';
  PublicName = 'cover.example';

{ TTestEchClientEngine }

procedure TTestEchClientEngine.SetUp;
begin
  inherited SetUp;
  FVec := Own<TStringList>(LoadVectorFields('Certs/Ech.txt'));
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
  CheckEquals(0, System.Length(LOrchestrator.GreaseEchExt), 'no decoy is offered, and nothing raised');
end;

procedure TTestEchClientEngine.TestGreaseSuiteIsCommonlyDeployed;
var
  LOrchestrator: IEchClientOrchestrator;
  LExt: TBytes;
  LKdf, LAead: UInt16;
  LI: Int32;
  LSawAes, LSawChaCha: Boolean;
  LSuite: THpkeSuiteId;
begin
  // a decoy advertises only an HKDF-SHA256 suite with AES-128-GCM or ChaCha20-Poly1305, the
  // pairings real configs publish; draw enough that a stray suite from the provider's full
  // vocabulary would show up, and that the choice still varies (RFC 9849 6.2.1)
  LSawAes := False;
  LSawChaCha := False;
  for LI := 1 to 96 do
  begin
    LOrchestrator := TEchClientOrchestrator.Create(Crypto,
      TEchClientPolicy.Create(Crypto, nil, True, False) as IEchClientPolicy);
    LExt := LOrchestrator.GreaseEchExt;
    CheckTrue(System.Length(LExt) > 5, 'a decoy is built');
    LKdf := UInt16((LExt[1] shl 8) or LExt[2]);
    LAead := UInt16((LExt[3] shl 8) or LExt[4]);
    CheckEquals(Integer(THpkeKdf.HKDF_SHA256), Integer(LKdf), 'decoy KDF is HKDF-SHA256');
    CheckTrue((LAead = THpkeAead.AES_128_GCM) or (LAead = THpkeAead.CHACHA20_POLY1305),
      'decoy AEAD is AES-128-GCM or ChaCha20-Poly1305');
    LSawAes := LSawAes or (LAead = THpkeAead.AES_128_GCM);
    LSawChaCha := LSawChaCha or (LAead = THpkeAead.CHACHA20_POLY1305);
  end;
  // a provider lacking one of the AEADs cannot draw it, so require only what it supports
  for LSuite in Crypto.Hpke.SupportedSuites(THpkeKem.DHKEM_X25519_HKDF_SHA256) do
  begin
    if (LSuite.Kdf = THpkeKdf.HKDF_SHA256) and (LSuite.Aead = THpkeAead.AES_128_GCM) then
      CheckTrue(LSawAes, 'AES-128-GCM is drawn when the provider supports it');
    if (LSuite.Kdf = THpkeKdf.HKDF_SHA256) and (LSuite.Aead = THpkeAead.CHACHA20_POLY1305) then
      CheckTrue(LSawChaCha, 'ChaCha20-Poly1305 is drawn when the provider supports it');
  end;
end;

procedure TTestEchClientEngine.TestEmptyConfigListWithoutGreaseFailsClosed;
var
  LPolicy: IEchClientPolicy;
  LRaised: Boolean;
begin
  // an empty ECHConfigList with GREASE off would silently send the true SNI: reject it at
  // configuration time rather than fall back to cleartext
  LRaised := False;
  try
    LPolicy := TEchClientPolicy.Create(Crypto, nil, False, False) as IEchClientPolicy;
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'an empty ECHConfigList with GREASE off fails closed');
end;

procedure TTestEchClientEngine.TestMalformedConfigListIsAConfigurationError;
var
  LPolicy: IEchClientPolicy;
  LRaised, LWireAlert: Boolean;
begin
  // caller-supplied bytes that do not parse are an argument fault, not a peer-wire alert
  LRaised := False;
  LWireAlert := False;
  try
    LPolicy := TEchClientPolicy.Create(Crypto, TBytes.Create($00, $05, $01), False, False)
      as IEchClientPolicy;
  except
    on E: EFatalAlertTlsLibException do
      LWireAlert := True;
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckFalse(LWireAlert, 'a malformed ECHConfigList is not reported as a fatal-alert type');
  CheckTrue(LRaised, 'a malformed ECHConfigList raises EArgumentTlsLibException');
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
  const ASealer: IHpkeSealer; const AEncoded: TBytes; ALegacyVersion: UInt16): TBytes;
var
  LIdx: Int32;
  LAad: TBytes;
begin
  LIdx := AEntries.IndexOf(TExtensionTypes.EncryptedClientHello);
  // the AAD is the outer with the payload zeroed at its final length (RFC 9849 sec. 5.2); the
  // encoder always writes 0x0303, so the wanted legacy_version is patched into the AAD and the frame
  AEch.Payload := nil;
  System.SetLength(AEch.Payload, System.Length(AEncoded) + 16);
  AEntries.SetData(LIdx, TEchExtension.EncodeOuter(AEch));
  AOuter.Extensions := AEntries.Encode;
  LAad := THandshakeMessages.EncodeClientHello(AOuter);
  LAad[0] := Byte(ALegacyVersion shr 8);
  LAad[1] := Byte(ALegacyVersion);
  AEch.Payload := ASealer.Seal(LAad, AEncoded);
  AEntries.SetData(LIdx, TEchExtension.EncodeOuter(AEch));
  AOuter.Extensions := AEntries.Encode;
  Result := THandshakeFraming.Frame(TTlsHandshakeType.ClientHello,
    THandshakeMessages.EncodeClientHello(AOuter));
  Result[4] := Byte(ALegacyVersion shr 8);
  Result[5] := Byte(ALegacyVersion);
end;

procedure TTestEchClientEngine.PrepareReseal(out AServer: IEchServerHandshake;
  out AOuter: TTlsClientHello; out AEntries: TExtensionVector;
  out AEch: TEchOuterClientHello; out ASealer: IHpkeSealer; out AEncoded: TBytes);
var
  LOuterFramed, LOuterBody, LAad, LEnc: TBytes;
  LEch: TExtensionEntry;
  LType: TEchClientHelloType;
  LConfig: TEchConfig;
  LSuite: IHpkeSuite;
  LSk: ISecretBuffer;
  LOpener: IHpkeOpener;
  LStore: IEchServerKeyStore;
begin
  LOuterFramed := OuterClientHello;
  LOuterBody := System.Copy(LOuterFramed, 4, System.Length(LOuterFramed) - 4);
  AOuter := THandshakeMessages.DecodeClientHello(LOuterBody);
  AEntries := TExtensionVector.Parse(AOuter.Extensions);
  CheckTrue(AEntries.TryFind(TExtensionTypes.EncryptedClientHello, LEch), 'outer has an ech extension');
  TEchExtension.Decode(LEch.Data, LType, AEch);
  LConfig := TEchConfigList.Parse(DecodeHex(FVec.Values['config_list']))[0];
  LSuite := Crypto.Hpke.Suite(LConfig.KemId, AEch.CipherSuite.KdfId, AEch.CipherSuite.AeadId);
  LSk := Crypto.Hpke.ImportPrivateKey(THpkeKem.DHKEM_X25519_HKDF_SHA256,
    DecodeHex(FVec.Values['config_private_key']));

  // recover the encoded inner the real client sealed
  FillChar(AEch.Payload[0], System.Length(AEch.Payload), 0);
  AEntries.SetData(AEntries.IndexOf(TExtensionTypes.EncryptedClientHello),
    TEchExtension.EncodeOuter(AEch));
  AOuter.Extensions := AEntries.Encode;
  LAad := THandshakeMessages.EncodeClientHello(AOuter);
  TEchExtension.Decode(LEch.Data, LType, AEch);
  LOpener := Crypto.Hpke.ImportRecipientKey(LSuite.Kem, LSk)
    .SetupOpener(LSuite, AEch.Enc, LConfig.HpkeInfo);
  AEncoded := LOpener.Open(LAad, AEch.Payload);

  // reseal it under a wire config_id that is not the entry's
  AEch.ConfigId := Byte(AEch.ConfigId xor 1);
  LSuite.SetupSealer(LConfig.PublicKey, LConfig.HpkeInfo, LEnc, ASealer);
  AEch.Enc := LEnc;
  LStore := TInMemoryEchKeyStore.FromConfig(DecodeHex(FVec.Values['config_list']), LSk, Crypto);
  AServer := TEchServerHandshake.Create(Crypto, TEchServerPolicy.Keyed(Crypto, LStore, True))
    as IEchServerHandshake;
end;

procedure TTestEchClientEngine.TestRetryChecksTheWireConfigIdNotTheEntrys;
var
  LEncoded, LRetryFramed: TBytes;
  LOuter: TTlsClientHello;
  LEntries: TExtensionVector;
  LOuterEch: TEchOuterClientHello;
  LSealer: IHpkeSealer;
  LServer: IEchServerHandshake;
  LStandard: UInt16;
begin
  // a client that ignores the config identifiers randomizes config_id on the first hello and must
  // keep that value on the retry (RFC 9849 sec. 6.1.1, 7.1.1); a trial-decrypting server compares
  // the retry with what it was sent, not with the id of the key-store entry that opened it
  PrepareReseal(LServer, LOuter, LEntries, LOuterEch, LSealer, LEncoded);
  LStandard := TlsWireVersionTls12;
  CheckTrue(ProcessOuterFramed(LServer,
    SealOuter(LOuter, LEntries, LOuterEch, LSealer, LEncoded, LStandard)) =
    TEchStatus.Accepted, 'the trial-decrypting server opens the first hello');

  // the retry keeps the wire id, cipher_suite and an empty enc, sealed at the next sequence number
  LOuterEch.Enc := nil;
  LRetryFramed := SealOuter(LOuter, LEntries, LOuterEch, LSealer, LEncoded, LStandard);
  CheckTrue(LServer.ProcessRetryOuter(LRetryFramed) = TEchStatus.Accepted,
    'the retry that keeps the wire config_id is accepted');
end;

procedure TTestEchClientEngine.TestAcceptedOuterWithLegacyVersion0304AbortsProtocolVersion;
var
  LEncoded: TBytes;
  LOuter: TTlsClientHello;
  LEntries: TExtensionVector;
  LOuterEch: TEchOuterClientHello;
  LSealer: IHpkeSealer;
  LServer: IEchServerHandshake;
  LFuture: UInt16;
  LAlert: TTlsAlertDescription;
  LRaised: Boolean;
begin
  // the outer is sealed correctly (its AAD carries the bad legacy_version), so only the
  // legacy_version rule can refuse it (RFC 9846 4.2.2)
  PrepareReseal(LServer, LOuter, LEntries, LOuterEch, LSealer, LEncoded);
  LFuture := TlsWireVersionTls13;
  LRaised := False;
  LAlert := TTlsAlertDescription.CloseNotify;
  try
    ProcessOuterFramed(LServer, SealOuter(LOuter, LEntries, LOuterEch, LSealer, LEncoded,
      LFuture));
  except
    on E: EFatalAlertTlsLibException do
    begin
      LRaised := True;
      LAlert := E.AlertDescription;
    end;
  end;
  CheckTrue(LRaised, 'an accepted outer with legacy_version 0x0304 aborts');
  CheckTrue(LAlert = TTlsAlertDescription.ProtocolVersion, 'it is protocol_version');
end;

procedure TTestEchClientEngine.TestRetryOuterWithLegacyVersion0304AbortsProtocolVersion;
var
  LEncoded: TBytes;
  LOuter: TTlsClientHello;
  LEntries: TExtensionVector;
  LOuterEch: TEchOuterClientHello;
  LSealer: IHpkeSealer;
  LServer: IEchServerHandshake;
  LStandard, LFuture: UInt16;
  LAlert: TTlsAlertDescription;
  LRaised: Boolean;
begin
  PrepareReseal(LServer, LOuter, LEntries, LOuterEch, LSealer, LEncoded);
  LStandard := TlsWireVersionTls12;
  LFuture := TlsWireVersionTls13;
  CheckTrue(ProcessOuterFramed(LServer,
    SealOuter(LOuter, LEntries, LOuterEch, LSealer, LEncoded, LStandard)) =
    TEchStatus.Accepted, 'the first outer is accepted');
  LOuterEch.Enc := nil;
  LRaised := False;
  LAlert := TTlsAlertDescription.CloseNotify;
  try
    LServer.ProcessRetryOuter(SealOuter(LOuter, LEntries, LOuterEch, LSealer, LEncoded,
      LFuture));
  except
    on E: EFatalAlertTlsLibException do
    begin
      LRaised := True;
      LAlert := E.AlertDescription;
    end;
  end;
  CheckTrue(LRaised, 'a retry outer with legacy_version 0x0304 aborts');
  CheckTrue(LAlert = TTlsAlertDescription.ProtocolVersion, 'it is protocol_version');
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

function TTestEchClientEngine.TamperedInnerAlert(AExtType: UInt16;
  const AData: TBytes): TTlsAlertDescription;
var
  LEncoded, LTampered: TBytes;
  LOuter: TTlsClientHello;
  LEntries, LExtensions: TExtensionVector;
  LOuterEch: TEchOuterClientHello;
  LSealer: IHpkeSealer;
  LServer: IEchServerHandshake;
  LReader: TWireReader;
  LStart, LTail, LIdx: Int32;
begin
  PrepareReseal(LServer, LOuter, LEntries, LOuterEch, LSealer, LEncoded);
  // skip legacy_version, random, session id, cipher suites and compression to the extensions
  LReader := TWireReader.Create(LEncoded);
  LReader.Skip(34);
  LReader.OpenVector(1);
  LReader.OpenVector(2);
  LReader.OpenVector(1);
  LStart := LReader.Position;
  LExtensions := TExtensionVector.ParseFrom(LReader);
  LTail := LReader.Position;
  // expand the compression so the inner stays complete and only the tampered extension differs
  LExtensions := TEchOuterExtensions.Reconstruct(LEntries, LExtensions);
  LIdx := LExtensions.IndexOf(AExtType);
  if LIdx >= 0 then
    LExtensions.SetData(LIdx, AData)
  else
    LExtensions.Append(TExtensionEntry.Create(AExtType, AData));
  LTampered := ConcatBytes(ConcatBytes(System.Copy(LEncoded, 0, LStart), LExtensions.Encode),
    System.Copy(LEncoded, LTail, System.Length(LEncoded) - LTail));
  Result := TTlsAlertDescription.CloseNotify;
  try
    ProcessOuterFramed(LServer, SealOuter(LOuter, LEntries, LOuterEch, LSealer, LTampered,
      TlsWireVersionTls12));
  except
    on E: EFatalAlertTlsLibException do
      Result := E.AlertDescription;
  end;
end;

procedure TTestEchClientEngine.TestInnerEchWithTrailingByteIsIllegalParameter;
begin
  // the inner ech is the lone type byte (RFC 9849 sec. 7.1); a trailing byte is not a decode_error
  CheckEquals(Integer(TTlsAlertDescription.IllegalParameter),
    Integer(TamperedInnerAlert(TExtensionTypes.EncryptedClientHello, DecodeHex('0100'))),
    'an inner ech with an extra byte is illegal_parameter');
end;

procedure TTestEchClientEngine.TestInnerEchEmptyBodyIsIllegalParameter;
begin
  CheckEquals(Integer(TTlsAlertDescription.IllegalParameter),
    Integer(TamperedInnerAlert(TExtensionTypes.EncryptedClientHello, nil)),
    'an inner ech with no body is illegal_parameter');
end;

procedure TTestEchClientEngine.TestInnerEchTruncatedOuterFormIsIllegalParameter;
begin
  // outer type byte then a cut-off kdf/aead pair: the sealed inner must not surface a decode_error
  CheckEquals(Integer(TTlsAlertDescription.IllegalParameter),
    Integer(TamperedInnerAlert(TExtensionTypes.EncryptedClientHello, DecodeHex('0000010001'))),
    'a truncated outer-form ech inside the inner is illegal_parameter');
end;

procedure TTestEchClientEngine.TestWellFormedInnerEchIsAccepted;
begin
  // positive control: the tampering helper reports no alert for a valid inner ech marker
  CheckEquals(Integer(TTlsAlertDescription.CloseNotify),
    Integer(TamperedInnerAlert(TExtensionTypes.EncryptedClientHello, DecodeHex('01'))),
    'a well-formed inner ech raises no alert');
end;

procedure TTestEchClientEngine.TestEmptyInnerSupportedVersionsIsDecodeError;
begin
  // an empty versions<2..254> list is a syntax error, not an offer of an old version
  CheckEquals(Integer(TTlsAlertDescription.DecodeError),
    Integer(TamperedInnerAlert(TExtensionTypes.SupportedVersions, DecodeHex('00'))),
    'an empty inner supported_versions list is decode_error');
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

function TTestEchClientEngine.GreaseClientHrrEffects(
  const AEchBody: TBytes): TArray<THandshakeEffect>;
var
  LParams: TClientHandshakeParams;
  LMachine: TTls13ClientStateMachine;
  LCodec: IExtensionBlockCodec;
  LContext: TExtensionContext;
  LHello: TTlsServerHello;
  LHrr: TBytes;
begin
  LParams := BaseParams(DecodeHex(FVec.Values['config_list']));
  LParams.EchPolicy := TEchClientPolicy.Create(Crypto, nil, True, False) as IEchClientPolicy;
  LCodec := TExtensionBlockCodec.Create(TCoreExtensions.CreateDefaultRegistry);
  LContext := TExtensionContext.Create;
  try
    LContext.SelectedVersion := TlsWireVersionTls13;
    LContext.Cookie := DecodeHex('a1b2c3d4e5f6');
    LContext.EchExtensionData := AEchBody;
    LHello.Random := THelloRetryRequest.SentinelRandom;
    LHello.LegacySessionIdEcho := LParams.LegacySessionId;
    LHello.CipherSuite := TCipherSuites13.Aes128GcmSha256;
    LHello.Extensions := LCodec.ProduceBlock(LContext,
      TTlsExtensionContextKind.HelloRetryRequest);
  finally
    LContext.Free;
  end;
  LHrr := THandshakeFraming.Frame(TTlsHandshakeType.ServerHello,
    THandshakeMessages.EncodeServerHello(LHello));
  LMachine := TTls13ClientStateMachine.Create(LParams);
  try
    LMachine.Start;
    Result := LMachine.ProcessMessage(TTlsLibTestHandshakeDecoder.HandshakeMessage(LHrr));
  finally
    LMachine.Free;
  end;
end;

procedure TTestEchClientEngine.TestGreaseClientRejectsHrrEchOfWrongLengthWithDecodeError;
var
  LEffects: TArray<THandshakeEffect>;
  LI: Int32;
  LFailed: Boolean;
begin
  // RFC 9849 sec. 6.2.1: a GREASE client still rejects a malformed HRR ech with decode_error
  LEffects := GreaseClientHrrEffects(DecodeHex('aabbcc'));
  LFailed := False;
  for LI := 0 to System.High(LEffects) do
    if LEffects[LI].Kind = THandshakeEffectKind.Fail then
    begin
      LFailed := True;
      CheckEquals(Integer(TTlsAlertDescription.DecodeError), Integer(LEffects[LI].Alert),
        'a malformed HRR ech under GREASE is a decode_error');
      CheckTrue(Pos('confirmation must be 8 bytes', LEffects[LI].Reason) > 0,
        'the failure comes from the HRR confirmation length check');
    end;
  CheckTrue(LFailed, 'a malformed HRR ech under GREASE aborts the handshake');
end;

procedure TTestEchClientEngine.TestGreaseClientIgnoresWellFormedHrrEchAndRetries;
var
  LEffects: TArray<THandshakeEffect>;
  LI, LSent: Int32;
begin
  // the decoy was not accepted, so an 8-byte HRR ech (any value) is ignored and the retry is sent
  LEffects := GreaseClientHrrEffects(DecodeHex('0102030405060708'));
  LSent := 0;
  for LI := 0 to System.High(LEffects) do
  begin
    CheckFalse(LEffects[LI].Kind = THandshakeEffectKind.Fail,
      'a well-formed HRR ech under GREASE does not abort');
    if LEffects[LI].Kind = THandshakeEffectKind.SendHandshake then
      Inc(LSent);
  end;
  CheckEquals(1, LSent, 'the GREASE client sends its second ClientHello');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestEchClientEngine);
{$ELSE}
  RegisterTest(TTestEchClientEngine.Suite);
{$ENDIF FPC}

end.
