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
  TlpIWireWriter,
  TlpWireWriter,
  TlpWireVectorMarker,
  TlpHandshakeMessages,
  TlpHandshakeEffect,
  TlpTls13ClientStateMachine,
  TlpEchConfig,
  TlpEchExtension,
  TlpEchOuterExtensions,
  TlpEchClient,
  TlpIEch,
  TlpTlsLibExceptions,
  TlsLibTestBase;

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
    function FindEntry(const AEntries: TArray<TEchExtEntry>;
      AType: UInt16; out AEntry: TEchExtEntry): Boolean;
    function SniHost(const AServerNameData: TBytes): string;
    function Contains(const AHaystack, ANeedle: TBytes): Boolean;
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestOuterHidesRealSniAndDecryptsToInner;
    procedure TestUnusableConfigFailsClosed;
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
  Result.Provider := Provider;
  Result.Clock := TSystemClock.Create;
  Result.Group := TNamedGroups.CreateX25519(Provider);
  Result.GroupCode := TNamedGroupCatalog.X25519;
  Result.CipherSuites := TCipherSuiteRegistry.CreateDefault(Provider);
  Result.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  Result.OfferedSuites := TArray<UInt16>.Create(TCipherSuites13.Aes128GcmSha256);
  Result.OfferedSchemes :=
    TArray<UInt16>.Create(TSignatureSchemes.EcdsaSecp256r1Sha256);
  Result.ClientRandom := DecodeHex(
    '1111111111111111111111111111111111111111111111111111111111111111');
  Result.LegacySessionId := DecodeHex(
    '3333333333333333333333333333333333333333333333333333333333333333');
  Result.ServerName := RealSni;
  Result.ExpectedHostName := RealSni;
  Result.EchPolicy := TEchClientPolicy.Create(AEchConfigList, False, False)
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

function TTestEchClientEngine.FindEntry(const AEntries: TArray<TEchExtEntry>;
  AType: UInt16; out AEntry: TEchExtEntry): Boolean;
var
  LI: Int32;
begin
  for LI := 0 to System.High(AEntries) do
    if AEntries[LI].ExtType = AType then
    begin
      AEntry := AEntries[LI];
      Exit(True);
    end;
  Result := False;
end;

function TTestEchClientEngine.SniHost(const AServerNameData: TBytes): string;
var
  LReader, LList, LName: TWireReader;
  LBytes: TBytes;
  LI: Int32;
begin
  Result := '';
  LReader := TWireReader.Create(AServerNameData);
  LList := LReader.OpenVector(2);
  if LList.ReadUInt8 <> 0 then
    Exit;
  LName := LList.OpenVector(2);
  LBytes := LName.ReadBytes(LName.Remaining);
  SetLength(Result, System.Length(LBytes));
  for LI := 0 to System.High(LBytes) do
    Result[LI + 1] := Char(LBytes[LI]);
end;

function TTestEchClientEngine.Contains(const AHaystack, ANeedle: TBytes): Boolean;
var
  LI, LJ: Int32;
  LMatch: Boolean;
begin
  if System.Length(ANeedle) = 0 then
    Exit(True);
  for LI := 0 to System.Length(AHaystack) - System.Length(ANeedle) do
  begin
    LMatch := True;
    for LJ := 0 to System.High(ANeedle) do
      if AHaystack[LI + LJ] <> ANeedle[LJ] then
      begin
        LMatch := False;
        Break;
      end;
    if LMatch then
      Exit(True);
  end;
  Result := False;
end;

procedure TTestEchClientEngine.TestOuterHidesRealSniAndDecryptsToInner;
var
  LOuterFramed, LOuterBody, LAad, LEncoded: TBytes;
  LOuter: TTlsClientHello;
  LEntries, LEncEntries, LReconstructed: TArray<TEchExtEntry>;
  LSni, LEch, LReEch: TEchExtEntry;
  LType: TEchClientHelloType;
  LOuterEch: TEchOuterClientHello;
  LReader, LBody, LExtReader, LSessReader: TWireReader;
  LWriter: IWireWriter;
  LMarker: TWireVectorMarker;
  LConfigs: TArray<TEchConfig>;
  LConfig: TEchConfig;
  LSuite: THpkeSuite;
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
  CheckFalse(Contains(LOuterFramed, LRealSniBytes),
    'the true SNI is not in the outer ClientHello');

  LOuterBody := System.Copy(LOuterFramed, 4, System.Length(LOuterFramed) - 4);
  LOuter := THandshakeMessages.DecodeClientHello(LOuterBody);
  LReader := TWireReader.Create(LOuter.Extensions);
  LBody := LReader.OpenVector(2);
  LEntries := TEchOuterExtensions.ParseExtensions(LBody.ReadBytes(LBody.Remaining));

  // the outer offers the public_name
  CheckTrue(FindEntry(LEntries, TExtensionTypes.ServerName, LSni), 'outer has SNI');
  CheckEquals(PublicName, SniHost(LSni.Data), 'the outer SNI is the public_name');

  // decode the outer encrypted_client_hello extension
  CheckTrue(FindEntry(LEntries, TExtensionTypes.EncryptedClientHello, LEch),
    'outer has an ech extension');
  TEchExtension.Decode(LEch.Data, LType, LOuterEch);
  CheckEquals(Ord(TEchClientHelloType.Outer), Ord(LType), 'it is the outer form');

  // rebuild the ClientHelloOuterAAD: the outer body with the ech payload zeroed
  LReEch := LEch;
  FillChar(LOuterEch.Payload[0], System.Length(LOuterEch.Payload), 0);
  LReEch.Data := TEchExtension.EncodeOuter(LOuterEch);
  for LI := 0 to System.High(LEntries) do
    if LEntries[LI].ExtType = TExtensionTypes.EncryptedClientHello then
      LEntries[LI] := LReEch;
  LWriter := TWireWriter.Create;
  LMarker := LWriter.OpenVector(2);
  LWriter.WriteBytes(TEchOuterExtensions.EncodeExtensions(LEntries));
  LWriter.CloseVector(LMarker);
  LOuter.Extensions := LWriter.ToBytes;
  LAad := THandshakeMessages.EncodeClientHello(LOuter);

  // decrypt with the config's private key and the config's HPKE info
  LConfigs := TEchConfigList.Parse(DecodeHex(FVec.Values['config_list']));
  LConfig := LConfigs[0];
  TEchExtension.Decode(LEch.Data, LType, LOuterEch); // re-decode for the real payload
  LSuite := THpkeSuite.Create(LConfig.KemId, LOuterEch.CipherSuite.KdfId,
    LOuterEch.CipherSuite.AeadId);
  LSk := Provider.Hpke.ImportPrivateKey(THpkeKem.DHKEM_X25519_HKDF_SHA256,
    DecodeHex(FVec.Values['config_private_key']));
  LOpener := Provider.Hpke.ImportRecipientKey(LSuite.Kem, LSk)
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
  LExtReader := LReader.OpenVector(2);
  LEncEntries := TEchOuterExtensions.ParseExtensions(
    LExtReader.ReadBytes(LExtReader.Remaining));
  LReconstructed := TEchOuterExtensions.Reconstruct(LEntries, LEncEntries);

  // the reconstructed inner carries the real SNI
  CheckTrue(FindEntry(LReconstructed, TExtensionTypes.ServerName, LSni),
    'the inner has a server_name');
  CheckEquals(RealSni, SniHost(LSni.Data),
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

initialization

{$IFDEF FPC}
  RegisterTest(TTestEchClientEngine);
{$ELSE}
  RegisterTest(TTestEchClientEngine.Suite);
{$ENDIF FPC}

end.
