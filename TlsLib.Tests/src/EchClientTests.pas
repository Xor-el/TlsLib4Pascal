{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit EchClientTests;

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
  TlpWireReader,
  TlpIWireWriter,
  TlpWireWriter,
  TlpWireVectorMarker,
  TlpHandshakeMessages,
  TlpCoreExtensions,
  TlpEchConfig,
  TlpEchExtension,
  TlpEchOuterExtensions,
  TlpEchClient,
  TlpSecureMemory,
  TlsLibTestBase;

type
  /// <summary>
  /// The client-side ECH encoding (RFC 9849 sec. 5.1 / 5.2 / 6.1.3): the padding
  /// algorithm, and a full seal -> open -> reconstruct round-trip against the real
  /// OpenSSL-generated config key pair - proving the EncodedClientHelloInner (empty
  /// session_id, ech_outer_extensions compression, zero padding) decrypts and
  /// reconstructs byte-for-byte back to the original ClientHelloInner.
  /// </summary>
  TTestEchClient = class(TTlsLibAlgorithmTestCase)
  private
    FVec: TStringList;
    function SelectConfig(out ASuite: IHpkeSuite): TEchConfig;
    function Entry(AType: UInt16; const AData: TBytes): TEchExtEntry;
    function ServerNameEntry(const AHost: string): TEchExtEntry;
    function ExtField(const AEntries: TArray<TEchExtEntry>): TBytes;
    function InnerBody(const AEntries: TArray<TEchExtEntry>): TBytes;
    procedure ParseEncodedInner(const AEncoded: TBytes;
      out AEntries: TArray<TEchExtEntry>; out APadding: TBytes);
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestPaddingWithServerName;
    procedure TestPaddingWithoutServerName;
    procedure TestPaddingMaxNameLengthZero;
    procedure TestPaddingRoundsToMultipleOf32;
    procedure TestSealOpenReconstructRoundTrip;
    procedure TestEncodedInnerHasEmptySessionIdAndZeroPadding;
    procedure TestCompressionReferencesSharedExtensions;
    procedure TestAcceptConfirmationMatch;
  end;

implementation

{ TTestEchClient }

procedure TTestEchClient.SetUp;
begin
  inherited SetUp;
  FVec := LoadVectorFields('Certs/Ech.txt');
end;

procedure TTestEchClient.TearDown;
begin
  FVec.Free;
  inherited TearDown;
end;

function TTestEchClient.SelectConfig(out ASuite: IHpkeSuite): TEchConfig;
var
  LConfigs: TArray<TEchConfig>;
  LChosen: TEchConfig;
begin
  LConfigs := TEchConfigList.Parse(DecodeHex(FVec.Values['config_list']));
  CheckTrue(TEchConfigList.TrySelect(LConfigs, Provider, LChosen, ASuite),
    'the vector config is usable');
  Result := LChosen;
end;

function TTestEchClient.Entry(AType: UInt16; const AData: TBytes): TEchExtEntry;
begin
  Result.ExtType := AType;
  Result.Data := AData;
end;

function TTestEchClient.ServerNameEntry(const AHost: string): TEchExtEntry;
var
  LWriter: IWireWriter;
  LList, LName: TWireVectorMarker;
  LI: Int32;
begin
  // server_name (RFC 6066): ServerNameList { NameType host_name(0); HostName<1..> }
  LWriter := TWireWriter.Create;
  LList := LWriter.OpenVector(2);
  LWriter.WriteUInt8(0);
  LName := LWriter.OpenVector(2);
  for LI := 1 to System.Length(AHost) do
    LWriter.WriteUInt8(Byte(Ord(AHost[LI])));
  LWriter.CloseVector(LName);
  LWriter.CloseVector(LList);
  Result := Entry(TExtensionTypes.ServerName, LWriter.ToBytes);
end;

function TTestEchClient.ExtField(const AEntries: TArray<TEchExtEntry>): TBytes;
var
  LWriter: IWireWriter;
  LMarker: TWireVectorMarker;
begin
  LWriter := TWireWriter.Create;
  LMarker := LWriter.OpenVector(2);
  LWriter.WriteBytes(TEchOuterExtensions.EncodeExtensions(AEntries));
  LWriter.CloseVector(LMarker);
  Result := LWriter.ToBytes;
end;

function TTestEchClient.InnerBody(const AEntries: TArray<TEchExtEntry>): TBytes;
var
  LHello: TTlsClientHello;
begin
  LHello := Default(TTlsClientHello);
  LHello.Random := DecodeHex(
    '0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20');
  LHello.LegacySessionId := DecodeHex(
    'a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf');
  LHello.CipherSuites := TArray<UInt16>.Create(UInt16($1301), UInt16($1303));
  LHello.Extensions := ExtField(AEntries);
  Result := THandshakeMessages.EncodeClientHello(LHello);
end;

procedure TTestEchClient.ParseEncodedInner(const AEncoded: TBytes;
  out AEntries: TArray<TEchExtEntry>; out APadding: TBytes);
var
  LReader, LSession, LCipher, LComp, LExts: TWireReader;
begin
  // EncodedClientHelloInner = client_hello || zeros. The client_hello ends at its
  // extensions vector; everything after is padding (must be zero).
  LReader := TWireReader.Create(AEncoded);
  LReader.Skip(2); // legacy_version
  LReader.Skip(32); // random
  LSession := LReader.OpenVector(1); // legacy_session_id (must be empty)
  CheckEquals(0, LSession.Remaining, 'EncodedClientHelloInner session_id is empty');
  LCipher := LReader.OpenVector(2); // cipher_suites
  LComp := LReader.OpenVector(1); // legacy_compression_methods
  CheckTrue((LCipher.Remaining >= 0) and (LComp.Remaining >= 0), 'framed');
  LExts := LReader.OpenVector(2); // extensions
  AEntries := TEchOuterExtensions.ParseExtensions(
    LExts.ReadBytes(LExts.Remaining));
  APadding := LReader.ReadBytes(LReader.Remaining);
end;

procedure TTestEchClient.TestPaddingWithServerName;
begin
  // D=18, M=64: stage1 = 46; L = 100+46 = 146; round N = 31 - ((146-1) mod 32) = 14
  CheckEquals(60, TEchClientHandshake.PaddingLength(100, 18, True, 64),
    'server-name padding + rounding');
end;

procedure TTestEchClient.TestPaddingWithoutServerName;
begin
  // no SNI, M=64: stage1 = 64+9 = 73; L = 100+73 = 173; N = 31 - ((173-1) mod 32) = 19
  CheckEquals(92, TEchClientHandshake.PaddingLength(100, 0, False, 64),
    'no-server-name padding + rounding');
end;

procedure TTestEchClient.TestPaddingMaxNameLengthZero;
begin
  // M=0 with a server name: no stage-1 padding, only 32-byte rounding (the plan's
  // maximum_name_length = 0 case)
  CheckEquals(24, TEchClientHandshake.PaddingLength(200, 13, True, 0),
    'only rounding when maximum_name_length is 0');
end;

procedure TTestEchClient.TestPaddingRoundsToMultipleOf32;
var
  LLen, LPad: Int32;
begin
  for LLen := 1 to 400 do
  begin
    LPad := TEchClientHandshake.PaddingLength(LLen, 5, True, 20);
    CheckEquals(0, (LLen + LPad) and 31,
      Format('length %d is padded to a multiple of 32', [LLen]));
  end;
end;

procedure TTestEchClient.TestSealOpenReconstructRoundTrip;
var
  LConfig: TEchConfig;
  LSuite: IHpkeSuite;
  LEch: TEchClientHandshake;
  LInnerEntries, LOuterEntries, LEncEntries, LReconstructed: TArray<TEchExtEntry>;
  LInner, LEncoded, LEnc, LAad, LPayload, LDecrypted, LPadding: TBytes;
  LSk: ISecretBuffer;
  LOpener: IHpkeOpener;
  LI: Int32;
begin
  LConfig := SelectConfig(LSuite);
  // inner: real SNI + a contiguous run of extensions the outer shares verbatim
  LInnerEntries := TArray<TEchExtEntry>.Create(
    ServerNameEntry('secret.internal.example'),
    Entry(TExtensionTypes.SupportedGroups, DecodeHex('00020017')),
    Entry(TExtensionTypes.KeyShare, DecodeHex('0017000401020304')),
    Entry(TExtensionTypes.SupportedVersions, DecodeHex('020304')),
    Entry(TExtensionTypes.RecordSizeLimit, DecodeHex('4001')));
  // outer: public_name SNI (differs, not shared) + the same shared extensions in order
  LOuterEntries := TArray<TEchExtEntry>.Create(
    ServerNameEntry('cover.example'),
    Entry(TExtensionTypes.SupportedGroups, DecodeHex('00020017')),
    Entry(TExtensionTypes.KeyShare, DecodeHex('0017000401020304')),
    Entry(TExtensionTypes.SupportedVersions, DecodeHex('020304')));

  LInner := InnerBody(LInnerEntries);
  LEch := TEchClientHandshake.Create(Provider, LConfig, LSuite);
  try
    LEncoded := LEch.BuildEncodedInner(LInner, LOuterEntries);
    LEnc := LEch.SetupSeal;
    LAad := DecodeHex('cafebabe00112233445566778899aabbccddeeff');
    LPayload := LEch.Seal(LAad, LEncoded);
  finally
    LEch.Free;
  end;

  // server side: decrypt with the config's real private key + the same HPKE info
  LSk := Provider.Hpke.ImportPrivateKey(THpkeKem.DHKEM_X25519_HKDF_SHA256,
    DecodeHex(FVec.Values['config_private_key']));
  LOpener := Provider.Hpke.ImportRecipientKey(LSuite.Kem, LSk)
    .SetupOpener(LSuite, LEnc, LConfig.HpkeInfo);
  LDecrypted := LOpener.Open(LAad, LPayload);
  CheckEqualBytes('decrypted equals the encoded inner', LEncoded, LDecrypted);

  // reconstruct the inner extensions from the decrypted encoded-inner + the outer
  ParseEncodedInner(LDecrypted, LEncEntries, LPadding);
  LReconstructed := TEchOuterExtensions.Reconstruct(LOuterEntries, LEncEntries);
  CheckEquals(System.Length(LInnerEntries), System.Length(LReconstructed),
    'reconstructed inner has the original extension count');
  for LI := 0 to System.High(LInnerEntries) do
  begin
    CheckEquals(Integer(LInnerEntries[LI].ExtType),
      Integer(LReconstructed[LI].ExtType), 'reconstructed extension type');
    CheckEqualBytes('reconstructed extension data', LInnerEntries[LI].Data,
      LReconstructed[LI].Data);
  end;
end;

procedure TTestEchClient.TestEncodedInnerHasEmptySessionIdAndZeroPadding;
var
  LConfig: TEchConfig;
  LSuite: IHpkeSuite;
  LEch: TEchClientHandshake;
  LEntries, LOuter, LEncEntries: TArray<TEchExtEntry>;
  LEncoded, LPadding: TBytes;
begin
  LConfig := SelectConfig(LSuite);
  LEntries := TArray<TEchExtEntry>.Create(ServerNameEntry('secret.example.com'),
    Entry(TExtensionTypes.SupportedGroups, DecodeHex('00020017')));
  LOuter := TArray<TEchExtEntry>.Create(
    Entry(TExtensionTypes.SupportedGroups, DecodeHex('00020017')));
  LEch := TEchClientHandshake.Create(Provider, LConfig, LSuite);
  try
    LEncoded := LEch.BuildEncodedInner(InnerBody(LEntries), LOuter);
  finally
    LEch.Free;
  end;
  ParseEncodedInner(LEncoded, LEncEntries, LPadding);
  CheckEquals(0, (System.Length(LEncoded)) and 31,
    'the encoded inner is a multiple of 32 bytes');
  CheckTrue(TSecureMemory.ConstantTimeIsAllZero(LPadding),
    'padding bytes are all zero');
end;

procedure TTestEchClient.TestCompressionReferencesSharedExtensions;
var
  LConfig: TEchConfig;
  LSuite: IHpkeSuite;
  LEch: TEchClientHandshake;
  LInnerEntries, LOuter, LEncEntries: TArray<TEchExtEntry>;
  LEncoded, LPadding: TBytes;
  LI: Int32;
  LHasOuterExt, LHasInlinedGroups: Boolean;
begin
  LConfig := SelectConfig(LSuite);
  LInnerEntries := TArray<TEchExtEntry>.Create(ServerNameEntry('secret.example.com'),
    Entry(TExtensionTypes.SupportedGroups, DecodeHex('00020017')),
    Entry(TExtensionTypes.KeyShare, DecodeHex('0017000401020304')));
  LOuter := TArray<TEchExtEntry>.Create(
    Entry(TExtensionTypes.SupportedGroups, DecodeHex('00020017')),
    Entry(TExtensionTypes.KeyShare, DecodeHex('0017000401020304')));
  LEch := TEchClientHandshake.Create(Provider, LConfig, LSuite);
  try
    LEncoded := LEch.BuildEncodedInner(InnerBody(LInnerEntries), LOuter);
  finally
    LEch.Free;
  end;
  ParseEncodedInner(LEncoded, LEncEntries, LPadding);
  LHasOuterExt := False;
  LHasInlinedGroups := False;
  for LI := 0 to System.High(LEncEntries) do
  begin
    if LEncEntries[LI].ExtType = TExtensionTypes.EchOuterExtensions then
      LHasOuterExt := True;
    if LEncEntries[LI].ExtType = TExtensionTypes.SupportedGroups then
      LHasInlinedGroups := True;
  end;
  CheckTrue(LHasOuterExt, 'an ech_outer_extensions block was produced');
  CheckFalse(LHasInlinedGroups,
    'the shared supported_groups was compressed out, not inlined');
end;

procedure TTestEchClient.TestAcceptConfirmationMatch;
var
  LInnerRandom, LTranscript, LGood, LBad: TBytes;
begin
  LInnerRandom := DecodeHex(
    '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
  LTranscript := DecodeHex(
    '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f');
  // last 8 bytes carry the Task-3 KAT confirmation value 113047a36d18f54c
  LGood := DecodeHex(
    '000000000000000000000000000000000000000000000000113047a36d18f54c');
  CheckTrue(TEchClientHandshake.AcceptConfirmationMatches(
    Provider.Primitives.CreateHkdf(THashAlgorithm.SHA_256), LInnerRandom,
    LTranscript, LGood), 'a matching confirmation is accepted');
  LBad := DecodeHex(
    '0000000000000000000000000000000000000000000000000000000000000000');
  CheckFalse(TEchClientHandshake.AcceptConfirmationMatches(
    Provider.Primitives.CreateHkdf(THashAlgorithm.SHA_256), LInnerRandom,
    LTranscript, LBad), 'a non-matching confirmation is rejected');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestEchClient);
{$ELSE}
  RegisterTest(TTestEchClient.Suite);
{$ENDIF FPC}

end.
