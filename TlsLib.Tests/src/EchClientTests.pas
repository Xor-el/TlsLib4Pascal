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
  TlpNegotiationTypes,
  TlpICryptoProvider,
  TlpISecretBuffer,
  TlpWireReader,
  TlpIWireWriter,
  TlpWireWriter,
  TlpWireVectorMarker,
  TlpHandshakeMessages,
  TlpCoreExtensions,
  TlpExtensionVector,
  TlpEchConfig,
  TlpEchExtension,
  TlpEchOuterExtensions,
  TlpEchClient,
  TlpSecureMemory,
  TlpTlsLibExceptions,
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
    function Entry(AType: UInt16; const AData: TBytes): TExtensionEntry;
    function ServerNameEntry(const AHost: string): TExtensionEntry;
    function Vec(const AEntries: array of TExtensionEntry): TExtensionVector;
    function InnerBody(const AEntries: TExtensionVector): TBytes;
    procedure ParseEncodedInner(const AEncoded: TBytes;
      out AEntries: TExtensionVector; out APadding: TBytes);
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestRecipientPublicKeyIsACopy;
    procedure TestPaddingWithServerName;
    procedure TestPaddingWithoutServerName;
    procedure TestPaddingMaxNameLengthZero;
    procedure TestPaddingRoundsToMultipleOf32;
    procedure TestSealOpenReconstructRoundTrip;
    procedure TestEncodedInnerHasEmptySessionIdAndZeroPadding;
    procedure TestCompressionReferencesSharedExtensions;
    procedure TestGreasePlacementDrivesCompression;
    procedure TestAcceptConfirmationMatch;
    procedure TestGreaseEncapsulationIsValid;
    procedure TestForgetSecretsMakesSealMethodsRefuse;
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
  CheckTrue(TEchConfigList.TrySelect(LConfigs, Crypto, LChosen, ASuite),
    'the vector config is usable');
  Result := LChosen;
end;

function TTestEchClient.Entry(AType: UInt16; const AData: TBytes): TExtensionEntry;
begin
  Result := TExtensionEntry.Create(AType, AData);
end;

function TTestEchClient.Vec(
  const AEntries: array of TExtensionEntry): TExtensionVector;
var
  LI: Int32;
begin
  Result := TExtensionVector.Empty;
  for LI := 0 to System.High(AEntries) do
    Result.Append(AEntries[LI]);
end;

function TTestEchClient.ServerNameEntry(const AHost: string): TExtensionEntry;
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

function TTestEchClient.InnerBody(const AEntries: TExtensionVector): TBytes;
var
  LHello: TTlsClientHello;
begin
  LHello := Default(TTlsClientHello);
  LHello.Random := DecodeHex(
    '0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20');
  LHello.LegacySessionId := DecodeHex(
    'a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf');
  LHello.CipherSuites := TArray<UInt16>.Create(TCipherSuites13.Aes128GcmSha256,
    TCipherSuites13.ChaCha20Poly1305Sha256);
  LHello.Extensions := AEntries.Encode;
  Result := THandshakeMessages.EncodeClientHello(LHello);
end;

procedure TTestEchClient.ParseEncodedInner(const AEncoded: TBytes;
  out AEntries: TExtensionVector; out APadding: TBytes);
var
  LReader, LSession, LCipher, LComp: TWireReader;
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
  // extensions vector, followed by the padding
  AEntries := TExtensionVector.ParseFrom(LReader);
  APadding := LReader.ReadBytes(LReader.Remaining);
end;

procedure TTestEchClient.TestRecipientPublicKeyIsACopy;
var
  LKey: IHpkeRecipientKey;
  LFirst, LSecond: TBytes;
begin
  // the key keeps its public key private: a caller changing the returned array must not alter it
  LKey := Crypto.Hpke.ImportRecipientKey(THpkeKem.DHKEM_X25519_HKDF_SHA256,
    Crypto.Hpke.ImportPrivateKey(THpkeKem.DHKEM_X25519_HKDF_SHA256,
    DecodeHex(FVec.Values['config_private_key'])));
  LFirst := LKey.PublicKey;
  LFirst[0] := Byte(LFirst[0] xor $FF);
  LSecond := LKey.PublicKey;
  CheckTrue(LFirst[0] <> LSecond[0], 'the returned public key is a copy');
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
  LInnerEntries, LOuterEntries, LEncEntries, LReconstructed: TExtensionVector;
  LInner, LEncoded, LEnc, LAad, LPayload, LDecrypted, LPadding: TBytes;
  LSk: ISecretBuffer;
  LOpener: IHpkeOpener;
  LI: Int32;
begin
  LConfig := SelectConfig(LSuite);
  // inner: real SNI + a contiguous run of extensions the outer shares verbatim
  LInnerEntries := Vec([
    ServerNameEntry('secret.internal.example'),
    Entry(TExtensionTypes.SupportedGroups, DecodeHex('00020017')),
    Entry(TExtensionTypes.KeyShare, DecodeHex('0017000401020304')),
    Entry(TExtensionTypes.SupportedVersions, DecodeHex('020304')),
    Entry(TExtensionTypes.RecordSizeLimit, DecodeHex('4001'))]);
  // outer: public_name SNI (differs, not shared) + the same shared extensions in order
  LOuterEntries := Vec([
    ServerNameEntry('cover.example'),
    Entry(TExtensionTypes.SupportedGroups, DecodeHex('00020017')),
    Entry(TExtensionTypes.KeyShare, DecodeHex('0017000401020304')),
    Entry(TExtensionTypes.SupportedVersions, DecodeHex('020304'))]);

  LInner := InnerBody(LInnerEntries);
  LEch := TEchClientHandshake.Create(Crypto, LConfig, LSuite);
  try
    LEncoded := LEch.BuildEncodedInner(LInner, LOuterEntries);
    LEnc := LEch.SetupSeal;
    LAad := DecodeHex('cafebabe00112233445566778899aabbccddeeff');
    LPayload := LEch.Seal(LAad, LEncoded);
  finally
    LEch.Free;
  end;

  // server side: decrypt with the config's real private key + the same HPKE info
  LSk := Crypto.Hpke.ImportPrivateKey(THpkeKem.DHKEM_X25519_HKDF_SHA256,
    DecodeHex(FVec.Values['config_private_key']));
  LOpener := Crypto.Hpke.ImportRecipientKey(LSuite.Kem, LSk)
    .SetupOpener(LSuite, LEnc, LConfig.HpkeInfo);
  LDecrypted := LOpener.Open(LAad, LPayload);
  CheckEqualBytes('decrypted equals the encoded inner', LEncoded, LDecrypted);

  // reconstruct the inner extensions from the decrypted encoded-inner + the outer
  ParseEncodedInner(LDecrypted, LEncEntries, LPadding);
  LReconstructed := TEchOuterExtensions.Reconstruct(LOuterEntries, LEncEntries);
  CheckEquals(LInnerEntries.Count, LReconstructed.Count,
    'reconstructed inner has the original extension count');
  for LI := 0 to LInnerEntries.Count - 1 do
  begin
    CheckEquals(Integer(LInnerEntries.Entries[LI].ExtensionType),
      Integer(LReconstructed.Entries[LI].ExtensionType),
      'reconstructed extension type');
    CheckEqualBytes('reconstructed extension data',
      LInnerEntries.Entries[LI].Data, LReconstructed.Entries[LI].Data);
  end;
end;

procedure TTestEchClient.TestEncodedInnerHasEmptySessionIdAndZeroPadding;
var
  LConfig: TEchConfig;
  LSuite: IHpkeSuite;
  LEch: TEchClientHandshake;
  LEntries, LOuter, LEncEntries: TExtensionVector;
  LEncoded, LPadding: TBytes;
begin
  LConfig := SelectConfig(LSuite);
  LEntries := Vec([ServerNameEntry('secret.example.com'),
    Entry(TExtensionTypes.SupportedGroups, DecodeHex('00020017'))]);
  LOuter := Vec([Entry(TExtensionTypes.SupportedGroups, DecodeHex('00020017'))]);
  LEch := TEchClientHandshake.Create(Crypto, LConfig, LSuite);
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
  LInnerEntries, LOuter, LEncEntries: TExtensionVector;
  LEncoded, LPadding: TBytes;
  LI: Int32;
  LHasOuterExt, LHasInlinedGroups: Boolean;
begin
  LConfig := SelectConfig(LSuite);
  LInnerEntries := Vec([ServerNameEntry('secret.example.com'),
    Entry(TExtensionTypes.SupportedGroups, DecodeHex('00020017')),
    Entry(TExtensionTypes.KeyShare, DecodeHex('0017000401020304'))]);
  LOuter := Vec([
    Entry(TExtensionTypes.SupportedGroups, DecodeHex('00020017')),
    Entry(TExtensionTypes.KeyShare, DecodeHex('0017000401020304'))]);
  LEch := TEchClientHandshake.Create(Crypto, LConfig, LSuite);
  try
    LEncoded := LEch.BuildEncodedInner(InnerBody(LInnerEntries), LOuter);
  finally
    LEch.Free;
  end;
  ParseEncodedInner(LEncoded, LEncEntries, LPadding);
  LHasOuterExt := False;
  LHasInlinedGroups := False;
  for LI := 0 to LEncEntries.Count - 1 do
  begin
    if LEncEntries.Entries[LI].ExtensionType = TExtensionTypes.EchOuterExtensions then
      LHasOuterExt := True;
    if LEncEntries.Entries[LI].ExtensionType = TExtensionTypes.SupportedGroups then
      LHasInlinedGroups := True;
  end;
  CheckTrue(LHasOuterExt, 'an ech_outer_extensions block was produced');
  CheckFalse(LHasInlinedGroups,
    'the shared supported_groups was compressed out, not inlined');
end;

procedure TTestEchClient.TestGreasePlacementDrivesCompression;
const
  GreaseType = UInt16($0A0A); // a GREASE codepoint (RFC 8701): compressible, duplicated in the outer
var
  LConfig: TEchConfig;
  LSuite: IHpkeSuite;
  LInner, LOuter, LEncEntries: TExtensionVector;

  function Encoded(const AInner, AOuter: TExtensionVector): TExtensionVector;
  var
    LH: TEchClientHandshake;
    LBytes, LPad: TBytes;
    LParsed: TExtensionVector;
  begin
    LH := TEchClientHandshake.Create(Crypto, LConfig, LSuite);
    try
      LBytes := LH.BuildEncodedInner(InnerBody(AInner), AOuter);
    finally
      LH.Free;
    end;
    ParseEncodedInner(LBytes, LParsed, LPad);
    Result := LParsed;
  end;

  function Has(const AEntries: TExtensionVector; AType: UInt16): Boolean;
  var
    LI: Int32;
  begin
    Result := False;
    for LI := 0 to AEntries.Count - 1 do
      if AEntries.Entries[LI].ExtensionType = AType then
        Exit(True);
  end;

begin
  LConfig := SelectConfig(LSuite);
  // contiguous placement (what the GREASE injector now produces): GREASE sits with the other
  // compressible extensions, so ech_outer_extensions folds it in and it is not left inline
  LInner := Vec([ServerNameEntry('secret.example.com'),
    Entry(TExtensionTypes.SupportedGroups, DecodeHex('00020017')),
    Entry(TExtensionTypes.KeyShare, DecodeHex('0017000401020304')),
    Entry(GreaseType, nil)]);
  LOuter := Vec([ServerNameEntry('cover.example'),
    Entry(TExtensionTypes.SupportedGroups, DecodeHex('00020017')),
    Entry(TExtensionTypes.KeyShare, DecodeHex('0017000401020304')),
    Entry(GreaseType, nil)]);
  LEncEntries := Encoded(LInner, LOuter);
  CheckTrue(Has(LEncEntries, TExtensionTypes.EchOuterExtensions),
    'an ech_outer_extensions block was produced');
  CheckFalse(Has(LEncEntries, GreaseType),
    'a contiguous GREASE extension is compressed out, not left inline');

  // front placement (the old shape): server_name splits GREASE from the compressible run, so the
  // block covers only groups+key_share and the empty GREASE extension stays inline - the waste avoided
  LInner := Vec([Entry(GreaseType, nil), ServerNameEntry('secret.example.com'),
    Entry(TExtensionTypes.SupportedGroups, DecodeHex('00020017')),
    Entry(TExtensionTypes.KeyShare, DecodeHex('0017000401020304'))]);
  LOuter := Vec([Entry(GreaseType, nil), ServerNameEntry('cover.example'),
    Entry(TExtensionTypes.SupportedGroups, DecodeHex('00020017')),
    Entry(TExtensionTypes.KeyShare, DecodeHex('0017000401020304'))]);
  LEncEntries := Encoded(LInner, LOuter);
  CheckTrue(Has(LEncEntries, TExtensionTypes.EchOuterExtensions),
    'the groups+key_share run still compresses');
  CheckTrue(Has(LEncEntries, GreaseType),
    'a front-placed GREASE extension is left inline, non-contiguous with the run');
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
    Crypto.Primitives.CreateHkdf(THashAlgorithm.SHA_256), LInnerRandom,
    LTranscript, LGood), 'a matching confirmation is accepted');
  LBad := DecodeHex(
    '0000000000000000000000000000000000000000000000000000000000000000');
  CheckFalse(TEchClientHandshake.AcceptConfirmationMatches(
    Crypto.Primitives.CreateHkdf(THashAlgorithm.SHA_256), LInnerRandom,
    LTranscript, LBad), 'a non-matching confirmation is rejected');
end;

procedure TTestEchClient.TestGreaseEncapsulationIsValid;
type
  TKemCase = record
    Kem: UInt16;
    Size: Int32;
    Name: string;
  end;
const
  LCases: array [0 .. 3] of TKemCase = (
    (Kem: THpkeKem.DHKEM_P256_HKDF_SHA256; Size: 65; Name: 'P-256'),
    (Kem: THpkeKem.DHKEM_P384_HKDF_SHA384; Size: 97; Name: 'P-384'),
    (Kem: THpkeKem.DHKEM_P521_HKDF_SHA512; Size: 133; Name: 'P-521'),
    (Kem: THpkeKem.DHKEM_X25519_HKDF_SHA256; Size: 32; Name: 'X25519'));
var
  LEnc: TBytes;
  LI: Int32;
begin
  // a GREASE ech's enc is a well-formed KEM value (RFC 9849 sec. 6.2): a serialized ephemeral
  // public key of the DH-KEM's Npk
  for LI := 0 to System.High(LCases) do
  begin
    LEnc := Crypto.Hpke.RandomEncapsulation(LCases[LI].Kem);
    CheckEquals(LCases[LI].Size, System.Length(LEnc),
      LCases[LI].Name + ': encapsulation size is Npk');
    CheckTrue(Crypto.Hpke.ValidatePublicKey(LCases[LI].Kem, LEnc),
      LCases[LI].Name + ': a well-formed KEM value');
  end;
end;

procedure TTestEchClient.TestForgetSecretsMakesSealMethodsRefuse;
var
  LConfig: TEchConfig;
  LSuite: IHpkeSuite;
  LEch: TEchClientHandshake;
  LRefused: Boolean;
begin
  LConfig := SelectConfig(LSuite);
  LEch := TEchClientHandshake.Create(Crypto, LConfig, LSuite);
  try
    LEch.ForgetSecrets;
    // the object is spent: every seal method refuses (a typed error) rather than resurrecting the
    // sealer or dereferencing the released one
    LRefused := False;
    try
      LEch.SetupSeal;
    except
      on E: EInvalidOperationTlsLibException do
        LRefused := True;
    end;
    CheckTrue(LRefused, 'SetupSeal refuses after ForgetSecrets');

    LRefused := False;
    try
      LEch.Seal(nil, nil);
    except
      on E: EInvalidOperationTlsLibException do
        LRefused := True;
    end;
    CheckTrue(LRefused, 'Seal refuses after ForgetSecrets');

    LRefused := False;
    try
      LEch.BuildEncodedInner(nil, Vec([]));
    except
      on E: EInvalidOperationTlsLibException do
        LRefused := True;
    end;
    CheckTrue(LRefused, 'BuildEncodedInner refuses after ForgetSecrets');

    // forgetting again is a harmless no-op (does not raise)
    LEch.ForgetSecrets;
    CheckTrue(True, 'ForgetSecrets is idempotent');
  finally
    LEch.Free;
  end;
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestEchClient);
{$ELSE}
  RegisterTest(TTestEchClient.Suite);
{$ENDIF FPC}

end.
