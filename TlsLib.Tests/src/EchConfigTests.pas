{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit EchConfigTests;

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
  TlpTlsLibExceptions,
  TlpEchConfig,
  TlsLibTestBase;

type
  /// <summary>
  /// The ECHConfig / ECHConfigList codec and client acceptance filter (RFC 9849 sec.
  /// 4, 6.1): round-trips an OpenSSL-generated config, checks the HPKE info string, and
  /// exercises every skip rule (version, KEM, export-only AEAD, public_name,
  /// mandatory/duplicate extension) and the first-match selection.
  /// </summary>
  TTestEchConfig = class(TTlsLibAlgorithmTestCase)
  private
    FVec: TStringList;
    function ConfigList: TBytes;
    function Pk32: TBytes;
    function Ascii(const AText: string): TBytes;
    function OneSuite(AKdf, AAead: UInt16): TArray<TEchCipherSuite>;
    function ConfigWith(AKemId: UInt16; const ASuites: TArray<TEchCipherSuite>;
      const APublicName: string;
      const AExtensions: TArray<TEchConfigExtension>): TEchConfig;
    function Usable(const AConfig: TEchConfig): Boolean;
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestParseRealConfig;
    procedure TestParseEncodeRoundTrip;
    procedure TestHpkeInfoPrefix;
    procedure TestSelectFirstUsableSkipsUnsupportedVersion;
    procedure TestSkipUnsupportedKem;
    procedure TestSkipExportOnlyAead;
    procedure TestSelectSkipsExportOnlyButTakesSecondSuite;
    procedure TestSkipUnknownMandatoryExtension;
    procedure TestOptionalExtensionIsUsable;
    procedure TestSkipDuplicateExtension;
    procedure TestBadPublicNames;
    procedure TestGoodPublicNames;
    procedure TestMalformedListRaises;
    procedure TestEmptyListRaises;
    procedure TestLargeConfigListParses;
  end;

implementation

{ TTestEchConfig }

procedure TTestEchConfig.SetUp;
begin
  inherited SetUp;
  FVec := LoadVectorFields('Certs/Ech.txt');
end;

procedure TTestEchConfig.TearDown;
begin
  FVec.Free;
  inherited TearDown;
end;

function TTestEchConfig.ConfigList: TBytes;
begin
  Result := DecodeHex(FVec.Values['config_list']);
end;

function TTestEchConfig.Pk32: TBytes;
var
  LI: Int32;
begin
  SetLength(Result, 32);
  for LI := 0 to 31 do
    Result[LI] := Byte(LI + 1);
end;

function TTestEchConfig.Ascii(const AText: string): TBytes;
var
  LI: Int32;
begin
  SetLength(Result, System.Length(AText));
  for LI := 1 to System.Length(AText) do
    Result[LI - 1] := Byte(Ord(AText[LI]));
end;

function TTestEchConfig.OneSuite(AKdf, AAead: UInt16): TArray<TEchCipherSuite>;
begin
  SetLength(Result, 1);
  Result[0].KdfId := AKdf;
  Result[0].AeadId := AAead;
end;

function TTestEchConfig.ConfigWith(AKemId: UInt16;
  const ASuites: TArray<TEchCipherSuite>; const APublicName: string;
  const AExtensions: TArray<TEchConfigExtension>): TEchConfig;
begin
  Result := TEchConfig.Build(TEchConfig.SupportedVersion, $01, AKemId, Pk32,
    ASuites, 0, Ascii(APublicName), AExtensions);
end;

function TTestEchConfig.Usable(const AConfig: TEchConfig): Boolean;
begin
  Result := AConfig.IsUsable(Provider);
end;

procedure TTestEchConfig.TestParseRealConfig;
var
  LConfigs: TArray<TEchConfig>;
begin
  LConfigs := TEchConfigList.Parse(ConfigList);
  CheckEquals(1, System.Length(LConfigs), 'one config in the list');
  CheckEquals(Integer(TEchConfig.SupportedVersion), Integer(LConfigs[0].Version),
    'version 0xfe0d');
  CheckEquals($D4, LConfigs[0].ConfigId, 'config_id');
  CheckEquals(Integer(THpkeKem.DHKEM_X25519_HKDF_SHA256), Integer(LConfigs[0].KemId),
    'KEM X25519');
  CheckEquals(32, System.Length(LConfigs[0].PublicKey), 'a 32-byte X25519 key');
  CheckEquals(1, System.Length(LConfigs[0].CipherSuites), 'one cipher suite');
  CheckEquals(Integer(THpkeKdf.HKDF_SHA256),
    Integer(LConfigs[0].CipherSuites[0].KdfId), 'kdf HKDF-SHA256');
  CheckEquals(Integer(THpkeAead.AES_128_GCM),
    Integer(LConfigs[0].CipherSuites[0].AeadId), 'aead AES-128-GCM');
  CheckEquals('cover.example', LConfigs[0].PublicName, 'public_name');
  CheckEquals(0, System.Length(LConfigs[0].Extensions), 'no extensions');
  CheckTrue(Usable(LConfigs[0]), 'the real config is usable');
end;

procedure TTestEchConfig.TestParseEncodeRoundTrip;
var
  LConfigs: TArray<TEchConfig>;
begin
  // encoding the parsed list reproduces the exact OpenSSL wire bytes
  LConfigs := TEchConfigList.Parse(ConfigList);
  CheckEqualBytes('config list round-trip', ConfigList,
    TEchConfigList.Encode(LConfigs));
end;

procedure TTestEchConfig.TestHpkeInfoPrefix;
var
  LConfigs: TArray<TEchConfig>;
  LInfo, LExpectedPrefix: TBytes;
  LI: Int32;
begin
  LConfigs := TEchConfigList.Parse(ConfigList);
  LInfo := LConfigs[0].HpkeInfo;
  // "tls ech" || 0x00 || ECHConfig
  LExpectedPrefix := TBytes.Create($74, $6C, $73, $20, $65, $63, $68, $00);
  CheckTrue(System.Length(LInfo) = System.Length(LExpectedPrefix) +
    System.Length(LConfigs[0].Raw), 'info length');
  for LI := 0 to System.High(LExpectedPrefix) do
    CheckEquals(LExpectedPrefix[LI], LInfo[LI], 'info prefix byte');
  // the trailing bytes are exactly the raw ECHConfig
  for LI := 0 to System.High(LConfigs[0].Raw) do
    CheckEquals(LConfigs[0].Raw[LI], LInfo[System.Length(LExpectedPrefix) + LI],
      'info config byte');
end;

procedure TTestEchConfig.TestSelectFirstUsableSkipsUnsupportedVersion;
var
  LStale, LGood: TEchConfig;
  LList: TArray<TEchConfig>;
  LChosen: TEchConfig;
  LSuite: IHpkeSuite;
begin
  // a config with a version we do not implement is skipped in favour of a later usable one
  LStale := TEchConfig.Build(UInt16($FE0C), $01,
    THpkeKem.DHKEM_X25519_HKDF_SHA256, Pk32,
    OneSuite(THpkeKdf.HKDF_SHA256, THpkeAead.AES_128_GCM), 0,
    Ascii('cover.example'), nil);
  LGood := ConfigWith(THpkeKem.DHKEM_X25519_HKDF_SHA256,
    OneSuite(THpkeKdf.HKDF_SHA256, THpkeAead.AES_128_GCM), 'cover.example', nil);
  LList := TArray<TEchConfig>.Create(LStale, LGood);
  CheckTrue(TEchConfigList.TrySelect(LList, Provider, LChosen, LSuite),
    'a usable config is selected');
  CheckEquals(Integer(TEchConfig.SupportedVersion), Integer(LChosen.Version),
    'the supported-version config was chosen');
  CheckTrue((LSuite.Kem = THpkeKem.DHKEM_X25519_HKDF_SHA256) and
    (LSuite.Kdf = THpkeKdf.HKDF_SHA256) and (LSuite.Aead = THpkeAead.AES_128_GCM),
    'the joined suite');
end;

procedure TTestEchConfig.TestSkipUnsupportedKem;
begin
  CheckFalse(Usable(ConfigWith(UInt16($0009),
    OneSuite(THpkeKdf.HKDF_SHA256, THpkeAead.AES_128_GCM), 'cover.example', nil)),
    'an unsupported KEM is not usable');
end;

procedure TTestEchConfig.TestSkipExportOnlyAead;
begin
  CheckFalse(Usable(ConfigWith(THpkeKem.DHKEM_X25519_HKDF_SHA256,
    OneSuite(THpkeKdf.HKDF_SHA256, THpkeAead.EXPORT_ONLY), 'cover.example', nil)),
    'an export-only AEAD is not usable');
end;

procedure TTestEchConfig.TestSelectSkipsExportOnlyButTakesSecondSuite;
var
  LSuites: TArray<TEchCipherSuite>;
  LConfig: TEchConfig;
  LSuite: IHpkeSuite;
begin
  // first advertised suite is export-only (unusable), the second is real
  SetLength(LSuites, 2);
  LSuites[0].KdfId := THpkeKdf.HKDF_SHA256;
  LSuites[0].AeadId := THpkeAead.EXPORT_ONLY;
  LSuites[1].KdfId := THpkeKdf.HKDF_SHA256;
  LSuites[1].AeadId := THpkeAead.AES_128_GCM;
  LConfig := ConfigWith(THpkeKem.DHKEM_X25519_HKDF_SHA256, LSuites,
    'cover.example', nil);
  CheckTrue(LConfig.TrySelectSuite(Provider, LSuite), 'a supported suite exists');
  CheckEquals(Integer(THpkeAead.AES_128_GCM), Integer(LSuite.Aead),
    'the real AEAD was selected, not export-only');
end;

procedure TTestEchConfig.TestSkipUnknownMandatoryExtension;
var
  LExts: TArray<TEchConfigExtension>;
begin
  SetLength(LExts, 1);
  LExts[0].ExtType := UInt16($8001); // high bit set = mandatory, and unknown
  LExts[0].Data := nil;
  CheckFalse(Usable(ConfigWith(THpkeKem.DHKEM_X25519_HKDF_SHA256,
    OneSuite(THpkeKdf.HKDF_SHA256, THpkeAead.AES_128_GCM), 'cover.example', LExts)),
    'an unsupported mandatory extension makes the config unusable');
end;

procedure TTestEchConfig.TestOptionalExtensionIsUsable;
var
  LExts: TArray<TEchConfigExtension>;
begin
  SetLength(LExts, 1);
  LExts[0].ExtType := UInt16($0001); // high bit clear = optional, safely ignored
  LExts[0].Data := TBytes.Create(9, 9);
  CheckTrue(Usable(ConfigWith(THpkeKem.DHKEM_X25519_HKDF_SHA256,
    OneSuite(THpkeKdf.HKDF_SHA256, THpkeAead.AES_128_GCM), 'cover.example', LExts)),
    'an unknown optional extension is ignored, config still usable');
end;

procedure TTestEchConfig.TestSkipDuplicateExtension;
var
  LExts: TArray<TEchConfigExtension>;
begin
  SetLength(LExts, 2);
  LExts[0].ExtType := UInt16($0001);
  LExts[1].ExtType := UInt16($0001);
  CheckFalse(Usable(ConfigWith(THpkeKem.DHKEM_X25519_HKDF_SHA256,
    OneSuite(THpkeKdf.HKDF_SHA256, THpkeAead.AES_128_GCM), 'cover.example', LExts)),
    'a duplicate extension type makes the config unusable');
end;

procedure TTestEchConfig.TestBadPublicNames;
const
  // a label may not begin or end with a hyphen (RFC 5890 LDH labels)
  LNames: array[0..11] of string = ('', '123', '0xABCD', 'a..b', '.leading',
    'trailing.', 'under_score', 'space name', '-abc.example', 'abc-.example',
    'host.-mid.example', 'host.mid-.example');
var
  LI: Int32;
begin
  for LI := 0 to System.High(LNames) do
    CheckFalse(Usable(ConfigWith(THpkeKem.DHKEM_X25519_HKDF_SHA256,
      OneSuite(THpkeKdf.HKDF_SHA256, THpkeAead.AES_128_GCM), LNames[LI], nil)),
      Format('public_name "%s" is invalid', [LNames[LI]]));
end;

procedure TTestEchConfig.TestGoodPublicNames;
const
  LNames: array[0..4] of string = ('cover.example', 'a.b.c', 'xn--abc',
    'host-1.example.net', 'a1b2');
var
  LI: Int32;
begin
  for LI := 0 to System.High(LNames) do
    CheckTrue(Usable(ConfigWith(THpkeKem.DHKEM_X25519_HKDF_SHA256,
      OneSuite(THpkeKdf.HKDF_SHA256, THpkeAead.AES_128_GCM), LNames[LI], nil)),
      Format('public_name "%s" is valid', [LNames[LI]]));
end;

procedure TTestEchConfig.TestMalformedListRaises;
var
  LRaised: Boolean;
begin
  // a list whose declared length overruns the buffer
  LRaised := False;
  try
    TEchConfigList.Parse(DecodeHex('00fe0d'));
  except
    on E: EDecodeErrorTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a malformed ECHConfigList raises a decode error');
end;

procedure TTestEchConfig.TestEmptyListRaises;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    TEchConfigList.Parse(DecodeHex('0000'));
  except
    on E: EDecodeErrorTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'an empty ECHConfigList raises a decode error');
end;

procedure TTestEchConfig.TestLargeConfigListParses;
const
  Count = 500;
var
  LConfigs, LParsed: TArray<TEchConfig>;
  LI: Int32;
begin
  // a large ECHConfigList arrives unauthenticated (server retry_configs); it must parse in linear
  // time and yield exactly its entries - the parser pre-sizes from the remaining length
  SetLength(LConfigs, Count);
  for LI := 0 to Count - 1 do
    LConfigs[LI] := ConfigWith(THpkeKem.DHKEM_X25519_HKDF_SHA256,
      OneSuite(THpkeKdf.HKDF_SHA256, THpkeAead.AES_128_GCM), 'example.com', nil);
  LParsed := TEchConfigList.Parse(TEchConfigList.Encode(LConfigs));
  CheckEquals(Count, System.Length(LParsed), 'every config in a large list is parsed');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestEchConfig);
{$ELSE}
  RegisterTest(TTestEchConfig.Suite);
{$ENDIF FPC}

end.
