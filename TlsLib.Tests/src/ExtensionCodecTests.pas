{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ExtensionCodecTests;

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
  TlpTlsLibExceptions,
  TlpTlsAlert,
  TlpTlsVersion,
  TlpNegotiationTypes,
  TlpWireReader,
  TlpExtensionContext,
  TlpITlsExtension,
  TlpExtensionBlockCodec,
  TlpCoreExtensions,
  TlsLibTestBase;

type
  TTestExtensionCodec = class(TTlsLibAlgorithmTestCase)
  private
    FCodec: IExtensionBlockCodec;
    function NewContext: TExtensionContext;
    procedure CheckU16(const AName: string; const AExpected, AActual: TArray<UInt16>);
    function ConsumeRaisesUnsupported(AKind: TTlsExtensionContextKind;
      const ABlock: TBytes; AOfferedType: Int32): Boolean;
    function ConsumeRaisesDecodeError(AKind: TTlsExtensionContextKind;
      const ABlock: TBytes): Boolean;
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestClientHelloCoreRoundTrip;
    procedure TestServerHelloSelectionsRoundTrip;
    procedure TestEncryptedExtensionsAlpnRoundTrip;
    procedure TestDuplicateExtensionIsIllegalParameter;
    procedure TestWrongContextIsUnsupportedExtension;
    procedure TestUnsolicitedServerExtensionAborts;
    procedure TestUnknownExtensionSkippedAndGreaseTolerated;
    procedure TestOmittedExtensionsBlockToleratedAsEmpty;
    procedure TestOmittedEncryptedExtensionsBlockIsDecodeError;
    procedure TestEmptyCertificateAuthoritiesIsDecodeError;
    procedure TestUnknownExtensionInCertificateRequestTolerated;
    procedure TestServerNameEmptyHostIsDecodeError;
    procedure TestServerNameUnknownTypeIsDecodeError;
    procedure TestAlpnZeroLengthProtocolIsDecodeError;
    procedure TestAlpnEmptyListIsDecodeError;
    procedure TestDuplicateKeyShareGroupRejected;
    procedure TestClientHelloEmptyKeyExchangeIsDecodeError;
    procedure TestServerHelloEmptyKeyExchangeIsDecodeError;
    procedure TestPskAndEarlyDataClientHelloRoundTrip;
    procedure TestPreSharedKeyServerSelectionRoundTrip;
    procedure TestEarlyDataAcceptInEncryptedExtensionsRoundTrip;
    procedure TestEarlyDataMaxSizeInNewSessionTicketRoundTrip;
    procedure TestPreSharedKeyIsLastClientHelloExtension;
  end;

implementation

{ TTestExtensionCodec }

procedure TTestExtensionCodec.SetUp;
begin
  inherited SetUp;
  FCodec := TExtensionBlockCodec.Create(TCoreExtensions.CreateDefaultRegistry)
    as IExtensionBlockCodec;
end;

procedure TTestExtensionCodec.TearDown;
begin
  inherited TearDown;
end;

function TTestExtensionCodec.NewContext: TExtensionContext;
begin
  Result := TExtensionContext.Create;
end;

procedure TTestExtensionCodec.CheckU16(const AName: string;
  const AExpected, AActual: TArray<UInt16>);
var
  LI: Int32;
begin
  CheckEquals(System.Length(AExpected), System.Length(AActual), AName + ' count');
  for LI := 0 to High(AExpected) do
    CheckEquals(AExpected[LI], AActual[LI], AName + ' element');
end;

function TTestExtensionCodec.ConsumeRaisesUnsupported(
  AKind: TTlsExtensionContextKind; const ABlock: TBytes;
  AOfferedType: Int32): Boolean;
var
  LCtx: TExtensionContext;
begin
  Result := False;
  LCtx := NewContext;
  try
    if AOfferedType >= 0 then
      LCtx.MarkOffered(UInt16(AOfferedType));
    try
      FCodec.ConsumeBlock(LCtx, AKind, ABlock);
    except
      on E: EFatalAlertTlsLibException do
        Result := True;
    end;
  finally
    LCtx.Free;
  end;
end;

procedure TTestExtensionCodec.TestClientHelloCoreRoundTrip;
var
  LSrc, LDst: TExtensionContext;
  LBlock: TBytes;
begin
  LSrc := NewContext;
  LDst := NewContext;
  try
    LSrc.SupportedVersions := TArray<UInt16>.Create(TlsWireVersionTls13);
    LSrc.SupportedGroups := TArray<UInt16>.Create(TNamedGroupCatalog.X25519,
      TNamedGroupCatalog.Secp256r1);
    LSrc.SignatureSchemes := TArray<UInt16>.Create(TSignatureSchemes.EcdsaSecp256r1Sha256,
      TSignatureSchemes.RsaPssRsaeSha256);
    LSrc.SignatureSchemesCert := TArray<UInt16>.Create(TSignatureSchemes.RsaPkcs1Sha256);
    LSrc.ServerName := 'example.com';
    LSrc.AlpnProtocols := TArray<string>.Create('h2', 'http/1.1');
    SetLength(LSrc.ClientKeyShares, 1);
    LSrc.ClientKeyShares[0].Group := TNamedGroupCatalog.X25519;
    LSrc.ClientKeyShares[0].KeyExchange :=
      DecodeHex('99381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c');

    LBlock := FCodec.ProduceBlock(LSrc, TTlsExtensionContextKind.ClientHello);
    FCodec.ConsumeBlock(LDst, TTlsExtensionContextKind.ClientHello, LBlock);

    CheckU16('supported_versions', LSrc.SupportedVersions, LDst.SupportedVersions);
    CheckU16('supported_groups', LSrc.SupportedGroups, LDst.SupportedGroups);
    CheckU16('signature_algorithms', LSrc.SignatureSchemes, LDst.SignatureSchemes);
    CheckU16('signature_algorithms_cert', LSrc.SignatureSchemesCert,
      LDst.SignatureSchemesCert);
    CheckEquals('example.com', LDst.ServerName, 'server_name');
    CheckEquals(2, System.Length(LDst.AlpnProtocols), 'alpn count');
    CheckEquals('h2', LDst.AlpnProtocols[0], 'alpn[0]');
    CheckEquals('http/1.1', LDst.AlpnProtocols[1], 'alpn[1]');
    CheckEquals(1, System.Length(LDst.ClientKeyShares), 'key_share count');
    CheckEquals(TNamedGroupCatalog.X25519, LDst.ClientKeyShares[0].Group, 'key_share group');
    CheckEqualBytes('key_share bytes', LSrc.ClientKeyShares[0].KeyExchange,
      LDst.ClientKeyShares[0].KeyExchange);
  finally
    LSrc.Free;
    LDst.Free;
  end;
end;

procedure TTestExtensionCodec.TestServerHelloSelectionsRoundTrip;
var
  LSrc, LDst: TExtensionContext;
  LBlock: TBytes;
begin
  LSrc := NewContext;
  LDst := NewContext;
  try
    LSrc.SelectedVersion := TlsWireVersionTls13;
    LSrc.SelectedKeyShare.Group := TNamedGroupCatalog.X25519;
    LSrc.SelectedKeyShare.KeyExchange :=
      DecodeHex('c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f');
    LBlock := FCodec.ProduceBlock(LSrc, TTlsExtensionContextKind.ServerHello);

    // the client only accepts responses it offered
    LDst.MarkOffered($002B);
    LDst.MarkOffered($0033);
    FCodec.ConsumeBlock(LDst, TTlsExtensionContextKind.ServerHello, LBlock);

    CheckEquals(TlsWireVersionTls13, LDst.SelectedVersion, 'selected_version');
    CheckEquals(TNamedGroupCatalog.X25519, LDst.SelectedKeyShare.Group, 'selected group');
    CheckEqualBytes('selected key_share bytes', LSrc.SelectedKeyShare.KeyExchange,
      LDst.SelectedKeyShare.KeyExchange);
  finally
    LSrc.Free;
    LDst.Free;
  end;
end;

procedure TTestExtensionCodec.TestEncryptedExtensionsAlpnRoundTrip;
var
  LSrc, LDst: TExtensionContext;
  LBlock: TBytes;
begin
  LSrc := NewContext;
  LDst := NewContext;
  try
    LSrc.SelectedAlpn := 'h2';
    LBlock := FCodec.ProduceBlock(LSrc, TTlsExtensionContextKind.EncryptedExtensions);
    LDst.MarkOffered($0010);
    FCodec.ConsumeBlock(LDst, TTlsExtensionContextKind.EncryptedExtensions, LBlock);
    CheckEquals('h2', LDst.SelectedAlpn, 'selected ALPN');
  finally
    LSrc.Free;
    LDst.Free;
  end;
end;

procedure TTestExtensionCodec.TestDuplicateExtensionIsIllegalParameter;
var
  LCtx: TExtensionContext;
  LAlert: TTlsAlertDescription;
  LRaised: Boolean;
begin
  // two supported_versions entries in one ClientHello block: a repeated type is rejected with
  // illegal_parameter, caught structurally before any semantic rule
  LCtx := NewContext;
  LRaised := False;
  LAlert := TTlsAlertDescription.CloseNotify;
  try
    try
      FCodec.ConsumeBlock(LCtx, TTlsExtensionContextKind.ClientHello,
        DecodeHex('000e002b0003020304002b0003020304'));
    except
      on E: EFatalAlertTlsLibException do
      begin
        LRaised := True;
        LAlert := E.AlertDescription;
      end;
    end;
  finally
    LCtx.Free;
  end;
  CheckTrue(LRaised, 'a duplicate extension raises a fatal alert');
  CheckEquals(Integer(TTlsAlertDescription.IllegalParameter), Integer(LAlert),
    'a duplicate extension is an illegal_parameter');
end;

procedure TTestExtensionCodec.TestOmittedExtensionsBlockToleratedAsEmpty;
var
  LCtx: TExtensionContext;
begin
  // a TLS 1.2 ServerHello may end after compression_method, leaving the extensions field
  // entirely absent (an empty block, distinct from a present-but-empty extensions<0..>
  // vector) - it must decode as no extensions rather than raising decode_error
  LCtx := NewContext;
  try
    FCodec.ConsumeBlock(LCtx, TTlsExtensionContextKind.ServerHello, nil);
    CheckFalse(LCtx.WasOffered(TExtensionTypes.SupportedVersions),
      'an omitted extensions field carries no extensions');
  finally
    LCtx.Free;
  end;
end;

procedure TTestExtensionCodec.TestOmittedEncryptedExtensionsBlockIsDecodeError;
begin
  // unlike a TLS 1.2 ServerHello, an EncryptedExtensions message carries a mandatory
  // extensions<0..> vector (RFC 8446 4.3.1); a message body with no bytes at all omits it
  // and must decode_error, not be tolerated as an empty offer
  CheckTrue(ConsumeRaisesDecodeError(
    TTlsExtensionContextKind.EncryptedExtensions, nil),
    'an omitted EncryptedExtensions extensions vector is a decode_error');
end;

procedure TTestExtensionCodec.TestEmptyCertificateAuthoritiesIsDecodeError;
begin
  // a CertificateRequest certificate_authorities extension (type 0x002F) with an empty
  // authorities vector violates the <3..2^16-1> minimum (RFC 8446 4.2.4) -> decode_error.
  // Block: outer(0006) + type(002F) + ext_len(0002) + authorities_len(0000)
  CheckTrue(ConsumeRaisesDecodeError(TTlsExtensionContextKind.CertificateRequest,
    DecodeHex('0006002F00020000')),
    'an empty certificate_authorities list is a decode_error');
end;

procedure TTestExtensionCodec.TestUnknownExtensionInCertificateRequestTolerated;
var
  LCtx: TExtensionContext;
begin
  // a CertificateRequest carries the server's own constraints, not responses to client
  // offers (RFC 8446 4.3.2), so an unknown extension is ignored, not rejected as unsolicited.
  // Block: outer(0006) + unknown type(1234) + ext_len(0002) + body(ABCD)
  LCtx := NewContext;
  try
    FCodec.ConsumeBlock(LCtx, TTlsExtensionContextKind.CertificateRequest,
      DecodeHex('000612340002ABCD'));
    Check(True, 'an unknown extension in a CertificateRequest is tolerated');
  finally
    LCtx.Free;
  end;
end;

function TTestExtensionCodec.ConsumeRaisesDecodeError(
  AKind: TTlsExtensionContextKind; const ABlock: TBytes): Boolean;
var
  LCtx: TExtensionContext;
begin
  Result := False;
  LCtx := NewContext;
  try
    try
      FCodec.ConsumeBlock(LCtx, AKind, ABlock);
    except
      on E: EDecodeErrorTlsLibException do
        Result := True;
    end;
  finally
    LCtx.Free;
  end;
end;

procedure TTestExtensionCodec.TestServerNameEmptyHostIsDecodeError;
begin
  // server_name list = one host_name entry with a zero-length name
  CheckTrue(ConsumeRaisesDecodeError(TTlsExtensionContextKind.ClientHello,
    DecodeHex('0009000000050003000000')),
    'an empty server_name host is a decode_error');
end;

procedure TTestExtensionCodec.TestServerNameUnknownTypeIsDecodeError;
begin
  // server_name list = one entry with name_type 0x01 (only host_name is defined)
  CheckTrue(ConsumeRaisesDecodeError(TTlsExtensionContextKind.ClientHello,
    DecodeHex('000c000000080006010003616263')),
    'an unknown server_name name_type is a decode_error');
end;

procedure TTestExtensionCodec.TestAlpnZeroLengthProtocolIsDecodeError;
begin
  // an ALPN list carrying one zero-length protocol name
  CheckTrue(ConsumeRaisesDecodeError(TTlsExtensionContextKind.ClientHello,
    DecodeHex('000700100003000100')),
    'a zero-length ALPN protocol is a decode_error');
end;

procedure TTestExtensionCodec.TestAlpnEmptyListIsDecodeError;
begin
  // an ALPN protocol_name_list with no protocols
  CheckTrue(ConsumeRaisesDecodeError(TTlsExtensionContextKind.ClientHello,
    DecodeHex('0006001000020000')),
    'an empty ALPN protocol list is a decode_error');
end;

procedure TTestExtensionCodec.TestWrongContextIsUnsupportedExtension;
begin
  // supported_versions (allowed in CH/SH/HRR) appearing in EncryptedExtensions,
  // offered so it clears the unsolicited check and reaches the context check
  CheckTrue(ConsumeRaisesUnsupported(TTlsExtensionContextKind.EncryptedExtensions,
    DecodeHex('0006002b00020304'), $002B),
    'an extension in the wrong message is unsupported_extension');
end;

procedure TTestExtensionCodec.TestUnsolicitedServerExtensionAborts;
begin
  // a ServerHello supported_versions the client never offered
  CheckTrue(ConsumeRaisesUnsupported(TTlsExtensionContextKind.ServerHello,
    DecodeHex('0006002b00020304'), -1),
    'an unsolicited response extension aborts');
end;

procedure TTestExtensionCodec.TestUnknownExtensionSkippedAndGreaseTolerated;
var
  LCtx: TExtensionContext;
begin
  // a GREASE (0x0a0a) unknown extension followed by supported_groups in a ClientHello
  LCtx := NewContext;
  try
    FCodec.ConsumeBlock(LCtx, TTlsExtensionContextKind.ClientHello,
      DecodeHex('000c0a0a0000000a00040002001d'));
    CheckU16('groups parsed past the skipped GREASE',
      TArray<UInt16>.Create(TNamedGroupCatalog.X25519), LCtx.SupportedGroups);
  finally
    LCtx.Free;
  end;
end;

procedure TTestExtensionCodec.TestClientHelloEmptyKeyExchangeIsDecodeError;
begin
  // client key_share: group 0x001D with a zero-length key_exchange
  // (outer 000A | ext 0033 len 0006 | shares 0004 | group 001D | key_exchange 0000)
  CheckTrue(ConsumeRaisesDecodeError(TTlsExtensionContextKind.ClientHello,
    DecodeHex('000A003300060004001D0000')),
    'an empty client key_exchange is a decode_error (RFC 8446 4.2.8)');
end;

procedure TTestExtensionCodec.TestServerHelloEmptyKeyExchangeIsDecodeError;
var
  LCtx: TExtensionContext;
  LRaised: Boolean;
begin
  LCtx := NewContext;
  try
    // mark key_share offered so it is not rejected as unsolicited before the empty check
    LCtx.MarkOffered($0033);
    LRaised := False;
    try
      // server key_share: group 0x001D with a zero-length key_exchange
      FCodec.ConsumeBlock(LCtx, TTlsExtensionContextKind.ServerHello,
        DecodeHex('000800330004001D0000'));
    except
      on E: EDecodeErrorTlsLibException do
        LRaised := True;
    end;
    CheckTrue(LRaised, 'an empty server key_exchange is a decode_error (RFC 8446 4.2.8)');
  finally
    LCtx.Free;
  end;
end;

procedure TTestExtensionCodec.TestDuplicateKeyShareGroupRejected;
var
  LSrc, LDst: TExtensionContext;
  LBlock: TBytes;
  LRaised: Boolean;
begin
  LSrc := NewContext;
  LDst := NewContext;
  try
    // two key_share entries for the same group (RFC 8446 4.2.8 forbids this)
    SetLength(LSrc.ClientKeyShares, 2);
    LSrc.ClientKeyShares[0].Group := TNamedGroupCatalog.X25519;
    LSrc.ClientKeyShares[0].KeyExchange :=
      DecodeHex('99381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c');
    LSrc.ClientKeyShares[1].Group := TNamedGroupCatalog.X25519;
    LSrc.ClientKeyShares[1].KeyExchange :=
      DecodeHex('0000000000000000000000000000000000000000000000000000000000000000');
    LBlock := FCodec.ProduceBlock(LSrc, TTlsExtensionContextKind.ClientHello);
    LRaised := False;
    try
      FCodec.ConsumeBlock(LDst, TTlsExtensionContextKind.ClientHello, LBlock);
    except
      on E: EPeerInputTlsLibException do
        LRaised := True;
    end;
    CheckTrue(LRaised, 'a duplicate key_share group is rejected as illegal_parameter');
  finally
    LSrc.Free;
    LDst.Free;
  end;
end;

procedure TTestExtensionCodec.TestPskAndEarlyDataClientHelloRoundTrip;
var
  LSrc, LDst: TExtensionContext;
  LBlock, LBinder: TBytes;
begin
  LSrc := NewContext;
  LDst := NewContext;
  try
    LSrc.SupportedVersions := TArray<UInt16>.Create(TlsWireVersionTls13);
    LSrc.PskModes := TBytes.Create(Byte(1)); // psk_dhe_ke
    LSrc.EarlyDataOffered := True;
    SetLength(LSrc.OfferedPskIdentities, 1);
    LSrc.OfferedPskIdentities[0] := DecodeHex('DEADBEEFCAFE');
    SetLength(LSrc.OfferedPskAges, 1);
    LSrc.OfferedPskAges[0] := UInt32($12345678);
    LBinder := nil;
    SetLength(LBinder, 32); // a zero placeholder, as the client would emit pre-patch
    SetLength(LSrc.OfferedPskBinders, 1);
    LSrc.OfferedPskBinders[0] := LBinder;

    LBlock := FCodec.ProduceBlock(LSrc, TTlsExtensionContextKind.ClientHello);
    FCodec.ConsumeBlock(LDst, TTlsExtensionContextKind.ClientHello, LBlock);

    CheckEquals(1, System.Length(LDst.PskModes), 'psk mode count');
    CheckEquals(1, LDst.PskModes[0], 'psk_dhe_ke offered');
    CheckTrue(LDst.EarlyDataOffered, 'early_data offered');
    CheckEquals(1, System.Length(LDst.OfferedPskIdentities), 'identity count');
    CheckEqualBytes('identity round-trips', DecodeHex('DEADBEEFCAFE'),
      LDst.OfferedPskIdentities[0]);
    CheckEquals(Int64($12345678), Int64(LDst.OfferedPskAges[0]), 'obfuscated age');
    CheckEquals(32, System.Length(LDst.OfferedPskBinders[0]), 'binder length');
  finally
    LSrc.Free;
    LDst.Free;
  end;
end;

procedure TTestExtensionCodec.TestPreSharedKeyServerSelectionRoundTrip;
var
  LSrc, LDst: TExtensionContext;
  LBlock: TBytes;
begin
  LSrc := NewContext;
  LDst := NewContext;
  try
    LSrc.PskSelected := True;
    LSrc.SelectedPskIdentity := 0;
    LBlock := FCodec.ProduceBlock(LSrc, TTlsExtensionContextKind.ServerHello);
    LDst.MarkOffered(TExtensionTypes.PreSharedKey);
    FCodec.ConsumeBlock(LDst, TTlsExtensionContextKind.ServerHello, LBlock);
    CheckTrue(LDst.PskSelected, 'the server selected a PSK');
    CheckEquals(0, LDst.SelectedPskIdentity, 'the selected identity index');
  finally
    LSrc.Free;
    LDst.Free;
  end;
end;

procedure TTestExtensionCodec.TestEarlyDataAcceptInEncryptedExtensionsRoundTrip;
var
  LSrc, LDst: TExtensionContext;
  LBlock: TBytes;
begin
  LSrc := NewContext;
  LDst := NewContext;
  try
    LSrc.EarlyDataAccepted := True;
    LBlock := FCodec.ProduceBlock(LSrc, TTlsExtensionContextKind.EncryptedExtensions);
    LDst.MarkOffered(TExtensionTypes.EarlyData);
    FCodec.ConsumeBlock(LDst, TTlsExtensionContextKind.EncryptedExtensions, LBlock);
    CheckTrue(LDst.EarlyDataAccepted, 'early_data acceptance round-trips');
  finally
    LSrc.Free;
    LDst.Free;
  end;
end;

procedure TTestExtensionCodec.TestEarlyDataMaxSizeInNewSessionTicketRoundTrip;
var
  LSrc, LDst: TExtensionContext;
  LBlock: TBytes;
begin
  LSrc := NewContext;
  LDst := NewContext;
  try
    LSrc.EarlyDataMaxSize := UInt32(16384);
    LBlock := FCodec.ProduceBlock(LSrc, TTlsExtensionContextKind.NewSessionTicket);
    // NewSessionTicket is server-originated: its early_data needs no prior offer
    FCodec.ConsumeBlock(LDst, TTlsExtensionContextKind.NewSessionTicket, LBlock);
    CheckEquals(Int64(16384), Int64(LDst.EarlyDataMaxSize), 'max_early_data round-trips');
  finally
    LSrc.Free;
    LDst.Free;
  end;
end;

procedure TTestExtensionCodec.TestPreSharedKeyIsLastClientHelloExtension;
var
  LSrc: TExtensionContext;
  LBlock: TBytes;
  LReader, LEntries, LData: TWireReader;
  LLastType: UInt16;
begin
  LSrc := NewContext;
  try
    LSrc.SupportedVersions := TArray<UInt16>.Create(TlsWireVersionTls13);
    LSrc.SupportedGroups := TArray<UInt16>.Create(TNamedGroupCatalog.X25519);
    LSrc.PskModes := TBytes.Create(Byte(1));
    SetLength(LSrc.OfferedPskIdentities, 1);
    LSrc.OfferedPskIdentities[0] := DecodeHex('AABBCC');
    SetLength(LSrc.OfferedPskAges, 1);
    LSrc.OfferedPskAges[0] := 0;
    SetLength(LSrc.OfferedPskBinders, 1);
    SetLength(LSrc.OfferedPskBinders[0], 32);
    LBlock := FCodec.ProduceBlock(LSrc, TTlsExtensionContextKind.ClientHello);
    LReader := TWireReader.Create(LBlock);
    LEntries := LReader.OpenVector(2);
    LLastType := 0;
    while not LEntries.EndReached do
    begin
      LLastType := LEntries.ReadUInt16;
      LData := LEntries.OpenVector(2);
      LData.ReadBytes(LData.Remaining);
    end;
    CheckEquals(Int64(TExtensionTypes.PreSharedKey), Int64(LLastType),
      'pre_shared_key is the last ClientHello extension');
  finally
    LSrc.Free;
  end;
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestExtensionCodec);
{$ELSE}
  RegisterTest(TTestExtensionCodec.Suite);
{$ENDIF FPC}

end.
