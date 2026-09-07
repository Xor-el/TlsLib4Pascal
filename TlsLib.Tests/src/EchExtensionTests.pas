{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit EchExtensionTests;

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
  TlpTlsAlert,
  TlpTlsLibExceptions,
  TlpEchConfig,
  TlpEchExtension,
  TlsLibTestBase;

type
  /// <summary>
  /// The encrypted_client_hello and ech_outer_extensions extension codecs (RFC 9849
  /// sec. 5 / 5.1) plus the fixed EncryptedExtensions (retry_configs) and
  /// HelloRetryRequest (8-byte confirmation) forms. Round-trips each form and asserts
  /// that malformed or trailing bytes, an unknown type, and a wrong confirmation length
  /// are rejected with a decode error.
  /// </summary>
  TTestEchExtension = class(TTlsLibAlgorithmTestCase)
  private
    function SampleOuter: TEchOuterClientHello;
    function DecodeRaises(const AData: TBytes): Boolean;
  published
    procedure TestOuterRoundTrip;
    procedure TestInnerRoundTrip;
    procedure TestUnknownTypeRejected;
    procedure TestOuterTrailingBytesRejected;
    procedure TestOuterExtensionsRoundTrip;
    procedure TestEmptyOuterExtensionsRejected;
    procedure TestHrrConfirmationRoundTrip;
    procedure TestHrrConfirmationBadLengthRejected;
  end;

implementation

{ TTestEchExtension }

function TTestEchExtension.SampleOuter: TEchOuterClientHello;
begin
  Result := Default(TEchOuterClientHello);
  Result.CipherSuite.KdfId := THpkeKdf.HKDF_SHA256;
  Result.CipherSuite.AeadId := THpkeAead.AES_128_GCM;
  Result.ConfigId := $AB;
  Result.Enc := TBytes.Create(1, 2, 3, 4, 5, 6, 7, 8);
  Result.Payload := TBytes.Create(9, 8, 7, 6, 5, 4, 3, 2, 1);
end;

function TTestEchExtension.DecodeRaises(const AData: TBytes): Boolean;
var
  LType: TEchClientHelloType;
  LOuter: TEchOuterClientHello;
begin
  Result := False;
  try
    TEchExtension.Decode(AData, LType, LOuter);
  except
    on E: EDecodeErrorTlsLibException do
      Result := True;
  end;
end;

procedure TTestEchExtension.TestOuterRoundTrip;
var
  LOuter, LDecoded: TEchOuterClientHello;
  LType: TEchClientHelloType;
begin
  LOuter := SampleOuter;
  TEchExtension.Decode(TEchExtension.EncodeOuter(LOuter), LType, LDecoded);
  CheckEquals(Ord(TEchClientHelloType.Outer), Ord(LType), 'outer type');
  CheckEquals(Integer(LOuter.CipherSuite.KdfId),
    Integer(LDecoded.CipherSuite.KdfId), 'kdf');
  CheckEquals(Integer(LOuter.CipherSuite.AeadId),
    Integer(LDecoded.CipherSuite.AeadId), 'aead');
  CheckEquals(Integer(LOuter.ConfigId), Integer(LDecoded.ConfigId), 'config_id');
  CheckEqualBytes('enc', LOuter.Enc, LDecoded.Enc);
  CheckEqualBytes('payload', LOuter.Payload, LDecoded.Payload);
end;

procedure TTestEchExtension.TestInnerRoundTrip;
var
  LType: TEchClientHelloType;
  LOuter: TEchOuterClientHello;
begin
  TEchExtension.Decode(TEchExtension.EncodeInner, LType, LOuter);
  CheckEquals(Ord(TEchClientHelloType.Inner), Ord(LType), 'inner type');
  CheckEquals(0, System.Length(LOuter.Enc), 'the inner marker carries no enc');
end;

procedure TTestEchExtension.TestUnknownTypeRejected;
var
  LType: TEchClientHelloType;
  LOuter: TEchOuterClientHello;
  LAlert: TTlsAlertDescription;
  LRaised: Boolean;
begin
  LRaised := False;
  LAlert := TTlsAlertDescription.DecodeError;
  try
    // an out-of-range ECHClientHelloType is illegal_parameter, not decode_error (RFC 9849 sec. 5)
    TEchExtension.Decode(TBytes.Create(2), LType, LOuter);
  except
    on E: EFatalAlertTlsLibException do
    begin
      LRaised := True;
      LAlert := E.AlertDescription;
    end;
  end;
  CheckTrue(LRaised, 'an unknown ECH type is rejected');
  CheckEquals(Ord(TTlsAlertDescription.IllegalParameter), Ord(LAlert),
    'an unknown ECH type is illegal_parameter');
end;

procedure TTestEchExtension.TestOuterTrailingBytesRejected;
var
  LEncoded, LWithTrailer: TBytes;
begin
  LEncoded := TEchExtension.EncodeOuter(SampleOuter);
  LWithTrailer := System.Copy(LEncoded);
  SetLength(LWithTrailer, System.Length(LWithTrailer) + 1);
  LWithTrailer[System.High(LWithTrailer)] := $FF;
  CheckTrue(DecodeRaises(LWithTrailer), 'trailing bytes after the body are rejected');
end;

procedure TTestEchExtension.TestOuterExtensionsRoundTrip;
var
  LTypes, LDecoded: TArray<UInt16>;
  LI: Int32;
begin
  LTypes := TArray<UInt16>.Create(UInt16(10), UInt16(13), UInt16(43), UInt16(51));
  LDecoded := TEchExtension.DecodeOuterExtensions(
    TEchExtension.EncodeOuterExtensions(LTypes));
  CheckEquals(System.Length(LTypes), System.Length(LDecoded), 'same count');
  for LI := 0 to System.High(LTypes) do
    CheckEquals(Integer(LTypes[LI]), Integer(LDecoded[LI]), 'same type');
end;

procedure TTestEchExtension.TestEmptyOuterExtensionsRejected;
var
  LRaised: Boolean;
begin
  // an empty list on the wire (1-byte length 0x00) is a decode error
  LRaised := False;
  try
    TEchExtension.DecodeOuterExtensions(TBytes.Create(0));
  except
    on E: EDecodeErrorTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'an empty ech_outer_extensions list is rejected');
end;

procedure TTestEchExtension.TestHrrConfirmationRoundTrip;
var
  LConfirm: TBytes;
begin
  LConfirm := TBytes.Create(1, 2, 3, 4, 5, 6, 7, 8);
  CheckEqualBytes('confirmation round-trip', LConfirm,
    TEchExtension.DecodeHrrConfirmation(
    TEchExtension.EncodeHrrConfirmation(LConfirm)));
end;

procedure TTestEchExtension.TestHrrConfirmationBadLengthRejected;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    TEchExtension.DecodeHrrConfirmation(TBytes.Create(1, 2, 3, 4, 5, 6, 7));
  except
    on E: EDecodeErrorTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a confirmation that is not 8 bytes is rejected');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestEchExtension);
{$ELSE}
  RegisterTest(TTestEchExtension.Suite);
{$ENDIF FPC}

end.
