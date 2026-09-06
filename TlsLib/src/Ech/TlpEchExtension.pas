{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpEchExtension;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpTlsAlert,
  TlpWireReader,
  TlpIWireWriter,
  TlpWireWriter,
  TlpWireVectorMarker,
  TlpEchConfig,
  TlpTlsLibExceptions;

type
  /// <summary>The two forms of the encrypted_client_hello extension (RFC 9849 sec. 5):
  /// the ClientHelloOuter form and the ClientHelloInner marker.</summary>
  TEchClientHelloType = (Outer = 0, Inner = 1);

  /// <summary>Codec of the 1-byte ECHClientHelloType discriminant (RFC 9849 sec. 5).</summary>
  TEchClientHelloTypeHelper = record helper for TEchClientHelloType
    function ToByte: Byte;
    class function TryFromByte(AByte: Byte;
      out AType: TEchClientHelloType): Boolean; static;
  end;

  /// <summary>
  /// The ClientHelloOuter encrypted_client_hello body (RFC 9849 sec. 5, outer form):
  /// the HPKE symmetric cipher suite, the recipient config_id, the HPKE encapsulation,
  /// and the sealed payload.
  /// </summary>
  TEchOuterClientHello = record
    CipherSuite: TEchCipherSuite;
    ConfigId: Byte;
    Enc: TBytes;
    Payload: TBytes;
  end;

  /// <summary>
  /// The encrypted_client_hello (0xfe0d) and ech_outer_extensions (0xfd00) extension
  /// codecs (RFC 9849 sec. 5 / 5.1) plus the fixed forms carried in EncryptedExtensions
  /// (retry_configs) and HelloRetryRequest (the 8-byte confirmation). Every decode is
  /// bounds-checked; a malformed body raises a decode_error.
  /// </summary>
  TEchExtension = class sealed(TObject)
  public const
    /// <summary>The fixed accept-confirmation length (RFC 9849 sec. 7.2).</summary>
    ConfirmationLength = Int32(8);
  public
    /// <summary>The ClientHelloOuter encrypted_client_hello body.</summary>
    class function EncodeOuter(const AOuter: TEchOuterClientHello): TBytes; static;
    /// <summary>The ClientHelloInner encrypted_client_hello body: the inner marker.</summary>
    class function EncodeInner: TBytes; static;
    /// <summary>
    /// Decodes an encrypted_client_hello body, returning its form. For the outer form
    /// AOuter is filled; for the inner form it is left empty. Raises a decode_error on a
    /// malformed body, or illegal_parameter on an out-of-range type (RFC 9849 sec. 5).
    /// </summary>
    class procedure Decode(const AData: TBytes; out AType: TEchClientHelloType;
      out AOuter: TEchOuterClientHello); static;

    /// <summary>The ech_outer_extensions body: a non-empty list of extension types.</summary>
    class function EncodeOuterExtensions(const ATypes: TArray<UInt16>): TBytes; static;
    /// <summary>Decodes an ech_outer_extensions body. Raises a decode_error on a
    /// malformed or empty list.</summary>
    class function DecodeOuterExtensions(const AData: TBytes): TArray<UInt16>; static;

    /// <summary>
    /// The EncryptedExtensions encrypted_client_hello body on ECH reject: the
    /// retry_configs, which is exactly an ECHConfigList (RFC 9849 sec. 5).
    /// </summary>
    class function EncodeRetryConfigs(const AConfigListBytes: TBytes): TBytes; static;
    /// <summary>Parses a retry_configs body (an ECHConfigList).</summary>
    class function DecodeRetryConfigs(const AData: TBytes): TArray<TEchConfig>; static;

    /// <summary>The HelloRetryRequest encrypted_client_hello body: an 8-byte
    /// confirmation (RFC 9849 sec. 5). Raises if AConfirmation is not 8 bytes.</summary>
    class function EncodeHrrConfirmation(const AConfirmation: TBytes): TBytes; static;
    /// <summary>The 8-byte confirmation from a HelloRetryRequest ech body. Raises a
    /// decode_error if the body is not exactly 8 bytes.</summary>
    class function DecodeHrrConfirmation(const AData: TBytes): TBytes; static;
  end;

implementation

resourcestring
  SUnknownEchType = 'unknown encrypted_client_hello type';
  SEmptyOuterExtensions = 'ech_outer_extensions must reference at least one extension';
  SBadConfirmationLength = 'encrypted_client_hello confirmation must be 8 bytes';

{ TEchClientHelloTypeHelper }

function TEchClientHelloTypeHelper.ToByte: Byte;
begin
  Result := Byte(Ord(Self));
end;

class function TEchClientHelloTypeHelper.TryFromByte(AByte: Byte;
  out AType: TEchClientHelloType): Boolean;
begin
  case AByte of
    0:
      AType := TEchClientHelloType.Outer;
    1:
      AType := TEchClientHelloType.Inner;
  else
    Exit(False);
  end;
  Result := True;
end;

{ TEchExtension }

class function TEchExtension.EncodeOuter(const AOuter: TEchOuterClientHello): TBytes;
var
  LWriter: IWireWriter;
  LEnc, LPayload: TWireVectorMarker;
begin
  LWriter := TWireWriter.Create;
  LWriter.WriteUInt8(TEchClientHelloType.Outer.ToByte);
  LWriter.WriteUInt16(AOuter.CipherSuite.KdfId);
  LWriter.WriteUInt16(AOuter.CipherSuite.AeadId);
  LWriter.WriteUInt8(AOuter.ConfigId);
  LEnc := LWriter.OpenVector(2);
  LWriter.WriteBytes(AOuter.Enc);
  LWriter.CloseVector(LEnc);
  LPayload := LWriter.OpenVector(2);
  LWriter.WriteBytes(AOuter.Payload);
  LWriter.CloseVector(LPayload);
  Result := LWriter.ToBytes;
end;

class function TEchExtension.EncodeInner: TBytes;
begin
  Result := TBytes.Create(TEchClientHelloType.Inner.ToByte);
end;

class procedure TEchExtension.Decode(const AData: TBytes;
  out AType: TEchClientHelloType; out AOuter: TEchOuterClientHello);
var
  LReader, LEnc, LPayload: TWireReader;
begin
  AOuter := Default(TEchOuterClientHello);
  LReader := TWireReader.Create(AData);
  // an out-of-range ECHClientHelloType is illegal_parameter, not decode_error (RFC 9849 sec. 5)
  if not TEchClientHelloType.TryFromByte(LReader.ReadUInt8, AType) then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.IllegalParameter, @SUnknownEchType);
  case AType of
    TEchClientHelloType.Outer:
      begin
        AOuter.CipherSuite.KdfId := LReader.ReadUInt16;
        AOuter.CipherSuite.AeadId := LReader.ReadUInt16;
        AOuter.ConfigId := LReader.ReadUInt8;
        LEnc := LReader.OpenVector(2);
        AOuter.Enc := LEnc.ReadBytes(LEnc.Remaining);
        LPayload := LReader.OpenVector(2);
        AOuter.Payload := LPayload.ReadBytes(LPayload.Remaining);
      end;
    TEchClientHelloType.Inner:
      ; // the inner marker carries no further data
  end;
  LReader.ExpectEnd;
end;

class function TEchExtension.EncodeOuterExtensions(
  const ATypes: TArray<UInt16>): TBytes;
var
  LWriter: IWireWriter;
  LMarker: TWireVectorMarker;
  LType: UInt16;
begin
  if System.Length(ATypes) = 0 then
    raise EArgumentTlsLibException.CreateRes(@SEmptyOuterExtensions);
  LWriter := TWireWriter.Create;
  LMarker := LWriter.OpenVector(1);
  for LType in ATypes do
    LWriter.WriteUInt16(LType);
  LWriter.CloseVector(LMarker);
  Result := LWriter.ToBytes;
end;

class function TEchExtension.DecodeOuterExtensions(
  const AData: TBytes): TArray<UInt16>;
var
  LReader, LList: TWireReader;
  LCount: Int32;
begin
  Result := nil;
  LReader := TWireReader.Create(AData);
  LList := LReader.OpenVector(1);
  LReader.ExpectEnd;
  LCount := 0;
  while not LList.EndReached do
  begin
    SetLength(Result, LCount + 1);
    Result[LCount] := LList.ReadUInt16;
    Inc(LCount);
  end;
  if LCount = 0 then
    raise EDecodeErrorTlsLibException.CreateRes(@SEmptyOuterExtensions);
end;

class function TEchExtension.EncodeRetryConfigs(
  const AConfigListBytes: TBytes): TBytes;
begin
  // the EncryptedExtensions ech body IS an ECHConfigList (RFC 9849 sec. 5)
  Result := System.Copy(AConfigListBytes);
end;

class function TEchExtension.DecodeRetryConfigs(
  const AData: TBytes): TArray<TEchConfig>;
begin
  Result := TEchConfigList.Parse(AData);
end;

class function TEchExtension.EncodeHrrConfirmation(
  const AConfirmation: TBytes): TBytes;
begin
  if System.Length(AConfirmation) <> ConfirmationLength then
    raise EArgumentTlsLibException.CreateRes(@SBadConfirmationLength);
  Result := System.Copy(AConfirmation);
end;

class function TEchExtension.DecodeHrrConfirmation(const AData: TBytes): TBytes;
begin
  if System.Length(AData) <> ConfirmationLength then
    raise EDecodeErrorTlsLibException.CreateRes(@SBadConfirmationLength);
  Result := System.Copy(AData);
end;

end.
