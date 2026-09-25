{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpRecordHeader;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpBinaryPrimitives,
  TlpTlsAlert,
  TlpTlsLibExceptions,
  TlpTlsContentType,
  TlpTlsVersion,
  TlpWireReader,
  TlpIWireWriter;

type
  /// <summary>The record-layer size ceilings (RFC 8446 5.1/5.2, RFC 5246 6.2.3).</summary>
  TRecordLimits = class sealed(TObject)
  public const
    /// <summary>The fixed 5-byte record header: type(1) version(2) length(2).</summary>
    HeaderLength = Int32(5);
    /// <summary>The TLSPlaintext.length ceiling, 2^14.</summary>
    MaxPlaintext = Int32(16384);
    /// <summary>The TLSCiphertext.length ceiling for 1.3, 2^14 + 256.</summary>
    MaxCipherTextTls13 = Int32(16384 + 256);
    /// <summary>The 1.2 AEAD ciphertext ceiling, 2^14 + 2048.</summary>
    MaxCiphertextTls12 = Int32(16384 + 2048);
  end;

  /// <summary>
  /// The 5-byte TLS record header. The content type is held as its raw wire byte
  /// so an unknown code survives the parse for the record layer's demux to reject
  /// (RFC 8446 5.1) rather than being guessed or dropped here.
  /// </summary>
  TTlsRecordHeader = record
  strict private
  var
    FContentTypeByte: Byte;
    FVersion: TTlsVersion;
    FLength: Int32;
  public
    /// <summary>A header for a known content type.</summary>
    class function Create(AContentType: TTlsContentType; const AVersion: TTlsVersion;
      ALength: Int32): TTlsRecordHeader; static;
    /// <summary>A header carrying a raw content-type byte (e.g. re-emitting one).</summary>
    class function CreateRaw(AContentTypeByte: Byte; const AVersion: TTlsVersion;
      ALength: Int32): TTlsRecordHeader; static;
    /// <summary>
    /// Reads the 5-byte header through the bounds-checked reader (a truncated
    /// header raises a clean decode_error, never over-reading), then rejects a
    /// length above AMaxCiphertextLength as record_overflow before the body is
    /// consumed.
    /// </summary>
    class function Parse(var AReader: TWireReader;
      AMaxCiphertextLength: Int32): TTlsRecordHeader; static;
    /// <summary>Writes the 5 header bytes through the wire writer.</summary>
    procedure Serialize(const AWriter: IWireWriter);
    /// <summary>Writes the 5 header bytes at ABuf[AOffset]; the caller sizes ABuf.</summary>
    procedure WriteTo(const ABuf: TBytes; AOffset: Int32);
    /// <summary>Maps the content-type byte to a known type; False if unknown.</summary>
    function TryContentType(out AContentType: TTlsContentType): Boolean;

    property ContentTypeByte: Byte read FContentTypeByte;
    property Version: TTlsVersion read FVersion;
    property Length: Int32 read FLength;
  end;

implementation

resourcestring
  SLengthOutOfRange = 'record length %d is outside the encodable 0..%d range';
  SRecordOverflow = 'record length %d exceeds the %d-byte ciphertext limit';

{ TTlsRecordHeader }

class function TTlsRecordHeader.Create(AContentType: TTlsContentType;
  const AVersion: TTlsVersion; ALength: Int32): TTlsRecordHeader;
begin
  Result := TTlsRecordHeader.CreateRaw(AContentType.ToByte,
    AVersion, ALength);
end;

class function TTlsRecordHeader.CreateRaw(AContentTypeByte: Byte;
  const AVersion: TTlsVersion; ALength: Int32): TTlsRecordHeader;
begin
  if (ALength < 0) or (ALength > $FFFF) then
    raise EArgumentTlsLibException.CreateResFmt(@SLengthOutOfRange, [ALength, $FFFF]);
  Result.FContentTypeByte := AContentTypeByte;
  Result.FVersion := AVersion;
  Result.FLength := ALength;
end;

class function TTlsRecordHeader.Parse(var AReader: TWireReader;
  AMaxCiphertextLength: Int32): TTlsRecordHeader;
var
  LContentTypeByte: Byte;
  LVersion: UInt16;
  LLength: Int32;
begin
  LContentTypeByte := AReader.ReadUInt8;
  LVersion := AReader.ReadUInt16;
  LLength := AReader.ReadUInt16;
  if LLength > AMaxCiphertextLength then
    raise EFatalAlertTlsLibException.CreateResFmt(TTlsAlertDescription.RecordOverflow,
      @SRecordOverflow, [LLength, AMaxCiphertextLength]);
  Result.FContentTypeByte := LContentTypeByte;
  Result.FVersion := TTlsVersion.Create(LVersion);
  Result.FLength := LLength;
end;

procedure TTlsRecordHeader.Serialize(const AWriter: IWireWriter);
begin
  AWriter.WriteUInt8(FContentTypeByte);
  AWriter.WriteUInt16(FVersion.WireValue);
  AWriter.WriteUInt16(UInt16(FLength));
end;

procedure TTlsRecordHeader.WriteTo(const ABuf: TBytes; AOffset: Int32);
begin
  ABuf[AOffset] := FContentTypeByte;
  TBinaryPrimitives.WriteUInt16BigEndian(ABuf, AOffset + 1, FVersion.WireValue);
  TBinaryPrimitives.WriteUInt16BigEndian(ABuf, AOffset + 3, UInt16(FLength));
end;

function TTlsRecordHeader.TryContentType(out AContentType: TTlsContentType): Boolean;
begin
  Result := TTlsContentType.TryFromByte(FContentTypeByte, AContentType);
end;

end.
