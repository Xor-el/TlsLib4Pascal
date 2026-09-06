{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpWireReader;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpBinaryPrimitives,
  TlpTlsLibExceptions;

type
  /// <summary>
  /// The single bounds-checked reader that mediates all wire parsing: over-read
  /// is structurally impossible. It is a record over a borrowed buffer with a
  /// cursor and a hard limit; every read validates against the limit first and
  /// raises <see cref="EDecodeErrorTlsLibException" /> on underflow. Pass it by
  /// var and never copy it mid-parse - a value copy forks the cursor.
  /// </summary>
  TWireReader = record
  strict private
  var
    FBuf: TBytes;
    FPos: Int32;
    FLimit: Int32;
    procedure Need(ACount: Int32);
  public
    /// <summary>A reader over the whole of ABuf.</summary>
    class function Create(const ABuf: TBytes): TWireReader; overload; static;
    /// <summary>A reader bounded to ABuf[AOffset .. AOffset + ALength).</summary>
    class function Create(const ABuf: TBytes; AOffset, ALength: Int32): TWireReader;
      overload; static;

    /// <summary>Bytes left before the limit.</summary>
    function Remaining: Int32;
    /// <summary>The cursor's absolute offset in the underlying buffer. A sub-reader from
    /// OpenVector shares the buffer, so this stays absolute across nesting - useful to map a
    /// parsed field back to its byte offset in the original message.</summary>
    function Position: Int32;
    /// <summary>True once the cursor has reached the limit.</summary>
    function EndReached: Boolean;

    function ReadUInt8: Byte;
    function ReadUInt16: UInt16;
    function ReadUInt24: UInt32;
    function ReadUInt32: UInt32;

    /// <summary>Reads ACount bytes into a fresh array.</summary>
    function ReadBytes(ACount: Int32): TBytes;
    /// <summary>Advances past ACount bytes.</summary>
    procedure Skip(ACount: Int32);

    /// <summary>
    /// Reads a length prefix ALenBytes wide (1..4), validates it against the
    /// bytes remaining, and returns a sub-reader bounded to exactly that slice;
    /// this reader advances past the slice. Follow with <see cref="ExpectEnd" />
    /// on the sub-reader to reject trailing bytes.
    /// </summary>
    function OpenVector(ALenBytes: Int32): TWireReader;
    /// <summary>Rejects any unconsumed trailing bytes (decode_error).</summary>
    procedure ExpectEnd;
  end;

implementation

resourcestring
  SUnexpectedEndOfData = 'unexpected end of data: needed %d byte(s), have %d';
  STrailingBytes = 'unexpected trailing bytes: %d byte(s) after structure';
  SInvalidPrefixWidth = 'invalid length-prefix width: %d (expected 1..4)';
  SInvalidSlice = 'invalid reader slice: offset %d length %d over buffer of %d';

{ TWireReader }

class function TWireReader.Create(const ABuf: TBytes): TWireReader;
begin
  Result := TWireReader.Create(ABuf, 0, System.Length(ABuf));
end;

class function TWireReader.Create(const ABuf: TBytes; AOffset, ALength: Int32): TWireReader;
begin
  if (AOffset < 0) or (ALength < 0) or
    (Int64(AOffset) + ALength > System.Length(ABuf)) then
    raise EArgumentTlsLibException.CreateResFmt(@SInvalidSlice,
      [AOffset, ALength, System.Length(ABuf)]);
  Result.FBuf := ABuf;
  Result.FPos := AOffset;
  Result.FLimit := AOffset + ALength;
end;

procedure TWireReader.Need(ACount: Int32);
begin
  if (ACount < 0) or (Int64(FPos) + ACount > FLimit) then
    raise EDecodeErrorTlsLibException.CreateResFmt(@SUnexpectedEndOfData,
      [ACount, FLimit - FPos]);
end;

function TWireReader.Position: Int32;
begin
  Result := FPos;
end;

function TWireReader.Remaining: Int32;
begin
  Result := FLimit - FPos;
end;

function TWireReader.EndReached: Boolean;
begin
  Result := FPos >= FLimit;
end;

function TWireReader.ReadUInt8: Byte;
begin
  Need(1);
  Result := FBuf[FPos];
  Inc(FPos);
end;

function TWireReader.ReadUInt16: UInt16;
begin
  Need(2);
  Result := TBinaryPrimitives.ReadUInt16BigEndian(PByte(FBuf), FPos);
  Inc(FPos, 2);
end;

function TWireReader.ReadUInt24: UInt32;
begin
  Need(3);
  Result := (UInt32(FBuf[FPos]) shl 16) or (UInt32(FBuf[FPos + 1]) shl 8) or
    FBuf[FPos + 2];
  Inc(FPos, 3);
end;

function TWireReader.ReadUInt32: UInt32;
begin
  Need(4);
  Result := TBinaryPrimitives.ReadUInt32BigEndian(PByte(FBuf), FPos);
  Inc(FPos, 4);
end;

function TWireReader.ReadBytes(ACount: Int32): TBytes;
begin
  Result := nil;
  Need(ACount);
  SetLength(Result, ACount);
  if ACount > 0 then
    Move(FBuf[FPos], Result[0], ACount);
  Inc(FPos, ACount);
end;

procedure TWireReader.Skip(ACount: Int32);
begin
  Need(ACount);
  Inc(FPos, ACount);
end;

function TWireReader.OpenVector(ALenBytes: Int32): TWireReader;
var
  LLen: Int32;
begin
  case ALenBytes of
    1:
      LLen := ReadUInt8;
    2:
      LLen := ReadUInt16;
    3:
      LLen := Int32(ReadUInt24);
    4:
      LLen := Int32(ReadUInt32);
  else
    raise EArgumentTlsLibException.CreateResFmt(@SInvalidPrefixWidth, [ALenBytes]);
  end;
  // A 4-byte prefix can exceed MaxInt; Need treats a negative count as underflow.
  Need(LLen);
  Result := TWireReader.Create(FBuf, FPos, LLen);
  Inc(FPos, LLen);
end;

procedure TWireReader.ExpectEnd;
begin
  if FPos < FLimit then
    raise EDecodeErrorTlsLibException.CreateResFmt(@STrailingBytes,
      [FLimit - FPos]);
end;

end.
