{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpWireWriter;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpBinaryPrimitives,
  TlpWireVectorMarker,
  TlpIWireWriter,
  TlpSecureMemory,
  TlpTlsLibExceptions;

type
  /// <summary>
  /// The default <see cref="IWireWriter" />: builds a TLS wire structure into a
  /// growable buffer. Big-endian integers, and length-prefixed vectors written as
  /// an OpenVector/CloseVector pair that emits a length placeholder, appends the
  /// body, then back-patches the prefix (so nested structures need no size
  /// pre-computation). The buffer is wiped on growth and on destruction, so a serialized
  /// secret (e.g. a session's master secret or resumption PSK) does not linger in a freed block.
  /// </summary>
  TWireWriter = class sealed(TInterfacedObject, IWireWriter)
  strict private
  var
    FBuf: TBytes;
    FLen: Int32;
    procedure EnsureCapacity(AAdditional: Int32);
    procedure AppendByte(AValue: Byte);
  public
    constructor Create;
    destructor Destroy; override;

    procedure WriteUInt8(AValue: Byte);
    procedure WriteUInt16(AValue: UInt16);
    procedure WriteUInt24(AValue: UInt32);
    procedure WriteUInt32(AValue: UInt32);

    procedure WriteBytes(const AData: TBytes); overload;
    procedure WriteBytes(const AData: TBytes; AOffset, ACount: Int32); overload;

    /// <summary>Emits an ALenBytes-wide (1..4) length placeholder and returns a
    /// marker for the matching <see cref="CloseVector" />.</summary>
    function OpenVector(ALenBytes: Int32): TWireVectorMarker;
    /// <summary>Back-patches the vector prefix with the body length; raises if
    /// the body exceeds what the prefix width can encode.</summary>
    procedure CloseVector(const AMarker: TWireVectorMarker);

    /// <summary>Bytes written so far.</summary>
    function Length: Int32;
    /// <summary>A fresh copy of the written bytes.</summary>
    function ToBytes: TBytes;
  end;

implementation

resourcestring
  SInvalidPrefixWidth = 'invalid length-prefix width: %d (expected 1..4)';
  SVectorBodyTooLong = 'vector body of %d byte(s) does not fit a %d-byte length prefix';
  SUInt24OutOfRange = 'value %d exceeds the 24-bit range';
  SWriteSliceOutOfRange = 'write slice offset %d length %d over buffer of %d';

{ TWireWriter }

constructor TWireWriter.Create;
begin
  inherited Create;
  FBuf := nil;
  FLen := 0;
end;

destructor TWireWriter.Destroy;
begin
  TSecureMemory.WipeBytes(FBuf);
  inherited Destroy;
end;

procedure TWireWriter.EnsureCapacity(AAdditional: Int32);
var
  LCapacity, LNeeded: Int32;
  LNew: TBytes;
begin
  LNeeded := FLen + AAdditional;
  LCapacity := System.Length(FBuf);
  if LNeeded <= LCapacity then
    Exit;
  if LCapacity = 0 then
    LCapacity := 64;
  while LCapacity < LNeeded do
    LCapacity := LCapacity * 2;
  // grow into a fresh block and wipe the old one: SetLength would move the contents and free the
  // old block unwiped, leaving a copy of any serialized secret behind
  LNew := nil;
  SetLength(LNew, LCapacity);
  if FLen > 0 then
    Move(FBuf[0], LNew[0], FLen);
  TSecureMemory.WipeBytes(FBuf);
  FBuf := LNew;
end;

procedure TWireWriter.AppendByte(AValue: Byte);
begin
  EnsureCapacity(1);
  FBuf[FLen] := AValue;
  Inc(FLen);
end;

procedure TWireWriter.WriteUInt8(AValue: Byte);
begin
  AppendByte(AValue);
end;

procedure TWireWriter.WriteUInt16(AValue: UInt16);
begin
  EnsureCapacity(2);
  TBinaryPrimitives.WriteUInt16BigEndian(PByte(FBuf), FLen, AValue);
  Inc(FLen, 2);
end;

procedure TWireWriter.WriteUInt24(AValue: UInt32);
begin
  if AValue > $FFFFFF then
    raise EArgumentTlsLibException.CreateResFmt(@SUInt24OutOfRange, [AValue]);
  EnsureCapacity(3);
  FBuf[FLen] := Byte(AValue shr 16);
  FBuf[FLen + 1] := Byte(AValue shr 8);
  FBuf[FLen + 2] := Byte(AValue);
  Inc(FLen, 3);
end;

procedure TWireWriter.WriteUInt32(AValue: UInt32);
begin
  EnsureCapacity(4);
  TBinaryPrimitives.WriteUInt32BigEndian(PByte(FBuf), FLen, AValue);
  Inc(FLen, 4);
end;

procedure TWireWriter.WriteBytes(const AData: TBytes);
begin
  WriteBytes(AData, 0, System.Length(AData));
end;

procedure TWireWriter.WriteBytes(const AData: TBytes; AOffset, ACount: Int32);
begin
  if (AOffset < 0) or (ACount < 0) or
    (Int64(AOffset) + ACount > System.Length(AData)) then
    raise EArgumentTlsLibException.CreateResFmt(@SWriteSliceOutOfRange,
      [AOffset, ACount, System.Length(AData)]);
  if ACount = 0 then
    Exit;
  EnsureCapacity(ACount);
  Move(AData[AOffset], FBuf[FLen], ACount);
  Inc(FLen, ACount);
end;

function TWireWriter.OpenVector(ALenBytes: Int32): TWireVectorMarker;
var
  LI: Int32;
begin
  if (ALenBytes < 1) or (ALenBytes > 4) then
    raise EArgumentTlsLibException.CreateResFmt(@SInvalidPrefixWidth, [ALenBytes]);
  Result := TWireVectorMarker.Create(FLen, ALenBytes);
  for LI := 1 to ALenBytes do
    AppendByte(0);
end;

procedure TWireWriter.CloseVector(const AMarker: TWireVectorMarker);
var
  LBodyLen, LK: Int32;
  LMax: Int64;
begin
  LBodyLen := FLen - (AMarker.Pos + AMarker.LenBytes);
  LMax := (Int64(1) shl (8 * AMarker.LenBytes)) - 1;
  if LBodyLen > LMax then
    raise EArgumentTlsLibException.CreateResFmt(@SVectorBodyTooLong,
      [LBodyLen, AMarker.LenBytes]);
  for LK := 0 to AMarker.LenBytes - 1 do
    FBuf[AMarker.Pos + LK] :=
      Byte((LBodyLen shr (8 * (AMarker.LenBytes - 1 - LK))) and $FF);
end;

function TWireWriter.Length: Int32;
begin
  Result := FLen;
end;

function TWireWriter.ToBytes: TBytes;
begin
  Result := nil;
  SetLength(Result, FLen);
  if FLen > 0 then
    Move(FBuf[0], Result[0], FLen);
end;

end.
