{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpGrease;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpWireReader,
  TlpWireVectorMarker,
  TlpIWireWriter,
  TlpWireWriter;

type
  /// <summary>
  /// GREASE (RFC 8701): the 16 reserved 0x?A?A codepoints a client sprinkles across
  /// its offers so peers stay tolerant of unknown values. GREASE values are never
  /// negotiated - a conformant peer ignores them - so emitting them exercises that
  /// tolerance. All helpers are pure.
  /// </summary>
  TGrease = class sealed(TObject)
  public
    /// <summary>Whether AValue is one of the 16 GREASE codepoints.</summary>
    class function IsGrease(AValue: UInt16): Boolean; static;
    /// <summary>The GREASE codepoint for index AIndex (taken modulo 16).</summary>
    class function ValueAt(AIndex: Int32): UInt16; static;
    /// <summary>A copy of AList with AValue prepended.</summary>
    class function Prepend(const AList: TArray<UInt16>; AValue: UInt16): TArray<UInt16>; static;
    /// <summary>Splices an empty-bodied GREASE extension (type AType) at the front of
    /// an already-serialized extensions block (2-byte length prefix + entries).</summary>
    class function InjectExtension(const ABlock: TBytes; AType: UInt16): TBytes; static;
  end;

implementation

{ TGrease }

class function TGrease.ValueAt(AIndex: Int32): UInt16;
begin
  // 0x0A0A, 0x1A1A, .. 0xFAFA: both bytes are (nibble)A with the same high nibble
  Result := UInt16((UInt32(AIndex and $0F) * $1010) + $0A0A);
end;

class function TGrease.IsGrease(AValue: UInt16): Boolean;
begin
  // low nibble of each byte is A, and both high nibbles match
  Result := ((AValue and $0F0F) = $0A0A) and
    ((AValue shr 12) = ((AValue shr 4) and $0F));
end;

class function TGrease.Prepend(const AList: TArray<UInt16>;
  AValue: UInt16): TArray<UInt16>;
var
  LI: Int32;
begin
  Result := nil;
  SetLength(Result, System.Length(AList) + 1);
  Result[0] := AValue;
  for LI := 0 to System.High(AList) do
    Result[LI + 1] := AList[LI];
end;

class function TGrease.InjectExtension(const ABlock: TBytes;
  AType: UInt16): TBytes;
var
  LReader, LInner: TWireReader;
  LEntries: TBytes;
  LWriter: IWireWriter;
  LMarker: TWireVectorMarker;
begin
  Result := nil;
  LReader := TWireReader.Create(ABlock);
  LInner := LReader.OpenVector(2);
  LEntries := LInner.ReadBytes(LInner.Remaining);
  LWriter := TWireWriter.Create;
  LMarker := LWriter.OpenVector(2);
  LWriter.WriteUInt16(AType);
  LWriter.WriteUInt16(0); // empty extension_data
  LWriter.WriteBytes(LEntries);
  LWriter.CloseVector(LMarker);
  Result := LWriter.ToBytes;
end;

end.
