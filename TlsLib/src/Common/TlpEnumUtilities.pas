{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpEnumUtilities;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TypInfo,
  TlpBinaryPrimitives;

type
  /// <summary>Normalizes an enum-name input before parsing (e.g. '-'/'/'  to '_').</summary>
  TEnumStringReplacer = function(const AInput: string): string;

  /// <summary>
  /// Utility class for enum operations. Works with ordinals; callers cast to their
  /// enum type, e.g. TMyEnum(ordinal).
  /// </summary>
  TEnumUtilities = class sealed(TObject)
  strict private
    class function DefaultReplacer(const AInput: string): string; static;

    /// <summary>Writes an enum ordinal into AResult using a size-aware, native-order store.</summary>
    class procedure WriteOrdinal<T>(out AResult: T; AOrdinal: Int32); static;

    /// <summary>Reads an enum ordinal from AValue using a size-aware, native-order load.</summary>
    class function ReadOrdinal<T>(const AValue: T): Int32; static;
  public
    /// <summary>
    /// Returns an array of ordinals for all defined values of the enum. For enums
    /// with gaps, only ordinals that have a name are included. Caller casts:
    /// TMyEnum(GetEnumValues(TypeInfo(TMyEnum))[i]).
    /// </summary>
    class function GetEnumValues(ATypeInfo: PTypeInfo): TArray<Int32>; overload; static;

    /// <summary>
    /// Tries to parse a string as an enum ordinal. Only parses single named
    /// constants: non-empty, first character a letter, no comma. The input is
    /// normalized by replacing '-' and '/' with '_'. Returns True and the ordinal
    /// in AResult when successful; otherwise False and AResult is 0.
    /// </summary>
    class function TryGetEnumValue(ATypeInfo: PTypeInfo; const AInput: string;
      out AResult: Int32): Boolean; overload; static;

    /// <summary>
    /// Tries to parse a string as an enum ordinal. Only parses single named
    /// constants: non-empty, first character a letter, no comma. When AReplacer is
    /// nil, the input is normalized by replacing '-' and '/' with '_' before
    /// parsing; when AReplacer is assigned, it is applied to the input. Returns True
    /// and the ordinal in AResult when successful; otherwise False and AResult is 0.
    /// </summary>
    class function TryGetEnumValue(ATypeInfo: PTypeInfo; const AInput: string;
      out AResult: Int32; const AReplacer: TEnumStringReplacer): Boolean; overload; static;

    /// <summary>
    /// Converts an enum ordinal to its declared name string. Returns the empty
    /// string if ATypeInfo is nil, not an enum, or the ordinal has no name.
    /// </summary>
    class function GetName(ATypeInfo: PTypeInfo; AOrdinal: Int32): string; overload; static;

    // Generic overloads (T must be an enum); delegate to PTypeInfo versions.

    /// <summary>Returns an array of all defined values of the enum.</summary>
    class function GetEnumValues<T>: TArray<T>; overload; static;

    /// <summary>
    /// Tries to parse a string as an enum value. Default normalization ('-', '/' to
    /// '_') is used. On failure, AResult is Default(T).
    /// </summary>
    class function TryGetEnumValue<T>(const AInput: string; out AResult: T): Boolean; overload; static;

    /// <summary>
    /// Tries to parse a string as an enum value. When AReplacer is nil, default
    /// normalization ('-', '/' to '_') is used. On failure, AResult is Default(T).
    /// </summary>
    class function TryGetEnumValue<T>(const AInput: string; out AResult: T;
      const AReplacer: TEnumStringReplacer): Boolean; overload; static;

    /// <summary>
    /// Tries to interpret an ordinal as a valid named value of the enum. On success
    /// sets AResult to T(AOrdinal) and returns True; otherwise AResult is Default(T)
    /// and returns False.
    /// </summary>
    class function TryGetEnumFromOrdinal<T>(AOrdinal: Int32; out AResult: T): Boolean; static;

    /// <summary>Converts an enum value to its declared name string.</summary>
    class function GetName<T>(const AValue: T): string; overload; static;
  end;

implementation

{ TEnumUtilities }

class function TEnumUtilities.DefaultReplacer(const AInput: string): string;
begin
  Result := StringReplace(AInput, '-', '_', [rfReplaceAll]);
  Result := StringReplace(Result, '/', '_', [rfReplaceAll]);
end;

class procedure TEnumUtilities.WriteOrdinal<T>(out AResult: T; AOrdinal: Int32);
begin
  case SizeOf(T) of
    1: PByte(@AResult)^ := Byte(AOrdinal);
    2: TBinaryPrimitives.StoreUInt16(PWord(@AResult), UInt16(AOrdinal));
  else
    TBinaryPrimitives.StoreUInt32(PCardinal(@AResult), UInt32(AOrdinal));
  end;
end;

class function TEnumUtilities.ReadOrdinal<T>(const AValue: T): Int32;
begin
  case SizeOf(T) of
    1: Result := PByte(@AValue)^;
    2: Result := TBinaryPrimitives.LoadUInt16(PWord(@AValue));
  else
    Result := Int32(TBinaryPrimitives.LoadUInt32(PCardinal(@AValue)));
  end;
end;

class function TEnumUtilities.GetEnumValues(ATypeInfo: PTypeInfo): TArray<Int32>;
var
  LTypeData: PTypeData;
  LI, LCount: Int32;
begin
  if (ATypeInfo = nil) or (ATypeInfo^.Kind <> tkEnumeration) then
  begin
    Result := nil;
    Exit;
  end;

  LTypeData := GetTypeData(ATypeInfo);
  SetLength(Result, LTypeData^.MaxValue - LTypeData^.MinValue + 1);
  LCount := 0;
  for LI := LTypeData^.MinValue to LTypeData^.MaxValue do
    if GetEnumName(ATypeInfo, LI) <> '' then
    begin
      Result[LCount] := LI;
      Inc(LCount);
    end;
  SetLength(Result, LCount);
end;

class function TEnumUtilities.TryGetEnumValue(ATypeInfo: PTypeInfo;
  const AInput: string; out AResult: Int32): Boolean;
begin
  Result := TryGetEnumValue(ATypeInfo, AInput, AResult, nil);
end;

class function TEnumUtilities.TryGetEnumValue(ATypeInfo: PTypeInfo;
  const AInput: string; out AResult: Int32;
  const AReplacer: TEnumStringReplacer): Boolean;
var
  LProcessed: string;
  LOrd: Int32;
begin
  AResult := 0;

  if (ATypeInfo = nil) or (ATypeInfo^.Kind <> tkEnumeration) then
    Exit(False);

  // Only parse single named constants: non-empty, first char a letter, no comma
  if (System.Length(AInput) = 0) or (Pos(',', AInput) > 0) then
    Exit(False);

  if not CharInSet(AInput[1], ['A'..'Z', 'a'..'z']) then
    Exit(False);

  if Assigned(AReplacer) then
    LProcessed := AReplacer(AInput)
  else
    LProcessed := DefaultReplacer(AInput);

  LOrd := GetEnumValue(ATypeInfo, LProcessed);
  if LOrd < 0 then
    Exit(False);

  AResult := LOrd;
  Result := True;
end;

class function TEnumUtilities.GetName(ATypeInfo: PTypeInfo; AOrdinal: Int32): string;
begin
  if (ATypeInfo = nil) or (ATypeInfo^.Kind <> tkEnumeration) then
    Exit('');
  Result := GetEnumName(ATypeInfo, AOrdinal);
end;

class function TEnumUtilities.GetEnumValues<T>: TArray<T>;
var
  LOrds: TArray<Int32>;
  LI: Int32;
begin
  LOrds := GetEnumValues(TypeInfo(T));
  SetLength(Result, Length(LOrds));
  for LI := 0 to High(LOrds) do
    WriteOrdinal<T>(Result[LI], LOrds[LI]);
end;

class function TEnumUtilities.TryGetEnumValue<T>(const AInput: string; out AResult: T): Boolean;
var
  LOrd: Int32;
begin
  // inlined rather than forwarding to the generic overload with a nil replacer
  Result := TryGetEnumValue(TypeInfo(T), AInput, LOrd, nil);
  if Result then
    WriteOrdinal<T>(AResult, LOrd)
  else
    AResult := Default(T);
end;

class function TEnumUtilities.TryGetEnumValue<T>(const AInput: string;
  out AResult: T; const AReplacer: TEnumStringReplacer): Boolean;
var
  LOrd: Int32;
begin
  Result := TryGetEnumValue(TypeInfo(T), AInput, LOrd, AReplacer);
  if Result then
    WriteOrdinal<T>(AResult, LOrd)
  else
    AResult := Default(T);
end;

class function TEnumUtilities.TryGetEnumFromOrdinal<T>(AOrdinal: Int32;
  out AResult: T): Boolean;
begin
  // GetName validates the ordinal rather than a MinValue/MaxValue range check
  // because enums may be non-contiguous (e.g. A = 0, B = 5, C = 10): GetName returns
  // the empty string for ordinals in the gaps, correctly rejecting them.
  Result := GetName(TypeInfo(T), AOrdinal) <> '';
  if Result then
    WriteOrdinal<T>(AResult, AOrdinal)
  else
    AResult := Default(T);
end;

class function TEnumUtilities.GetName<T>(const AValue: T): string;
var
  LOrd: Int32;
begin
  LOrd := ReadOrdinal<T>(AValue);
  Result := GetName(TypeInfo(T), LOrd);
end;

end.
