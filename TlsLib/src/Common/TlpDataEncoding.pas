{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpDataEncoding;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpTlsLibExceptions;

type
  /// <summary>The letter case a hex encoding emits.</summary>
  THexCase = (Lower, Upper);

  /// <summary>
  /// Byte-to-text data encodings (RFC 4648): a lossless, encoding-independent
  /// text form for arbitrary bytes, where a character-set encoding would be lossy
  /// or reject non-UTF-8 input.
  /// </summary>
  TDataEncoding = class sealed(TObject)
  strict private
    class function NibbleValue(AChar: Char): Int32; static;
    class function Base64Value(AChar: Char): Int32; static;
  public
    /// <summary>The Base16 (hex) encoding of AData, lowercase by default.</summary>
    class function HexEncode(const AData: TBytes;
      ACase: THexCase = THexCase.Lower): string; static;
    /// <summary>
    /// The bytes of a Base16 (hex) string (either case). Raises
    /// EArgumentTlsLibException on an odd length or a non-hex character.
    /// </summary>
    class function HexDecode(const AHex: string): TBytes; static;
    /// <summary>The standard Base64 (RFC 4648, '+' and '/', padded) encoding of AData,
    /// as a single line with no embedded newlines.</summary>
    class function Base64Encode(const AData: TBytes): string; static;
    /// <summary>
    /// The bytes of a standard Base64 string (RFC 4648, '+' and '/'), tolerating
    /// embedded whitespace and newlines (as in a PEM body). Raises
    /// EArgumentTlsLibException on an invalid character or a malformed padding length.
    /// </summary>
    class function Base64Decode(const AText: string): TBytes; static;
  end;

implementation

const
  LowerHexDigits: array [0 .. 15] of Char = ('0', '1', '2', '3', '4', '5', '6',
    '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f');
  UpperHexDigits: array [0 .. 15] of Char = ('0', '1', '2', '3', '4', '5', '6',
    '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F');

resourcestring
  SOddHexLength = 'a hex string must have an even number of digits';
  SNonHexCharacter = 'the hex string contains a non-hex character';
  SInvalidBase64 = 'the base64 text contains an invalid character';

{ TDataEncoding }

class function TDataEncoding.HexEncode(const AData: TBytes;
  ACase: THexCase): string;
var
  LI: Int32;
  LHi, LLo: Char;
begin
  Result := '';
  SetLength(Result, System.Length(AData) * 2);
  for LI := 0 to System.Length(AData) - 1 do
  begin
    if ACase = THexCase.Upper then
    begin
      LHi := UpperHexDigits[AData[LI] shr 4];
      LLo := UpperHexDigits[AData[LI] and $0F];
    end
    else
    begin
      LHi := LowerHexDigits[AData[LI] shr 4];
      LLo := LowerHexDigits[AData[LI] and $0F];
    end;
    Result[(LI * 2) + 1] := LHi;
    Result[(LI * 2) + 2] := LLo;
  end;
end;

class function TDataEncoding.NibbleValue(AChar: Char): Int32;
begin
  case AChar of
    '0' .. '9':
      Result := Ord(AChar) - Ord('0');
    'a' .. 'f':
      Result := 10 + Ord(AChar) - Ord('a');
    'A' .. 'F':
      Result := 10 + Ord(AChar) - Ord('A');
  else
    Result := -1;
  end;
end;

class function TDataEncoding.HexDecode(const AHex: string): TBytes;
var
  LI, LHi, LLo: Int32;
begin
  Result := nil;
  if System.Length(AHex) mod 2 <> 0 then
    raise EArgumentTlsLibException.CreateRes(@SOddHexLength);
  SetLength(Result, System.Length(AHex) div 2);
  for LI := 0 to System.Length(Result) - 1 do
  begin
    LHi := NibbleValue(AHex[(LI * 2) + 1]);
    LLo := NibbleValue(AHex[(LI * 2) + 2]);
    if (LHi < 0) or (LLo < 0) then
      raise EArgumentTlsLibException.CreateRes(@SNonHexCharacter);
    Result[LI] := Byte((LHi shl 4) or LLo);
  end;
end;

class function TDataEncoding.Base64Value(AChar: Char): Int32;
begin
  case AChar of
    'A' .. 'Z':
      Result := Ord(AChar) - Ord('A');
    'a' .. 'z':
      Result := 26 + Ord(AChar) - Ord('a');
    '0' .. '9':
      Result := 52 + Ord(AChar) - Ord('0');
    '+':
      Result := 62;
    '/':
      Result := 63;
  else
    Result := -1;
  end;
end;

class function TDataEncoding.Base64Encode(const AData: TBytes): string;
const
  B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
var
  LI, LN, LPos, LB0, LB1, LB2: Int32;
begin
  Result := '';
  LN := System.Length(AData);
  if LN = 0 then
    Exit;
  SetLength(Result, ((LN + 2) div 3) * 4);
  LPos := 1;
  LI := 0;
  while LI < LN do
  begin
    LB0 := AData[LI];
    if LI + 1 < LN then
      LB1 := AData[LI + 1]
    else
      LB1 := 0;
    if LI + 2 < LN then
      LB2 := AData[LI + 2]
    else
      LB2 := 0;
    Result[LPos] := B64[(LB0 shr 2) + 1];
    Result[LPos + 1] := B64[(((LB0 and 3) shl 4) or (LB1 shr 4)) + 1];
    if LI + 1 < LN then
      Result[LPos + 2] := B64[(((LB1 and 15) shl 2) or (LB2 shr 6)) + 1]
    else
      Result[LPos + 2] := '=';
    if LI + 2 < LN then
      Result[LPos + 3] := B64[(LB2 and 63) + 1]
    else
      Result[LPos + 3] := '=';
    Inc(LPos, 4);
    Inc(LI, 3);
  end;
end;

class function TDataEncoding.Base64Decode(const AText: string): TBytes;
var
  LI, LVal, LSignificant, LPadding, LBits, LAccum, LOut: Int32;
  LC: Char;
  LSeenPadding: Boolean;
begin
  // RFC 4648 with padding: whitespace is ignored; '=' appears only as trailing padding
  // (at most two, and nothing but '=' after the first); the significant length is a
  // multiple of four. Anything else is rejected - a lenient "stop at '=' " decoder
  // silently accepts trailing garbage and mis-sized input.
  Result := nil;
  LBits := 0;
  LAccum := 0;
  LOut := 0;
  LSignificant := 0;
  LPadding := 0;
  LSeenPadding := False;
  SetLength(Result, ((System.Length(AText) div 4) + 1) * 3);
  for LI := 1 to System.Length(AText) do
  begin
    LC := AText[LI];
    if (LC = #13) or (LC = #10) or (LC = ' ') or (LC = #9) then
      Continue;
    Inc(LSignificant);
    if LC = '=' then
    begin
      LSeenPadding := True;
      Inc(LPadding);
      if LPadding > 2 then
        raise EArgumentTlsLibException.CreateRes(@SInvalidBase64);
      Continue;
    end;
    if LSeenPadding then
      raise EArgumentTlsLibException.CreateRes(@SInvalidBase64);
    LVal := Base64Value(LC);
    if LVal < 0 then
      raise EArgumentTlsLibException.CreateRes(@SInvalidBase64);
    LAccum := (LAccum shl 6) or LVal;
    Inc(LBits, 6);
    if LBits >= 8 then
    begin
      Dec(LBits, 8);
      Result[LOut] := Byte((LAccum shr LBits) and $FF);
      Inc(LOut);
    end;
  end;
  if LSignificant mod 4 <> 0 then
    raise EArgumentTlsLibException.CreateRes(@SInvalidBase64);
  SetLength(Result, LOut);
end;

end.
