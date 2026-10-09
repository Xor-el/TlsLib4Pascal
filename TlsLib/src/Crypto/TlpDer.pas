{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpDer;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpBinaryPrimitives;

type
  /// <summary>
  /// Minimal DER (X.690) TLV read/write helpers shared by the crypto providers - HPKE PKCS#8
  /// decode, the OS-native key wrapping, and ECDSA signature encoding - so the one
  /// bounds-checked walker and the length/TLV/INTEGER builders are defined once. Definite-form
  /// lengths only (the shapes these keys and signatures use); it is not a general ASN.1 parser.
  /// </summary>
  TDer = class sealed(TObject)
  public
    /// <summary>Walks the TLV at AOffset: its tag, the offset and length of its content, and
    /// the offset of the next TLV. False if the encoding runs past the buffer.</summary>
    class function ReadTlv(const ADer: TBytes; AOffset: Int32; out ATag: Byte;
      out AContentOffset, AContentLen, ANext: Int32): Boolean; static;
    /// <summary>Whether the ALen bytes at AOffset equal the expected OID value bytes.</summary>
    class function OidMatches(const ADer: TBytes; AOffset, ALen: Int32;
      const AExpected: array of Byte): Boolean; static;
    /// <summary>The DER length encoding of ALen (short form, or the minimal long form 0x81-0x84).</summary>
    class function EncodeLength(ALen: Int32): TBytes; static;
    /// <summary>A tag-length-value: ATag, the encoded length of AContent, then AContent.</summary>
    class function Tlv(ATag: Byte; const AContent: TBytes): TBytes; static;
    /// <summary>A DER INTEGER holding AValue as an unsigned big-endian number: minimally
    /// encoded (leading zero bytes dropped) with a 0x00 prepended when the top bit is set.</summary>
    class function IntegerTlv(const AValue: TBytes): TBytes; static;
  end;

implementation

{ TDer }

class function TDer.ReadTlv(const ADer: TBytes; AOffset: Int32; out ATag: Byte;
  out AContentOffset, AContentLen, ANext: Int32): Boolean;
var
  LLen: Int64;
  LN, LI: Int32;
begin
  Result := False;
  ATag := 0;
  AContentOffset := 0;
  AContentLen := 0;
  ANext := 0;
  if (AOffset < 0) or (Int64(AOffset) + 2 > System.Length(ADer)) then
    Exit;
  ATag := ADer[AOffset];
  LLen := ADer[AOffset + 1];
  if (LLen and $80) = 0 then
    AContentOffset := AOffset + 2
  else
  begin
    LN := Int32(LLen) and $7F;
    if (LN = 0) or (LN > 4) or (Int64(AOffset) + 2 + LN > System.Length(ADer)) then
      Exit;
    // accumulate in Int64 so a 4-byte length cannot wrap
    LLen := 0;
    for LI := 0 to LN - 1 do
      LLen := (LLen shl 8) or ADer[AOffset + 2 + LI];
    // reject a non-minimal long form (X.690 10.1, DER)
    if ((LN = 1) and (LLen < $80)) or ((LN >= 2) and (ADer[AOffset + 2] = 0)) then
      Exit;
    AContentOffset := AOffset + 2 + LN;
  end;
  // a length whose content end would overflow Int32 is rejected, not wrapped into a passing range
  if (LLen < 0) or (LLen > Int64(High(Int32)) - AContentOffset) then
    Exit;
  AContentLen := Int32(LLen);
  ANext := AContentOffset + AContentLen;
  Result := ANext <= System.Length(ADer);
end;

class function TDer.OidMatches(const ADer: TBytes; AOffset, ALen: Int32;
  const AExpected: array of Byte): Boolean;
var
  LI: Int32;
begin
  Result := False;
  if ALen <> System.Length(AExpected) then
    Exit;
  for LI := 0 to ALen - 1 do
    if ADer[AOffset + LI] <> AExpected[LI] then
      Exit;
  Result := True;
end;

class function TDer.EncodeLength(ALen: Int32): TBytes;
var
  LWide: TBytes;
  LN: Int32;
begin
  if ALen < $80 then
    Exit(TBytes.Create(Byte(ALen)));
  // long form: the fewest big-endian octets that hold the length (X.690 8.1.3.5, 10.1)
  LWide := nil;
  SetLength(LWide, 4);
  TBinaryPrimitives.WriteUInt32BigEndian(LWide, 0, UInt32(ALen));
  LN := 4;
  while LWide[4 - LN] = 0 do
    System.Dec(LN);
  SetLength(Result, 1 + LN);
  Result[0] := Byte($80 or LN);
  System.Move(LWide[4 - LN], Result[1], LN);
end;

class function TDer.Tlv(ATag: Byte; const AContent: TBytes): TBytes;
var
  LLen: TBytes;
  LN, LM: Int32;
begin
  LLen := EncodeLength(System.Length(AContent));
  LN := System.Length(LLen);
  LM := System.Length(AContent);
  SetLength(Result, 1 + LN + LM);
  Result[0] := ATag;
  Move(LLen[0], Result[1], LN);
  if LM > 0 then
    Move(AContent[0], Result[1 + LN], LM);
end;

class function TDer.IntegerTlv(const AValue: TBytes): TBytes;
var
  LI, LN, LM: Int32;
  LContent: TBytes;
begin
  LN := System.Length(AValue);
  LI := 0;
  // minimal encoding: drop leading zero bytes, but keep at least one
  while (LI < LN - 1) and (AValue[LI] = 0) do
    Inc(LI);
  LM := LN - LI;
  if (LM > 0) and ((AValue[LI] and $80) <> 0) then
  begin
    // top bit set would read as negative: prepend a zero byte
    SetLength(LContent, LM + 1);
    LContent[0] := 0;
    Move(AValue[LI], LContent[1], LM);
  end
  else
  begin
    SetLength(LContent, LM);
    if LM > 0 then
      Move(AValue[LI], LContent[0], LM);
  end;
  Result := Tlv($02, LContent);
end;

end.
