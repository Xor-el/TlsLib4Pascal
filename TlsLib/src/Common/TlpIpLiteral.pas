{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpIpLiteral;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpBinaryPrimitives;

type
  /// <summary>The text forms of IP addresses: a dotted-quad IPv4 and the RFC 4291 section 2.2
  /// IPv6 representation. Parsing is strict - anything a second parser could read differently is
  /// refused rather than repaired.</summary>
  TIpLiteral = class sealed(TObject)
  public
    /// <summary>The four octets of a dotted quad. False for any other shape, including a part
    /// with a leading zero (a resolver may read it as octal, so the literal is ambiguous).</summary>
    class function TryParseIPv4(const AText: string; out ABytes: TBytes): Boolean; static;
    /// <summary>The sixteen octets of an IPv6 address written without brackets, with at most one
    /// "::" and an optional trailing embedded IPv4 (RFC 4291 2.2). False for any other
    /// shape.</summary>
    class function TryParseIPv6(const AText: string; out ABytes: TBytes): Boolean; static;
  end;

implementation

{ TIpLiteral }

class function TIpLiteral.TryParseIPv4(const AText: string;
  out ABytes: TBytes): Boolean;
var
  LParts: TArray<string>;
  LPart: string;
  LI, LValue, LDigit: Int32;
begin
  ABytes := nil;
  Result := False;
  LParts := AText.Split(['.']);
  if System.Length(LParts) <> 4 then
    Exit;
  SetLength(ABytes, 4);
  for LI := 0 to 3 do
  begin
    LPart := LParts[LI];
    if (System.Length(LPart) < 1) or (System.Length(LPart) > 3) then
      Exit;
    // a leading zero reads as octal to a resolver, so the literal is ambiguous
    if (System.Length(LPart) > 1) and (LPart[1] = '0') then
      Exit;
    LValue := 0;
    for LDigit := 1 to System.Length(LPart) do
    begin
      if (LPart[LDigit] < '0') or (LPart[LDigit] > '9') then
        Exit;
      LValue := (LValue * 10) + (Ord(LPart[LDigit]) - Ord('0'));
    end;
    if LValue > 255 then
      Exit;
    ABytes[LI] := Byte(LValue);
  end;
  Result := True;
end;

class function TIpLiteral.TryParseIPv6(const AText: string;
  out ABytes: TBytes): Boolean;
var
  LHead, LTail: TArray<UInt16>;
  LDoubleColon: Int32;
  LEmbedded: TBytes;

  // an embedded IPv4 supplies the low-order 32 bits (RFC 4291 2.2), so only the side of the
  // address that ends it may carry one
  function ParseGroups(const AGroups: string; AEndsAddress: Boolean;
    out AValues: TArray<UInt16>): Boolean;
  var
    LParts: TArray<string>;
    LI, LJ, LV, LCount: Int32;
    LPart: string;
  begin
    AValues := nil;
    Result := False;
    if AGroups = '' then
      Exit(True); // an empty side of "::" contributes no groups
    LParts := AGroups.Split([':']);
    LCount := 0;
    for LI := 0 to High(LParts) do
    begin
      LPart := LParts[LI];
      // a trailing embedded IPv4 (e.g. ::ffff:1.2.3.4) only in the final group
      if (LI = High(LParts)) and (Pos('.', LPart) > 0) then
      begin
        if (not AEndsAddress) or (not TryParseIPv4(LPart, LEmbedded)) then
          Exit;
        SetLength(AValues, LCount + 2);
        AValues[LCount] := TBinaryPrimitives.ReadUInt16BigEndian(LEmbedded, 0);
        AValues[LCount + 1] := TBinaryPrimitives.ReadUInt16BigEndian(LEmbedded, 2);
        Inc(LCount, 2);
        Continue;
      end;
      if (System.Length(LPart) < 1) or (System.Length(LPart) > 4) then
        Exit;
      LV := 0;
      for LJ := 1 to System.Length(LPart) do
      begin
        case LPart[LJ] of
          '0' .. '9':
            LV := (LV shl 4) or (Ord(LPart[LJ]) - Ord('0'));
          'a' .. 'f':
            LV := (LV shl 4) or (Ord(LPart[LJ]) - Ord('a') + 10);
          'A' .. 'F':
            LV := (LV shl 4) or (Ord(LPart[LJ]) - Ord('A') + 10);
        else
          Exit;
        end;
      end;
      SetLength(AValues, LCount + 1);
      AValues[LCount] := UInt16(LV);
      Inc(LCount);
    end;
    Result := True;
  end;

var
  LAll: TArray<UInt16>;
  LI, LPos, LFill: Int32;
begin
  ABytes := nil;
  Result := False;
  if Pos(':', AText) = 0 then
    Exit;
  LDoubleColon := Pos('::', AText);
  if LDoubleColon > 0 then
  begin
    if Pos('::', System.Copy(AText, LDoubleColon + 1, MaxInt)) > 0 then
      Exit;
    if not ParseGroups(System.Copy(AText, 1, LDoubleColon - 1), False, LHead) then
      Exit;
    if not ParseGroups(System.Copy(AText, LDoubleColon + 2, MaxInt), True, LTail) then
      Exit;
    if System.Length(LHead) + System.Length(LTail) >= 8 then
      Exit; // "::" must stand for at least one zero group
    SetLength(LAll, 8);
    for LI := 0 to High(LHead) do
      LAll[LI] := LHead[LI];
    LFill := 8 - System.Length(LTail);
    for LI := 0 to High(LTail) do
      LAll[LFill + LI] := LTail[LI];
  end
  else
  begin
    if not ParseGroups(AText, True, LAll) then
      Exit;
    if System.Length(LAll) <> 8 then
      Exit;
  end;
  SetLength(ABytes, 16);
  LPos := 0;
  for LI := 0 to 7 do
  begin
    TBinaryPrimitives.WriteUInt16BigEndian(ABytes, LPos, LAll[LI]);
    Inc(LPos, 2);
  end;
  Result := True;
end;

end.
