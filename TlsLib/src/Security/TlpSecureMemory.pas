{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpSecureMemory;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils;

type
  /// <summary>
  /// Secret-safe memory primitives: zeroization and constant-time comparisons.
  /// The constant-time helpers are the secret/tag/MAC-safe twins of the variable-
  /// time array helpers in <c>TArrayUtilities</c>.
  /// </summary>
  TSecureMemory = class sealed(TObject)
  public
    /// <summary>Zeroizes ALen bytes at APtr; a no-op for nil / non-positive length.</summary>
    class procedure Wipe(APtr: Pointer; ALen: NativeInt); static;
    /// <summary>Zeroizes then clears a transient byte array (e.g. a secret copy).</summary>
    class procedure WipeBytes(var AData: TBytes); static;
    /// <summary>
    /// Compares ALen bytes at APtrA and APtrB in constant time (no early exit),
    /// so the running time does not leak how many leading bytes matched. Use for
    /// any secret / tag / MAC equality check.
    /// </summary>
    class function ConstantTimeAreEqual(APtrA, APtrB: Pointer; ALen: NativeInt): Boolean;
      overload; static;
    /// <summary>Constant-time equality of two byte arrays; differing lengths compare
    /// unequal and an empty pair compares equal. Neither array is modified - the
    /// caller wipes any secret operand itself.</summary>
    class function ConstantTimeAreEqual(const AA, AB: TBytes): Boolean; overload; static;
    /// <summary>Constant-time all-zero test (OR-accumulate, no early exit) for
    /// secret-dependent data. An empty array counts as all-zero.</summary>
    class function ConstantTimeIsAllZero(const AData: TBytes): Boolean; static;
    /// <summary>Constant-time twin of <see cref="TArrayUtilities.CompareLexicographic" /> for
    /// secret data: negative, zero or positive as AA sorts before, equal to or after AB, with no
    /// early exit over the common prefix. Only the lengths, which are public, decide a tie.</summary>
    class function ConstantTimeCompareLexicographic(const AA, AB: TBytes): Int32; static;
  end;

implementation

{ TSecureMemory }

class procedure TSecureMemory.Wipe(APtr: Pointer; ALen: NativeInt);
begin
  if (APtr = nil) or (ALen <= 0) then
    Exit;
  FillChar(APtr^, ALen, 0);
end;

class procedure TSecureMemory.WipeBytes(var AData: TBytes);
begin
  if System.Length(AData) > 0 then
    Wipe(@AData[0], System.Length(AData));
  AData := nil;
end;

class function TSecureMemory.ConstantTimeAreEqual(APtrA, APtrB: Pointer;
  ALen: NativeInt): Boolean;
var
  LA, LB: PByte;
  LI: NativeInt;
  LDiff: Byte;
begin
  LA := PByte(APtrA);
  LB := PByte(APtrB);
  LDiff := 0;
  for LI := 0 to ALen - 1 do
    LDiff := LDiff or (LA[LI] xor LB[LI]);
  Result := LDiff = 0;
end;

class function TSecureMemory.ConstantTimeAreEqual(const AA, AB: TBytes): Boolean;
begin
  if System.Length(AA) <> System.Length(AB) then
    Result := False
  else if System.Length(AA) = 0 then
    Result := True
  else
    Result := ConstantTimeAreEqual(@AA[0], @AB[0], System.Length(AA));
end;

class function TSecureMemory.ConstantTimeIsAllZero(const AData: TBytes): Boolean;
var
  LI: Int32;
  LAcc: Byte;
begin
  LAcc := 0;
  for LI := 0 to System.Length(AData) - 1 do
    LAcc := LAcc or AData[LI];
  Result := LAcc = 0;
end;

class function TSecureMemory.ConstantTimeCompareLexicographic(const AA, AB: TBytes): Int32;
var
  LI, LCommon, LLengthOrder: Int32;
  LLess, LGreater, LOpen: UInt32;
begin
  LCommon := System.Length(AA);
  if System.Length(AB) < LCommon then
    LCommon := System.Length(AB);
  LLess := 0;
  LGreater := 0;
  for LI := 0 to LCommon - 1 do
  begin
    // the first differing byte decides; later bytes fold in under a closed mask
    LOpen := (LLess or LGreater) xor 1;
    LLess := LLess or ((UInt32(Int32(AA[LI]) - Int32(AB[LI])) shr 31) and LOpen);
    LGreater := LGreater or ((UInt32(Int32(AB[LI]) - Int32(AA[LI])) shr 31) and LOpen);
  end;
  LLengthOrder := Ord(System.Length(AA) > System.Length(AB)) -
    Ord(System.Length(AA) < System.Length(AB));
  Result := Int32(LGreater) - Int32(LLess) +
    LLengthOrder * Int32((LLess or LGreater) xor 1);
end;

end.
