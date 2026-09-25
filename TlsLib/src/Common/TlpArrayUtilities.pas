{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpArrayUtilities;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  Generics.Defaults;

type
  /// <summary>Extracts an array element's key for a keyed search.</summary>
  TKeyOf<T, TKey> = function(const AItem: T): TKey;

  /// <summary>Small array helpers shared across the library.</summary>
  TArrayUtilities = class sealed(TObject)
  public
    /// <summary>A fresh array holding AA followed by AB.</summary>
    class function Concat(const AA, AB: TBytes): TBytes; overload; static;
    /// <summary>A fresh array holding every element of AArrays in order.</summary>
    class function Concat(const AArrays: array of TBytes): TBytes; overload; static;
    /// <summary>Variable-time all-zero test (early-exit); non-secret data only.
    /// An empty array counts as all-zero. The constant-time twin is
    /// <see cref="TSecureMemory.ConstantTimeIsAllZero" />.</summary>
    class function IsAllZero(const AData: TBytes): Boolean; static;
    /// <summary>Variable-time byte-array equality; use only on public (non-secret)
    /// data. The constant-time twin is
    /// <see cref="TSecureMemory.ConstantTimeAreEqual" />.</summary>
    class function AreEqual(const AA, AB: TBytes): Boolean; static;

    /// <summary>Appends AValue, growing AItems by one.</summary>
    class procedure Append<T>(var AItems: TArray<T>; const AValue: T); static;
    /// <summary>A fresh array holding every element of AA followed by AB.</summary>
    class function Concat<T>(const AA, AB: TArray<T>): TArray<T>; overload; static;
    /// <summary>A deep copy of an array of arrays: a new outer array whose every inner array is
    /// itself copied, so the result shares no storage with A (unlike a shallow System.Copy, which
    /// copies only the outer array and leaves the inner arrays aliased).</summary>
    class function DeepCopy<T>(const A: TArray<TArray<T>>): TArray<TArray<T>>; static;
    /// <summary>Removes every element whose key equals AKey, compacting in place.</summary>
    class procedure RemoveKey<T, TKey>(var AItems: TArray<T>;
      const AKeyOf: TKeyOf<T, TKey>; const AKey: TKey); static;
    /// <summary>Whether AItems holds AValue.</summary>
    class function Contains<T>(const AItems: TArray<T>; const AValue: T): Boolean;
      static;
    /// <summary>The index of the first element whose key is AKey, or -1.</summary>
    class function IndexOfKey<T, TKey>(const AItems: TArray<T>;
      const AKeyOf: TKeyOf<T, TKey>; const AKey: TKey): Int32; static;
    /// <summary>Whether any element's key is AKey.</summary>
    class function ContainsKey<T, TKey>(const AItems: TArray<T>;
      const AKeyOf: TKeyOf<T, TKey>; const AKey: TKey): Boolean; static;
  end;

implementation

{ TArrayUtilities }

class function TArrayUtilities.Concat(const AA, AB: TBytes): TBytes;
begin
  Result := nil;
  SetLength(Result, System.Length(AA) + System.Length(AB));
  if System.Length(AA) > 0 then
    Move(AA[0], Result[0], System.Length(AA));
  if System.Length(AB) > 0 then
    Move(AB[0], Result[System.Length(AA)], System.Length(AB));
end;

class function TArrayUtilities.IsAllZero(const AData: TBytes): Boolean;
var
  LI: Int32;
begin
  for LI := 0 to System.Length(AData) - 1 do
    if AData[LI] <> 0 then
      Exit(False);
  Result := True;
end;

class function TArrayUtilities.AreEqual(const AA, AB: TBytes): Boolean;
var
  LI: Int32;
begin
  Result := False;
  if System.Length(AA) <> System.Length(AB) then
    Exit;
  for LI := 0 to System.Length(AA) - 1 do
    if AA[LI] <> AB[LI] then
      Exit;
  Result := True;
end;

class procedure TArrayUtilities.Append<T>(var AItems: TArray<T>; const AValue: T);
begin
  SetLength(AItems, Length(AItems) + 1);
  AItems[High(AItems)] := AValue;
end;

class function TArrayUtilities.Concat<T>(const AA, AB: TArray<T>): TArray<T>;
var
  LI, LLenA, LLenB: Int32;
begin
  Result := nil;
  LLenA := Length(AA);
  LLenB := Length(AB);
  SetLength(Result, LLenA + LLenB);
  for LI := 0 to LLenA - 1 do
    Result[LI] := AA[LI];
  for LI := 0 to LLenB - 1 do
    Result[LLenA + LI] := AB[LI];
end;

class function TArrayUtilities.DeepCopy<T>(
  const A: TArray<TArray<T>>): TArray<TArray<T>>;
var
  LI: Int32;
begin
  Result := nil;
  SetLength(Result, System.Length(A));
  for LI := 0 to System.High(A) do
    Result[LI] := System.Copy(A[LI]);
end;

class procedure TArrayUtilities.RemoveKey<T, TKey>(var AItems: TArray<T>;
  const AKeyOf: TKeyOf<T, TKey>; const AKey: TKey);
var
  LI, LOut: Int32;
  LComparer: IEqualityComparer<TKey>;
begin
  LComparer := TEqualityComparer<TKey>.Default;
  LOut := 0;
  for LI := 0 to Length(AItems) - 1 do
    if not LComparer.Equals(AKeyOf(AItems[LI]), AKey) then
    begin
      AItems[LOut] := AItems[LI];
      Inc(LOut);
    end;
  SetLength(AItems, LOut);
end;

class function TArrayUtilities.Contains<T>(const AItems: TArray<T>;
  const AValue: T): Boolean;
var
  LI: Int32;
  LComparer: IEqualityComparer<T>;
begin
  Result := False;
  LComparer := TEqualityComparer<T>.Default;
  for LI := 0 to Length(AItems) - 1 do
    if LComparer.Equals(AItems[LI], AValue) then
      Exit(True);
end;

class function TArrayUtilities.IndexOfKey<T, TKey>(const AItems: TArray<T>;
  const AKeyOf: TKeyOf<T, TKey>; const AKey: TKey): Int32;
var
  LI: Int32;
  LComparer: IEqualityComparer<TKey>;
begin
  Result := -1;
  LComparer := TEqualityComparer<TKey>.Default;
  for LI := 0 to Length(AItems) - 1 do
    if LComparer.Equals(AKeyOf(AItems[LI]), AKey) then
      Exit(LI);
end;

class function TArrayUtilities.ContainsKey<T, TKey>(const AItems: TArray<T>;
  const AKeyOf: TKeyOf<T, TKey>; const AKey: TKey): Boolean;
begin
  Result := IndexOfKey<T, TKey>(AItems, AKeyOf, AKey) >= 0;
end;

class function TArrayUtilities.Concat(const AArrays: array of TBytes): TBytes;
var
  LTotal, LPos, LI, LLen: Int32;
begin
  Result := nil;
  LTotal := 0;
  for LI := 0 to System.Length(AArrays) - 1 do
    Inc(LTotal, System.Length(AArrays[LI]));
  SetLength(Result, LTotal);
  LPos := 0;
  for LI := 0 to System.Length(AArrays) - 1 do
  begin
    LLen := System.Length(AArrays[LI]);
    if LLen > 0 then
    begin
      Move(AArrays[LI][0], Result[LPos], LLen);
      Inc(LPos, LLen);
    end;
  end;
end;

end.
