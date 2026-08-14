{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

/// <summary>
/// Accumulates a change-detection signature from heterogeneous inputs - files (by a stat, never a
/// read), scalar flags, injected-object identity, and in-memory byte blobs (by digest). Two equal
/// signatures mean the inputs are unchanged; the signature is used as a memo key so a build (a TLS
/// config, say) is reused until one of its inputs changes. Inputs are the operator's own
/// configuration, never attacker-controlled, so this is change detection, not authentication.
/// </summary>
unit TlpTlsSignatureBuilder;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

interface

uses
  SysUtils,
  TlpCryptoAlgorithms,
  TlpICryptoProvider,
  TlpDataEncoding;

type
  /// <summary>A value type - build it on the stack, feed it, read Value. AProvider is only consulted
  /// by AddBytesDigest (in-memory byte inputs); pass nil when only files/scalars are contributed.</summary>
  TTlsSignatureBuilder = record
  strict private
  var
    FProvider: ICryptoProvider;
    FBuffer: string;
    procedure Append(const APart: string);
  public
    class function Create(const AProvider: ICryptoProvider): TTlsSignatureBuilder; static;
    procedure AddText(const AName, AValue: string);
    procedure AddFlag(const AName: string; AValue: Boolean);
    procedure AddCardinal(const AName: string; AValue: Cardinal);
    /// <summary>
    /// Identity of an injected interface (nil contributes a stable marker). Pointer identity is
    /// sound only under the retain-or-irrelevant rule: each signed input must be either retained
    /// by the built artifact - so its address cannot be recycled while the signature naming it is
    /// live - or ignored by it, so an address reuse still yields an equal build. Do not sign an
    /// interface the build merely samples then drops. AddMethod relies on the same rule.
    /// </summary>
    procedure AddPointer(const AName: string; const AInstance: IInterface);
    /// <summary>Identity of an of-object callback (its code+data pair); see AddPointer's rule.</summary>
    procedure AddMethod(const AName: string; const AMethod: TMethod);
    /// <summary>A file by path + size + mtime - a stat, never a read; a rotated file changes it.
    /// FPC/Unix mtime is second-granularity, so a same-size in-place rewrite within one second of
    /// the last can be missed.</summary>
    procedure AddFile(const AName, APath: string);
    /// <summary>An in-memory byte input by its SHA-256 (needs a provider); empty is a stable marker.</summary>
    procedure AddBytesDigest(const AName: string; const AData: TBytes);
    /// <summary>A secret string by its SHA-256 (needs a provider) - never embeds the value in the
    /// signature; a change still forces a rebuild.</summary>
    procedure AddSecret(const AName, AValue: string);
    function Value: string;
  end;

implementation

const
  FieldSep = #30;  // record separator - keeps field boundaries unambiguous in the signature
  PairSep = #31;   // unit separator - between a field name and its value

{ TTlsSignatureBuilder }

class function TTlsSignatureBuilder.Create(
  const AProvider: ICryptoProvider): TTlsSignatureBuilder;
begin
  Result.FProvider := AProvider;
  Result.FBuffer := '';
end;

procedure TTlsSignatureBuilder.Append(const APart: string);
begin
  // length-prefix each field so no value can alias a field boundary (injective encoding)
  FBuffer := FBuffer + UIntToStr(Cardinal(System.Length(APart))) + ':' + APart + FieldSep;
end;

procedure TTlsSignatureBuilder.AddText(const AName, AValue: string);
begin
  Append(AName + PairSep + AValue);
end;

procedure TTlsSignatureBuilder.AddFlag(const AName: string; AValue: Boolean);
begin
  Append(AName + PairSep + BoolToStr(AValue, True));
end;

procedure TTlsSignatureBuilder.AddCardinal(const AName: string; AValue: Cardinal);
begin
  Append(AName + PairSep + UIntToStr(AValue));
end;

procedure TTlsSignatureBuilder.AddPointer(const AName: string;
  const AInstance: IInterface);
begin
  Append(AName + PairSep + IntToHex(NativeUInt(Pointer(AInstance)), SizeOf(Pointer) * 2));
end;

procedure TTlsSignatureBuilder.AddMethod(const AName: string; const AMethod: TMethod);
begin
  Append(AName + PairSep + IntToHex(NativeUInt(AMethod.Code), SizeOf(Pointer) * 2) +
    ':' + IntToHex(NativeUInt(AMethod.Data), SizeOf(Pointer) * 2));
end;

procedure TTlsSignatureBuilder.AddFile(const AName, APath: string);
var
  LRec: TSearchRec;
begin
  if (APath <> '') and (FindFirst(APath, faAnyFile, LRec) = 0) then
  begin
    Append(AName + PairSep + APath + '|' + IntToStr(LRec.Size) + '|' +
      FormatDateTime('yyyymmddhhnnsszzz', LRec.TimeStamp));
    FindClose(LRec);
  end
  else
    // absent (or unnamed) now: a distinct marker, so a file that later appears changes the value
    Append(AName + PairSep + APath + '|<none>');
end;

procedure TTlsSignatureBuilder.AddBytesDigest(const AName: string;
  const AData: TBytes);
var
  LHash: IHash;
  LDigest: TBytes;
begin
  if System.Length(AData) = 0 then
  begin
    Append(AName + PairSep + '<empty>');
    Exit;
  end;
  LHash := FProvider.CreateHash(THashAlgorithm.SHA_256);
  LHash.Update(AData, 0, System.Length(AData));
  LDigest := LHash.DoFinal;
  Append(AName + PairSep + TDataEncoding.HexEncode(LDigest));
end;

procedure TTlsSignatureBuilder.AddSecret(const AName, AValue: string);
begin
  AddBytesDigest(AName, TEncoding.UTF8.GetBytes(AValue));
end;

function TTlsSignatureBuilder.Value: string;
begin
  Result := FBuffer;
end;

end.
