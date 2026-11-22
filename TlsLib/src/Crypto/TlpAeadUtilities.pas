{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpAeadUtilities;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpICryptoProvider;

type
  /// <summary>Allocating convenience over the in-place <see cref="IAead" /> seam, for cold paths
  /// that do not reuse a buffer (HPKE, session tickets, tests): seals/opens a whole array and
  /// returns a fresh result.</summary>
  TAeadUtilities = class sealed(TObject)
  strict private
    class function PlainBuffer(const AAead: IAead; ACipherLen: Int32): TBytes; static;
  public
    /// <summary>Seals APlaintext whole; returns ciphertext followed by the tag.</summary>
    class function Seal(const AAead: IAead; const ANonce, AAad,
      APlaintext: TBytes): TBytes; static;
    /// <summary>Opens ciphertext||tag whole; returns the plaintext, raising on auth failure.</summary>
    class function Open(const AAead: IAead; const ANonce, AAad,
      ACiphertext: TBytes): TBytes; static;
    /// <summary>As <see cref="Open" />, but False (APlaintext nil) on an authentication failure
    /// instead of raising.</summary>
    class function TryOpen(const AAead: IAead; const ANonce, AAad, ACiphertext: TBytes;
      out APlaintext: TBytes): Boolean; static;
  end;

implementation

class function TAeadUtilities.Seal(const AAead: IAead; const ANonce, AAad,
  APlaintext: TBytes): TBytes;
var
  LPlainLen: Int32;
begin
  LPlainLen := System.Length(APlaintext);
  Result := nil;
  SetLength(Result, LPlainLen + AAead.TagSize);
  AAead.Seal(ANonce, AAad, 0, System.Length(AAad), APlaintext, 0, LPlainLen, Result, 0);
end;

class function TAeadUtilities.PlainBuffer(const AAead: IAead; ACipherLen: Int32): TBytes;
var
  LPlainLen: Int32;
begin
  LPlainLen := ACipherLen - AAead.TagSize;
  if LPlainLen < 0 then
    LPlainLen := 0; // a too-short input cannot authenticate; Open and TryOpen report it
  Result := nil;
  SetLength(Result, LPlainLen);
end;

class function TAeadUtilities.Open(const AAead: IAead; const ANonce, AAad,
  ACiphertext: TBytes): TBytes;
begin
  Result := PlainBuffer(AAead, System.Length(ACiphertext));
  AAead.Open(ANonce, AAad, 0, System.Length(AAad), ACiphertext, 0, System.Length(ACiphertext),
    Result, 0);
end;

class function TAeadUtilities.TryOpen(const AAead: IAead; const ANonce, AAad,
  ACiphertext: TBytes; out APlaintext: TBytes): Boolean;
var
  LWritten: Int32;
begin
  APlaintext := PlainBuffer(AAead, System.Length(ACiphertext));
  Result := AAead.TryOpen(ANonce, AAad, 0, System.Length(AAad), ACiphertext, 0,
    System.Length(ACiphertext), APlaintext, 0, LWritten);
  if not Result then
    APlaintext := nil;
end;

end.
