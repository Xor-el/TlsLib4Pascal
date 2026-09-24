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
  public
    /// <summary>Seals APlaintext whole; returns ciphertext followed by the tag.</summary>
    class function Seal(const AAead: IAead; const ANonce, AAad,
      APlaintext: TBytes): TBytes; static;
    /// <summary>Opens ciphertext||tag whole; returns the plaintext, raising on auth failure.</summary>
    class function Open(const AAead: IAead; const ANonce, AAad,
      ACiphertext: TBytes): TBytes; static;
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
  AAead.Seal(ANonce, AAad, APlaintext, 0, LPlainLen, Result, 0);
end;

class function TAeadUtilities.Open(const AAead: IAead; const ANonce, AAad,
  ACiphertext: TBytes): TBytes;
var
  LCipherLen, LPlainLen: Int32;
begin
  LCipherLen := System.Length(ACiphertext);
  LPlainLen := LCipherLen - AAead.TagSize;
  if LPlainLen < 0 then
    LPlainLen := 0; // a too-short input cannot authenticate; let Open surface bad_record_mac
  Result := nil;
  SetLength(Result, LPlainLen);
  AAead.Open(ANonce, AAad, ACiphertext, 0, LCipherLen, Result, 0);
end;

end.
