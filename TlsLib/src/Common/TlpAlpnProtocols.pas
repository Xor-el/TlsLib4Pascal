{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpAlpnProtocols;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpArrayUtilities,
  TlpTlsLibExceptions;

type
  /// <summary>ALPN protocol names (RFC 7301 3.1). A name is a sequence of 1..255 opaque octets, so
  /// the library carries it as bytes; this is the text convenience for the usual ASCII names such as
  /// "h2".</summary>
  TAlpnProtocols = class sealed(TObject)
  public
    /// <summary>The octets of an ASCII protocol name. Raises when the name has a character above 127,
    /// which would otherwise be folded onto an ASCII one. The 1..255 length rule is the builder's.</summary>
    class function FromText(const AName: string): TBytes; overload; static;
    class function FromText(const ANames: TArray<string>): TArray<TBytes>; overload; static;
    /// <summary>The name as text. False when it has an octet above 127, which has no text form.</summary>
    class function TryToText(const AName: TBytes; out AText: string): Boolean; static;
    /// <summary>True when the list holds a name with exactly these octets.</summary>
    class function Contains(const AList: TArray<TBytes>; const AName: TBytes): Boolean; static;
    class function H2: TBytes; static;
    class function Http11: TBytes; static;
  end;

implementation

resourcestring
  SAlpnProtocolNotAscii = 'an ALPN protocol name given as text must be ASCII';

{ TAlpnProtocols }

class function TAlpnProtocols.FromText(const AName: string): TBytes;
var
  LI: Int32;
begin
  // the encoder would best-fit a character above 127 onto an ASCII one, so refuse it first
  for LI := 1 to System.Length(AName) do
    if Ord(AName[LI]) > 127 then
      raise EArgumentTlsLibException.CreateRes(@SAlpnProtocolNotAscii);
  Result := TEncoding.ASCII.GetBytes(AName);
end;

class function TAlpnProtocols.FromText(const ANames: TArray<string>): TArray<TBytes>;
var
  LI: Int32;
begin
  System.SetLength(Result, System.Length(ANames));
  for LI := 0 to System.High(ANames) do
    Result[LI] := FromText(ANames[LI]);
end;

class function TAlpnProtocols.TryToText(const AName: TBytes; out AText: string): Boolean;
var
  LI: Int32;
begin
  AText := '';
  Result := False;
  for LI := 0 to System.High(AName) do
    if AName[LI] > 127 then
      Exit;
  AText := TEncoding.ASCII.GetString(AName);
  Result := True;
end;

class function TAlpnProtocols.Contains(const AList: TArray<TBytes>;
  const AName: TBytes): Boolean;
var
  LI: Int32;
begin
  Result := False;
  for LI := 0 to System.High(AList) do
    if TArrayUtilities.AreEqual(AList[LI], AName) then
    begin
      Result := True;
      Exit;
    end;
end;

class function TAlpnProtocols.H2: TBytes;
begin
  Result := FromText('h2');
end;

class function TAlpnProtocols.Http11: TBytes;
begin
  Result := FromText('http/1.1');
end;

end.
