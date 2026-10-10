{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpHttpUrl;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpIpLiteral;

type
  THttpScheme = (Http, Https);

  THttpHostKind = (DnsName, IPv4, IPv6);

  /// <summary>An absolute http or https URL (RFC 9110 4.2.1, 4.2.2), parsed strictly: in the scheme,
  /// authority, port and character set, anything a second parser could read differently is
  /// refused rather than repaired. Dot segments in the path are neither refused nor removed. A
  /// value of this type is the only URL text the library fetches, and ToString is the text it
  /// sends.</summary>
  THttpUrl = record
  strict private
    FScheme: THttpScheme;
    FHost: string;
    FHostKind: THttpHostKind;
    FPort: UInt16;
    FPathAndQuery: string;
    class function IsUrlChar(AChar: Char): Boolean; static;
    class function TryParseHost(const AHost: string; out AKind: THttpHostKind): Boolean; static;
    class function TryParsePort(const APort: string; ADefault: UInt16;
      out APortValue: UInt16): Boolean; static;
  public
    /// <summary>False for anything but a well-formed absolute http(s) URL: another scheme, userinfo,
    /// an empty or malformed host (including a trailing dot or a numeric-looking name), a bad port,
    /// a control character, backslash or non-ASCII character, a square bracket outside an IPv6
    /// host, a bad percent-encoding, or more than 8000 characters (the length RFC 9110 4.1 asks
    /// recipients to support).</summary>
    class function TryParse(const AText: string; out AUrl: THttpUrl): Boolean; static;
    /// <summary>The port a scheme implies when none is written (RFC 9110 4.2.1, 4.2.2).</summary>
    class function DefaultPort(AScheme: THttpScheme): UInt16; static;
    function Scheme: THttpScheme;
    /// <summary>The host in lower case; an IPv6 literal without its brackets.</summary>
    function Host: string;
    function HostKind: THttpHostKind;
    /// <summary>The effective port, the scheme's default when none was written.</summary>
    function Port: UInt16;
    /// <summary>The path and query, starting with '/'; the fragment is not part of it (RFC 9110
    /// 7.1).</summary>
    function PathAndQuery: string;
    /// <summary>The canonical text: lower-case scheme and host, the default port omitted, an empty
    /// path as '/', upper-case hex digits in percent-encodings (RFC 3986 2.1, 6.2.2.1, 6.2.3), no
    /// fragment (RFC 9110 7.1); a default port and an empty path are equivalent spellings
    /// (RFC 9110 4.2.3). Spellings that differ only in those ways have equal text, so it is both
    /// the de-duplication key and the request target.</summary>
    function ToString: string;
  end;

implementation

const
  MaxUrlLength = 8000;
  MaxPortDigits = 5;
  MaxHostLength = 253;
  MaxLabelLength = 63;

{ THttpUrl }

class function THttpUrl.IsUrlChar(AChar: Char): Boolean;
begin
  // unreserved, gen-delims and sub-delims (RFC 3986 2.2, 2.3) plus '%'; a space, a control
  // character, a backslash and anything non-ASCII fall outside
  Result := CharInSet(AChar, ['a' .. 'z', 'A' .. 'Z', '0' .. '9', '-', '.', '_', '~', ':', '/',
    '?', '#', '[', ']', '@', '!', '$', '&', '''', '(', ')', '*', '+', ',', ';', '=', '%']);
end;

class function THttpUrl.DefaultPort(AScheme: THttpScheme): UInt16;
begin
  if AScheme = THttpScheme.Https then
    Result := 443
  else
    Result := 80;
end;

class function THttpUrl.TryParseHost(const AHost: string; out AKind: THttpHostKind): Boolean;
var
  LBytes: TBytes;
  LI, LLabelStart: Int32;
begin
  AKind := THttpHostKind.DnsName;
  Result := False;
  if (AHost = '') or (System.Length(AHost) > MaxHostLength) then
    Exit;
  if TIpLiteral.TryParseIPv4(AHost, LBytes) then
  begin
    AKind := THttpHostKind.IPv4;
    Exit(True);
  end;
  // LDH labels only: no percent-encoding, no underscore, no empty label
  LLabelStart := 1;
  for LI := 1 to System.Length(AHost) do
    if AHost[LI] = '.' then
    begin
      if (LI = LLabelStart) or (LI - LLabelStart > MaxLabelLength) then
        Exit;
      LLabelStart := LI + 1;
    end
    else if not (((AHost[LI] >= 'a') and (AHost[LI] <= 'z')) or
      ((AHost[LI] >= 'A') and (AHost[LI] <= 'Z')) or ((AHost[LI] >= '0') and (AHost[LI] <= '9')) or
      (AHost[LI] = '-')) then
      Exit;
  if (LLabelStart > System.Length(AHost)) or
    (System.Length(AHost) + 1 - LLabelStart > MaxLabelLength) then
    Exit;
  // a name whose last label starts with a digit is read as a (decimal, octal or hex) number by
  // some resolvers and URL parsers, so the same text would name two different hosts
  if (AHost[LLabelStart] >= '0') and (AHost[LLabelStart] <= '9') then
    Exit;
  Result := True;
end;

class function THttpUrl.TryParsePort(const APort: string; ADefault: UInt16;
  out APortValue: UInt16): Boolean;
var
  LI, LValue: Int32;
begin
  APortValue := ADefault;
  Result := False;
  // an empty port is the default (RFC 3986 3.2.3, 6.2.3)
  if APort = '' then
    Exit(True);
  if System.Length(APort) > MaxPortDigits then
    Exit;
  LValue := 0;
  for LI := 1 to System.Length(APort) do
  begin
    if (APort[LI] < '0') or (APort[LI] > '9') then
      Exit;
    LValue := (LValue * 10) + (Ord(APort[LI]) - Ord('0'));
  end;
  if (LValue < 1) or (LValue > 65535) then
    Exit;
  APortValue := UInt16(LValue);
  Result := True;
end;

class function THttpUrl.TryParse(const AText: string; out AUrl: THttpUrl): Boolean;
var
  LAuthorityStart, LAuthorityEnd, LFragment, LClose, LColon, LI: Int32;
  LAuthority, LHostPart, LPortPart, LRest: string;
  LScheme: THttpScheme;
  LKind: THttpHostKind;
  LPort: UInt16;
  LBytes: TBytes;
begin
  AUrl := Default(THttpUrl);
  Result := False;
  if (AText = '') or (System.Length(AText) > MaxUrlLength) then
    Exit;
  for LI := 1 to System.Length(AText) do
    if not IsUrlChar(AText[LI]) then
      Exit
    else if AText[LI] = '%' then
      if (LI + 2 > System.Length(AText)) or
        not CharInSet(AText[LI + 1], ['0' .. '9', 'a' .. 'f', 'A' .. 'F']) or
        not CharInSet(AText[LI + 2], ['0' .. '9', 'a' .. 'f', 'A' .. 'F']) then
        Exit;
  // the scheme is case-insensitive (RFC 3986 3.1) and only http and https are ever fetched
  if SameText(System.Copy(AText, 1, 7), 'http://') then
  begin
    LScheme := THttpScheme.Http;
    LAuthorityStart := 8;
  end
  else if SameText(System.Copy(AText, 1, 8), 'https://') then
  begin
    LScheme := THttpScheme.Https;
    LAuthorityStart := 9;
  end
  else
    Exit;
  LAuthorityEnd := LAuthorityStart;
  while (LAuthorityEnd <= System.Length(AText)) and (AText[LAuthorityEnd] <> '/') and
    (AText[LAuthorityEnd] <> '?') and (AText[LAuthorityEnd] <> '#') do
    Inc(LAuthorityEnd);
  LAuthority := System.Copy(AText, LAuthorityStart, LAuthorityEnd - LAuthorityStart);
  // userinfo in a URL from an untrusted source is an error (RFC 9110 4.2.4)
  if Pos('@', LAuthority) > 0 then
    Exit;
  if (LAuthority <> '') and (LAuthority[1] = '[') then
  begin
    LClose := Pos(']', LAuthority);
    if LClose = 0 then
      Exit;
    LHostPart := System.Copy(LAuthority, 2, LClose - 2);
    LPortPart := System.Copy(LAuthority, LClose + 1, MaxInt);
    if LPortPart <> '' then
    begin
      if LPortPart[1] <> ':' then
        Exit;
      LPortPart := System.Copy(LPortPart, 2, MaxInt);
    end;
    // a zone identifier (RFC 6874 syntax) and IPvFuture have no place in a responder URL; the strict
    // parser also refuses anything that is not an RFC 4291 address
    if (Pos('%', LHostPart) > 0) or not TIpLiteral.TryParseIPv6(LHostPart, LBytes) then
      Exit;
    LKind := THttpHostKind.IPv6;
  end
  else
  begin
    LColon := Pos(':', LAuthority);
    if LColon > 0 then
    begin
      LHostPart := System.Copy(LAuthority, 1, LColon - 1);
      LPortPart := System.Copy(LAuthority, LColon + 1, MaxInt);
    end
    else
    begin
      LHostPart := LAuthority;
      LPortPart := '';
    end;
    if not TryParseHost(LHostPart, LKind) then
      Exit;
  end;
  if not TryParsePort(LPortPart, DefaultPort(LScheme), LPort) then
    Exit;
  // the fragment is never part of the request target (RFC 9110 7.1)
  LRest := System.Copy(AText, LAuthorityEnd, MaxInt);
  // square brackets belong to an IP-literal host only; clients disagree on them in a path or query
  // (RFC 3986 3.3, 3.4)
  if (Pos('[', LRest) > 0) or (Pos(']', LRest) > 0) then
    Exit;
  // percent-encodings are compared by their upper-case form (RFC 3986 2.1, 6.2.2.1)
  for LI := 1 to System.Length(LRest) do
    if LRest[LI] = '%' then
    begin
      LRest[LI + 1] := UpCase(LRest[LI + 1]);
      LRest[LI + 2] := UpCase(LRest[LI + 2]);
    end;
  LFragment := Pos('#', LRest);
  if LFragment > 0 then
    LRest := System.Copy(LRest, 1, LFragment - 1);
  if (LRest = '') or (LRest[1] = '?') then
    LRest := '/' + LRest;
  AUrl.FScheme := LScheme;
  AUrl.FHostKind := LKind;
  AUrl.FPort := LPort;
  AUrl.FHost := LowerCase(LHostPart);
  AUrl.FPathAndQuery := LRest;
  Result := True;
end;

function THttpUrl.Scheme: THttpScheme;
begin
  Result := FScheme;
end;

function THttpUrl.Host: string;
begin
  Result := FHost;
end;

function THttpUrl.HostKind: THttpHostKind;
begin
  Result := FHostKind;
end;

function THttpUrl.Port: UInt16;
begin
  Result := FPort;
end;

function THttpUrl.PathAndQuery: string;
begin
  Result := FPathAndQuery;
end;

function THttpUrl.ToString: string;
begin
  if FScheme = THttpScheme.Https then
    Result := 'https://'
  else
    Result := 'http://';
  if FHostKind = THttpHostKind.IPv6 then
    Result := Result + '[' + FHost + ']'
  else
    Result := Result + FHost;
  if FPort <> DefaultPort(FScheme) then
    Result := Result + ':' + IntToStr(FPort);
  Result := Result + FPathAndQuery;
end;

end.
