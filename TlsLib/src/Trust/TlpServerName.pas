{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpServerName;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpBinaryPrimitives;

type
  /// <summary>Whether a server name is a DNS host or an IP-address literal.</summary>
  TServerNameKind = (Dns, Ip);

  /// <summary>
  /// The identity a client verifies a server certificate against - a DNS host or an
  /// IP literal. The empty value (IsEmpty) means no identity is present: it arises only
  /// when name-checking is disabled or in a role that verifies no name (client auth).
  /// Whenever name-checking is enabled the engine factory fails closed at creation on an
  /// unusable host, so a checking server-cert verifier never sees an empty name; a
  /// verifier that does receive one must treat it as a match failure.
  /// TryParse classifies the caller's host string once - an IP literal (v4 or v6,
  /// optionally bracketed) becomes Ip with the raw octets; anything else that is a
  /// syntactically usable host becomes Dns (a trailing dot is trimmed). An IPv6-
  /// shaped string that does not parse is rejected rather than treated as DNS.
  /// A DNS name drives SNI and dNSName SAN matching; an IP literal drives iPAddress
  /// SAN matching and is never sent in SNI (RFC 6066 sec. 3).
  /// </summary>
  TServerName = record
  strict private
    FKind: TServerNameKind;
    FDnsName: string;
    FIpBytes: TBytes;
    class function TryParseIPv4(const AHost: string; out ABytes: TBytes): Boolean; static;
    class function TryParseIPv6(const AHost: string; out ABytes: TBytes): Boolean; static;
  public
    /// <summary>Parses AHost into a server name. False (and an unusable result) when
    /// AHost is empty, an unparsable IPv6-shaped literal, or otherwise not a usable
    /// host. IPv6 literals may be bracketed (<c>[::1]</c>).</summary>
    class function TryParse(const AHost: string; out AName: TServerName): Boolean; static;
    /// <summary>A DNS server name. The caller guarantees a non-empty DNS host (e.g.
    /// an already-validated ECH public_name); use TryParse for untrusted input.</summary>
    class function DnsName(const AHost: string): TServerName; static;
    /// <summary>Whether this name is an IP-address literal (never carried in SNI).</summary>
    function IsIp: Boolean;
    /// <summary>Whether this name carries no identity - a name-check is disabled or the
    /// role verifies no name. A checking server-cert verifier treats this as a match
    /// failure; it cannot occur while name-checking is enabled.</summary>
    function IsEmpty: Boolean;
    /// <summary>The DNS host (empty when IsIp).</summary>
    function AsDns: string;
    /// <summary>The raw IP octets, 4 or 16 bytes (nil when not IsIp).</summary>
    function AsIpBytes: TBytes;
    /// <summary>The original host text, for host-facing bridges and cache keys.</summary>
    function ToString: string;
    property Kind: TServerNameKind read FKind;
  end;

implementation

{ TServerName }

class function TServerName.TryParseIPv4(const AHost: string;
  out ABytes: TBytes): Boolean;
var
  LParts: TArray<string>;
  LPart: string;
  LI, LValue, LDigit: Int32;
begin
  ABytes := nil;
  Result := False;
  LParts := AHost.Split(['.']);
  if System.Length(LParts) <> 4 then
    Exit;
  SetLength(ABytes, 4);
  for LI := 0 to 3 do
  begin
    LPart := LParts[LI];
    if (System.Length(LPart) < 1) or (System.Length(LPart) > 3) then
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

class function TServerName.TryParseIPv6(const AHost: string;
  out ABytes: TBytes): Boolean;
var
  LHead, LTail: TArray<UInt16>;
  LDoubleColon: Int32;
  LEmbedded: TBytes;

  function ParseGroups(const AText: string; out AValues: TArray<UInt16>): Boolean;
  var
    LParts: TArray<string>;
    LI, LJ, LV, LCount: Int32;
    LPart: string;
  begin
    AValues := nil;
    Result := False;
    if AText = '' then
      Exit(True); // an empty side of "::" contributes no groups
    LParts := AText.Split([':']);
    LCount := 0;
    for LI := 0 to High(LParts) do
    begin
      LPart := LParts[LI];
      // a trailing embedded IPv4 (e.g. ::ffff:1.2.3.4) only in the final group
      if (LI = High(LParts)) and (Pos('.', LPart) > 0) then
      begin
        if not TryParseIPv4(LPart, LEmbedded) then
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
  if Pos(':', AHost) = 0 then
    Exit;
  LDoubleColon := Pos('::', AHost);
  if LDoubleColon > 0 then
  begin
    if Pos('::', System.Copy(AHost, LDoubleColon + 1, MaxInt)) > 0 then
      Exit;
    if not ParseGroups(System.Copy(AHost, 1, LDoubleColon - 1), LHead) then
      Exit;
    if not ParseGroups(System.Copy(AHost, LDoubleColon + 2, MaxInt), LTail) then
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
    if not ParseGroups(AHost, LAll) then
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

class function TServerName.TryParse(const AHost: string;
  out AName: TServerName): Boolean;
var
  LHost: string;
  LBytes: TBytes;
begin
  AName := Default(TServerName);
  Result := False;
  if AHost = '' then
    Exit;

  // a bracketed IPv6 literal, [::1], carries its address between the brackets
  LHost := AHost;
  if (System.Length(LHost) >= 2) and (LHost[1] = '[') and
    (LHost[System.Length(LHost)] = ']') then
  begin
    if not TryParseIPv6(System.Copy(LHost, 2, System.Length(LHost) - 2), LBytes) then
      Exit;
    AName.FKind := TServerNameKind.Ip;
    AName.FIpBytes := LBytes;
    AName.FDnsName := AHost;
    Exit(True);
  end;

  // a fully qualified host may carry a trailing root dot; drop it before classifying so an
  // IPv4 literal written as "1.2.3.4." is recognized as an IP (never a DNS name sent in SNI)
  if (System.Length(LHost) > 1) and (LHost[System.Length(LHost)] = '.') then
    LHost := System.Copy(LHost, 1, System.Length(LHost) - 1);
  if LHost = '' then
    Exit;

  if TryParseIPv4(LHost, LBytes) or TryParseIPv6(LHost, LBytes) then
  begin
    AName.FKind := TServerNameKind.Ip;
    AName.FIpBytes := LBytes;
    AName.FDnsName := LHost;
    Exit(True);
  end;

  // an IPv6-shaped string that did not parse as an address is not a valid DNS name
  if Pos(':', LHost) > 0 then
    Exit;

  AName.FKind := TServerNameKind.Dns;
  AName.FDnsName := LHost;
  Result := True;
end;

class function TServerName.DnsName(const AHost: string): TServerName;
begin
  Result := Default(TServerName);
  Result.FKind := TServerNameKind.Dns;
  Result.FDnsName := AHost;
end;

function TServerName.IsIp: Boolean;
begin
  Result := FKind = TServerNameKind.Ip;
end;

function TServerName.IsEmpty: Boolean;
begin
  Result := (FKind = TServerNameKind.Dns) and (FDnsName = '');
end;

function TServerName.AsDns: string;
begin
  if FKind = TServerNameKind.Dns then
    Result := FDnsName
  else
    Result := '';
end;

function TServerName.AsIpBytes: TBytes;
begin
  Result := FIpBytes;
end;

function TServerName.ToString: string;
begin
  Result := FDnsName;
end;

end.
