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
  TlpIpLiteral;

type
  /// <summary>Whether a server name is a DNS host or an IP-address literal.</summary>
  TServerNameKind = (Dns, Ip);

  /// <summary>Whether a client sends its host as server_name (SNI, RFC 6066 sec. 3): Send, the
  /// default, sends a DNS host and never an IP literal; Omit sends none. Independent of the
  /// certificate name check (RFC 9525), which always uses the connection host.</summary>
  TServerNameIndication = (Send, Omit);

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

uses
  TlpEndpointIdentity;

{ TServerName }

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
    if not TIpLiteral.TryParseIPv6(System.Copy(LHost, 2, System.Length(LHost) - 2), LBytes) then
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

  if TIpLiteral.TryParseIPv4(LHost, LBytes) or TIpLiteral.TryParseIPv6(LHost, LBytes) then
  begin
    AName.FKind := TServerNameKind.Ip;
    AName.FIpBytes := LBytes;
    AName.FDnsName := LHost;
    Exit(True);
  end;

  // an IPv6-shaped string that did not parse as an address is not a valid DNS name
  if Pos(':', LHost) > 0 then
    Exit;

  // a reference host to verify against must be a well-formed DNS name with no wildcard: a client
  // checks a concrete host, and a malformed host would otherwise be compared as an opaque literal
  // that can never match a SAN. Callers pass A-labels (punycode), not U-labels.
  if not TEndpointIdentity.IsValidReferenceHostName(LHost) then
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
