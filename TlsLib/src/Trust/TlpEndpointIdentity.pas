{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpEndpointIdentity;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpArrayUtilities,
  TlpServerName;

type
  /// <summary>
  /// RFC 6125 / RFC 9525 endpoint identity matching. A DNS host is matched against the
  /// certificate's dNSName SANs (a single wildcard is honored only as the entire leftmost label
  /// and only when it leaves at least two labels below it: <c>*.example.com</c> matches
  /// <c>a.example.com</c> but not <c>example.com</c>, <c>a.b.example.com</c>, or a public suffix
  /// like <c>*.com</c>; matching is case-insensitive). An ill-formed presented name (empty or
  /// non-LDH label, or a wildcard that is not the whole leftmost label) is ignored, never
  /// compared as a literal. An IP-literal host is matched only against iPAddress SANs, never
  /// against dNSName/wildcards. The host is classified once, up front, into a
  /// <see cref="TServerName"/>.
  /// </summary>
  TEndpointIdentity = class sealed(TObject)
  strict private
    class function CountDots(const AText: string): Int32; static;
    class function IsLdhLabel(const ALabel: string;
      AAllowWildcard: Boolean): Boolean; static;
    class function IsWellFormedDnsName(const AName: string;
      AAllowWildcard: Boolean): Boolean; static;
    class function MatchesOneDns(const AHostName, ADnsName: string): Boolean; static;
    class function MatchesDns(const AHostName: string;
      const ADnsNames: TArray<string>): Boolean; static;
    class function MatchesIp(const AHostIp: TBytes;
      const AIpAddresses: TArray<TBytes>): Boolean; static;
  public
    /// <summary>True if AName matches the certificate's SANs: an IP literal against
    /// AIpAddresses (raw 4- or 16-byte octets), a DNS host against ADnsNames.</summary>
    class function Matches(const AName: TServerName;
      const ADnsNames: TArray<string>;
      const AIpAddresses: TArray<TBytes>): Boolean; static;
    /// <summary>Whether a presented dNSName / SNI pattern is well-formed (RFC 9525 6.3): all
    /// labels non-empty and LDH (letters, digits, hyphen; underscore tolerated), with an
    /// optional single wildcard that must be the entire leftmost label. An ill-formed presented
    /// name is ignored for matching; an ill-formed SNI pattern is rejected at configuration.</summary>
    class function IsValidPresentedDnsName(const AName: string): Boolean; static;
    /// <summary>Whether AName is a usable reference host to verify against: a valid DNS name
    /// with no wildcard (a client verifies a concrete host, never a pattern).</summary>
    class function IsValidReferenceHostName(const AName: string): Boolean; static;
    /// <summary>Whether AName is a DNS pattern that can actually match at runtime: well-formed,
    /// and any wildcard leaves at least two labels below it (never a public suffix like *.com).
    /// This is exactly what MatchesOneDns accepts, so a configured SNI pattern and the matcher
    /// can never disagree.</summary>
    class function IsMatchableDnsPattern(const AName: string): Boolean; static;
  end;

implementation

{ TEndpointIdentity }

class function TEndpointIdentity.MatchesOneDns(const AHostName,
  ADnsName: string): Boolean;
var
  LSuffix: string;
  LDot: Int32;
begin
  if (AHostName = '') or (ADnsName = '') then
    Exit(False);

  // an ill-formed or unmatchable presented name (empty/non-LDH label, a wildcard that is not the
  // entire leftmost label, or a wildcard over a public suffix like *.com) is ignored entirely
  // (RFC 9525 6.3), never compared as a literal
  if not IsMatchableDnsPattern(ADnsName) then
    Exit(False);

  // DNS name comparison is case-insensitive (RFC 6125 / RFC 9525)
  if SameText(ADnsName, AHostName) then
    Exit(True);

  // a single leftmost "*." wildcard matches exactly one non-empty label
  if (System.Length(ADnsName) > 2) and (ADnsName[1] = '*') and (ADnsName[2] = '.') then
  begin
    LSuffix := System.Copy(ADnsName, 2, System.Length(ADnsName) - 1); // ".example.com"
    LDot := Pos('.', AHostName);
    // the host must have a non-empty first label, and the remainder must equal the
    // wildcard suffix exactly (so the wildcard spans a single label only)
    Result := (LDot > 1) and
      SameText(System.Copy(AHostName, LDot, System.Length(AHostName) - LDot + 1), LSuffix);
    Exit;
  end;

  Result := False;
end;

class function TEndpointIdentity.CountDots(const AText: string): Int32;
var
  LI: Int32;
begin
  Result := 0;
  for LI := 1 to System.Length(AText) do
    if AText[LI] = '.' then
      Inc(Result);
end;

class function TEndpointIdentity.IsLdhLabel(const ALabel: string;
  AAllowWildcard: Boolean): Boolean;
var
  LI: Int32;
  LCh: Char;
begin
  Result := False;
  if ALabel = '' then
    Exit;
  // a wildcard label is the entire "*" and nothing else
  if AAllowWildcard and (ALabel = '*') then
    Exit(True);
  for LI := 1 to System.Length(ALabel) do
  begin
    LCh := ALabel[LI];
    // letters/digits/hyphen (RFC 1123), plus underscore as a widely tolerated exception
    if not (((LCh >= 'A') and (LCh <= 'Z')) or ((LCh >= 'a') and (LCh <= 'z')) or
      ((LCh >= '0') and (LCh <= '9')) or (LCh = '-') or (LCh = '_')) then
      Exit;
  end;
  Result := True;
end;

class function TEndpointIdentity.IsWellFormedDnsName(const AName: string;
  AAllowWildcard: Boolean): Boolean;
var
  LI, LStart: Int32;
  LFirstLabel: Boolean;
begin
  Result := False;
  if AName = '' then
    Exit;
  LFirstLabel := True;
  LStart := 1;
  for LI := 1 to System.Length(AName) + 1 do
    if (LI > System.Length(AName)) or (AName[LI] = '.') then
    begin
      // a wildcard is only ever valid as the entire leftmost label
      if not IsLdhLabel(System.Copy(AName, LStart, LI - LStart),
        AAllowWildcard and LFirstLabel) then
        Exit;
      LFirstLabel := False;
      LStart := LI + 1;
    end;
  Result := True;
end;

class function TEndpointIdentity.IsValidPresentedDnsName(const AName: string): Boolean;
begin
  Result := IsWellFormedDnsName(AName, True);
end;

class function TEndpointIdentity.IsValidReferenceHostName(const AName: string): Boolean;
begin
  Result := IsWellFormedDnsName(AName, False);
end;

class function TEndpointIdentity.IsMatchableDnsPattern(const AName: string): Boolean;
begin
  if not IsValidPresentedDnsName(AName) then
    Exit(False);
  // a wildcard must leave at least two labels below it (never a public suffix such as *.com, and
  // never a bare "*"): the suffix after the leading "*" then has two dots, e.g. ".example.com"
  // (RFC 9525 6.3 / RFC 6125 6.4.3). A well-formed name starting with "*" is "*" or "*.<rest>".
  if (System.Length(AName) > 0) and (AName[1] = '*') then
    Result := CountDots(System.Copy(AName, 2, System.Length(AName) - 1)) >= 2
  else
    Result := True;
end;

class function TEndpointIdentity.MatchesDns(const AHostName: string;
  const ADnsNames: TArray<string>): Boolean;
var
  LI: Int32;
begin
  Result := False;
  for LI := 0 to High(ADnsNames) do
    if MatchesOneDns(AHostName, ADnsNames[LI]) then
      Exit(True);
end;

class function TEndpointIdentity.MatchesIp(const AHostIp: TBytes;
  const AIpAddresses: TArray<TBytes>): Boolean;
var
  LI: Int32;
begin
  Result := False;
  for LI := 0 to High(AIpAddresses) do
    if TArrayUtilities.AreEqual(AHostIp, AIpAddresses[LI]) then
      Exit(True);
end;

class function TEndpointIdentity.Matches(const AName: TServerName;
  const ADnsNames: TArray<string>; const AIpAddresses: TArray<TBytes>): Boolean;
begin
  if AName.IsIp then
    // an IP-literal host matches only iPAddress SANs (RFC 6125 forbids wildcard/dNSName)
    Result := MatchesIp(AName.AsIpBytes, AIpAddresses)
  else
    Result := MatchesDns(AName.AsDns, ADnsNames);
end;

end.
