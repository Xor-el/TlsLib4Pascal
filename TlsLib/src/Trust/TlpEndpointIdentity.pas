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
  /// RFC 6125 endpoint identity matching. A DNS host is matched against the
  /// certificate's dNSName SANs (a single left-most wildcard label is honored:
  /// <c>*.example.com</c> matches <c>a.example.com</c> but not <c>example.com</c>
  /// or <c>a.b.example.com</c>; matching is case-insensitive). An IP-literal host
  /// is matched only against iPAddress SANs, never against dNSName/wildcards. The
  /// host is classified once, up front, into a <see cref="TServerName"/>.
  /// </summary>
  TEndpointIdentity = class sealed(TObject)
  strict private
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
