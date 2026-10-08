{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit EndpointIdentityTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  TlpEndpointIdentity,
  TlpServerName;

type
  TTestEndpointIdentity = class(TTestCase)
  private
    function Matches(const AHost: string; const ANames: array of string): Boolean;
    function MatchesIp(const AHost: string; const AIps: array of TBytes): Boolean;
  published
    procedure TestExactMatch;
    procedure TestExactMatchCaseInsensitive;
    procedure TestNoMatch;
    procedure TestWildcardMatchesOneLabel;
    procedure TestWildcardDoesNotMatchBareDomain;
    procedure TestWildcardDoesNotMatchMultipleLabels;
    procedure TestWildcardPublicSuffixNotMatched;
    procedure TestWildcardTwoLabelSuffixMatches;
    procedure TestPartialWildcardIgnored;
    procedure TestMultipleWildcardsIgnored;
    procedure TestReferenceHostWildcardRejected;
    procedure TestReferenceHostNonLdhRejected;
    procedure TestReferenceHostUnderscoreAndALabelAccepted;
    procedure TestNumericLookingHostsAreNotNames;
    procedure TestLabelLengthAndHyphenLimits;
    procedure TestDnsPatternPredicatesDirect;
    procedure TestFirstOfSeveralNamesMatches;
    procedure TestIpLiteralDoesNotMatchWildcardDns;
    procedure TestIpLiteralMatchesIpSan;
    procedure TestIpLiteralRejectsDifferentIpSan;
    procedure TestIpv6LiteralMatchesIpSan;
    procedure TestIpv6LiteralDoesNotMatchDns;
    procedure TestTrailingDotIpv4ClassifiedAsIp;
    procedure TestTrailingDotFqdnTrimmedToDns;
    procedure TestDefaultNameIsEmpty;
    procedure TestDnsNameWithEmptyHostIsEmpty;
    procedure TestParsedDnsNameIsNotEmpty;
    procedure TestParsedIpNameIsNotEmpty;
  end;

implementation

{ TTestEndpointIdentity }

function TTestEndpointIdentity.Matches(const AHost: string;
  const ANames: array of string): Boolean;
var
  LNames: TArray<string>;
  LName: TServerName;
  LI: Int32;
begin
  SetLength(LNames, System.Length(ANames));
  for LI := 0 to High(ANames) do
    LNames[LI] := ANames[LI];
  if not TServerName.TryParse(AHost, LName) then
    Exit(False);
  Result := TEndpointIdentity.Matches(LName, LNames, nil);
end;

function TTestEndpointIdentity.MatchesIp(const AHost: string;
  const AIps: array of TBytes): Boolean;
var
  LIps: TArray<TBytes>;
  LName: TServerName;
  LI: Int32;
begin
  SetLength(LIps, System.Length(AIps));
  for LI := 0 to High(AIps) do
    LIps[LI] := AIps[LI];
  if not TServerName.TryParse(AHost, LName) then
    Exit(False);
  Result := TEndpointIdentity.Matches(LName, nil, LIps);
end;

procedure TTestEndpointIdentity.TestExactMatch;
begin
  CheckTrue(Matches('example.com', ['example.com']));
end;

procedure TTestEndpointIdentity.TestExactMatchCaseInsensitive;
begin
  CheckTrue(Matches('WWW.Example.COM', ['www.example.com']));
end;

procedure TTestEndpointIdentity.TestNoMatch;
begin
  CheckFalse(Matches('example.com', ['example.org', 'other.com']));
end;

procedure TTestEndpointIdentity.TestWildcardMatchesOneLabel;
begin
  CheckTrue(Matches('a.example.com', ['*.example.com']));
end;

procedure TTestEndpointIdentity.TestWildcardPublicSuffixNotMatched;
begin
  // *.com leaves only one label below the wildcard - local policy: it must never match
  // (public suffixes, RFC 9525 7.1)
  CheckFalse(Matches('example.com', ['*.com']));
end;

procedure TTestEndpointIdentity.TestWildcardTwoLabelSuffixMatches;
begin
  // a wildcard leaving two labels below it is fine (*.co.uk vs host.co.uk)
  CheckTrue(Matches('host.co.uk', ['*.co.uk']));
end;

procedure TTestEndpointIdentity.TestPartialWildcardIgnored;
begin
  // a wildcard that is not the entire leftmost label is ill-formed and ignored, not a literal
  CheckFalse(Matches('foo.example.com', ['f*.example.com']));
  CheckFalse(Matches('foo.example.com', ['*oo.example.com']));
end;

procedure TTestEndpointIdentity.TestMultipleWildcardsIgnored;
begin
  CheckFalse(Matches('a.b.com', ['*.*.com']));
end;

procedure TTestEndpointIdentity.TestReferenceHostWildcardRejected;
var
  LName: TServerName;
begin
  // a client verifies a concrete host; a wildcard is not a usable reference host
  CheckFalse(TServerName.TryParse('*.example.com', LName));
end;

procedure TTestEndpointIdentity.TestReferenceHostNonLdhRejected;
var
  LName: TServerName;
begin
  CheckFalse(TServerName.TryParse('bad host.example.com', LName));
end;

procedure TTestEndpointIdentity.TestReferenceHostUnderscoreAndALabelAccepted;
var
  LName: TServerName;
begin
  // underscore is tolerated; a punycode A-label is a normal LDH host
  CheckTrue(TServerName.TryParse('_dmarc.example.com', LName));
  CheckTrue(TServerName.TryParse('xn--nxasmq6b.example.com', LName));
end;

procedure TTestEndpointIdentity.TestNumericLookingHostsAreNotNames;
var
  LName: TServerName;
begin
  // octal-ambiguous and numeric-final-label hosts are neither an IP literal nor a DNS name
  CheckFalse(TServerName.TryParse('010.0.0.1', LName), 'leading zero');
  CheckFalse(TServerName.TryParse('1.2.3', LName), 'short dotted decimal');
  CheckFalse(TServerName.TryParse('0x7f.0.0.1', LName), 'hex octet');
  CheckFalse(TServerName.TryParse('example.0x7f', LName), 'hex final label');
  CheckFalse(TServerName.TryParse('2130706433', LName), 'single decimal label');
  CheckFalse(TServerName.TryParse('example.123.', LName), 'numeric final label before a root dot');
  CheckFalse(TServerName.TryParse('example.0x', LName), 'bare hex prefix');
  CheckTrue(TServerName.TryParse('localhost', LName), 'a single alphabetic label');
  CheckTrue(TServerName.TryParse('0.0.0.0', LName), 'a lone zero octet is a valid IPv4');
  CheckTrue(LName.IsIp, 'and it is an IP');
  CheckTrue(TServerName.TryParse('example.face', LName), 'bare hex letters are an ordinary label');
  CheckTrue(TServerName.TryParse('0x.example.com', LName), 'a numeric-looking non-final label is fine');
end;

procedure TTestEndpointIdentity.TestLabelLengthAndHyphenLimits;
begin
  // RFC 1035: a label is at most 63 octets
  CheckTrue(TEndpointIdentity.IsValidReferenceHostName(
    StringOfChar('a', 63) + '.example.com'), 'a 63-octet label is accepted');
  CheckFalse(TEndpointIdentity.IsValidReferenceHostName(
    StringOfChar('a', 64) + '.example.com'), 'a 64-octet label is rejected');
  // a label may not begin or end with a hyphen; an interior hyphen is fine
  CheckFalse(TEndpointIdentity.IsValidReferenceHostName('-bad.example.com'),
    'a leading hyphen is rejected');
  CheckFalse(TEndpointIdentity.IsValidReferenceHostName('bad-.example.com'),
    'a trailing hyphen is rejected');
  CheckTrue(TEndpointIdentity.IsValidReferenceHostName('a-b.example.com'),
    'an interior hyphen is accepted');
  // RFC 1035 2.3.4: the whole name is at most 255 wire octets (253 in text form follows)
  CheckTrue(TEndpointIdentity.IsValidReferenceHostName(StringOfChar('a', 63) + '.' +
    StringOfChar('a', 63) + '.' + StringOfChar('a', 63) + '.' + StringOfChar('a', 61)),
    'a 253-octet name is accepted');
  CheckFalse(TEndpointIdentity.IsValidReferenceHostName(StringOfChar('a', 63) + '.' +
    StringOfChar('a', 63) + '.' + StringOfChar('a', 63) + '.' + StringOfChar('a', 63)),
    'a name over 253 octets is rejected');
  // the length limits do not touch the wildcard label or the underscore tolerance
  CheckTrue(TEndpointIdentity.IsValidPresentedDnsName('*.example.com'),
    'a wildcard label is still valid');
  CheckTrue(TEndpointIdentity.IsValidReferenceHostName('_dmarc.example.com'),
    'underscore tolerance is kept');
end;

procedure TTestEndpointIdentity.TestDnsPatternPredicatesDirect;
begin
  // matchable patterns (exactly what MatchesOneDns accepts)
  CheckTrue(TEndpointIdentity.IsMatchableDnsPattern('example.com'));
  CheckTrue(TEndpointIdentity.IsMatchableDnsPattern('*.example.com'));
  CheckTrue(TEndpointIdentity.IsMatchableDnsPattern('*.co.uk'));
  // unmatchable / ill-formed
  CheckFalse(TEndpointIdentity.IsMatchableDnsPattern('*.com'));
  CheckFalse(TEndpointIdentity.IsMatchableDnsPattern('*'));
  CheckFalse(TEndpointIdentity.IsMatchableDnsPattern('*.'));
  CheckFalse(TEndpointIdentity.IsMatchableDnsPattern('f*.example.com'));
  CheckFalse(TEndpointIdentity.IsMatchableDnsPattern('a.*.com'));
  CheckFalse(TEndpointIdentity.IsMatchableDnsPattern('a..com')); // empty label
  CheckFalse(TEndpointIdentity.IsMatchableDnsPattern('example.com.')); // trailing dot
  CheckFalse(TEndpointIdentity.IsMatchableDnsPattern('bad host.com')); // non-LDH
  CheckFalse(TEndpointIdentity.IsMatchableDnsPattern(''));
  // presented-name well-formedness (allows a whole-leftmost-label wildcard)
  CheckTrue(TEndpointIdentity.IsValidPresentedDnsName('*.example.com'));
  CheckFalse(TEndpointIdentity.IsValidPresentedDnsName('a b.com'));
  // reference-host validity: never a wildcard
  CheckTrue(TEndpointIdentity.IsValidReferenceHostName('localhost'));
  CheckTrue(TEndpointIdentity.IsValidReferenceHostName('_dmarc.example.com'));
  CheckFalse(TEndpointIdentity.IsValidReferenceHostName('*.example.com'));
end;

procedure TTestEndpointIdentity.TestWildcardDoesNotMatchBareDomain;
begin
  CheckFalse(Matches('example.com', ['*.example.com']));
end;

procedure TTestEndpointIdentity.TestWildcardDoesNotMatchMultipleLabels;
begin
  CheckFalse(Matches('a.b.example.com', ['*.example.com']));
end;

procedure TTestEndpointIdentity.TestFirstOfSeveralNamesMatches;
begin
  CheckTrue(Matches('localhost', ['other.example', 'localhost', '*.test']));
end;

procedure TTestEndpointIdentity.TestIpLiteralDoesNotMatchWildcardDns;
begin
  // RFC 9525: an IP-literal host must never match a dNSName/wildcard
  CheckFalse(Matches('127.0.0.1', ['*.0.0.1']));
  CheckFalse(Matches('127.0.0.1', ['127.0.0.1']));
end;

procedure TTestEndpointIdentity.TestIpLiteralMatchesIpSan;
begin
  CheckTrue(MatchesIp('127.0.0.1', [TBytes.Create(127, 0, 0, 1)]));
end;

procedure TTestEndpointIdentity.TestIpLiteralRejectsDifferentIpSan;
begin
  CheckFalse(MatchesIp('127.0.0.1', [TBytes.Create(8, 8, 8, 8)]));
end;

procedure TTestEndpointIdentity.TestIpv6LiteralMatchesIpSan;
var
  LLoopback: TBytes;
begin
  LLoopback := nil;
  SetLength(LLoopback, 16);
  LLoopback[15] := 1; // ::1
  CheckTrue(MatchesIp('::1', [LLoopback]));
end;

procedure TTestEndpointIdentity.TestIpv6LiteralDoesNotMatchDns;
begin
  // an IPv6-literal host is never matched against dNSName entries
  CheckFalse(Matches('::1', ['*.1', '1']));
end;

procedure TTestEndpointIdentity.TestTrailingDotIpv4ClassifiedAsIp;
var
  LName: TServerName;
begin
  // a trailing root dot on an IPv4 literal must still classify as an IP (never a DNS name
  // that would then be sent as SNI or matched against dNSName SANs)
  CheckTrue(TServerName.TryParse('127.0.0.1.', LName));
  CheckTrue(LName.IsIp);
  CheckEquals('', LName.AsDns);
  CheckTrue(MatchesIp('127.0.0.1.', [TBytes.Create(127, 0, 0, 1)]));
end;

procedure TTestEndpointIdentity.TestTrailingDotFqdnTrimmedToDns;
var
  LName: TServerName;
begin
  // a trailing root dot on a genuine FQDN is trimmed and the host stays a DNS name
  CheckTrue(TServerName.TryParse('example.com.', LName));
  CheckFalse(LName.IsIp);
  CheckEquals('example.com', LName.AsDns);
end;

procedure TTestEndpointIdentity.TestDefaultNameIsEmpty;
var
  LName: TServerName;
begin
  LName := Default(TServerName);
  CheckTrue(LName.IsEmpty);
end;

procedure TTestEndpointIdentity.TestDnsNameWithEmptyHostIsEmpty;
begin
  CheckTrue(TServerName.DnsName('').IsEmpty);
end;

procedure TTestEndpointIdentity.TestParsedDnsNameIsNotEmpty;
var
  LName: TServerName;
begin
  CheckTrue(TServerName.TryParse('example.com', LName));
  CheckFalse(LName.IsEmpty);
end;

procedure TTestEndpointIdentity.TestParsedIpNameIsNotEmpty;
var
  LName: TServerName;
begin
  CheckTrue(TServerName.TryParse('127.0.0.1', LName));
  CheckFalse(LName.IsEmpty);
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestEndpointIdentity);
{$ELSE}
  RegisterTest(TTestEndpointIdentity.Suite);
{$ENDIF FPC}

end.
