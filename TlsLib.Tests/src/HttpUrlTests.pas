{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit HttpUrlTests;

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
  TlpHttpUrl,
  TlsLibTestBase;

type
  TTestHttpUrl = class(TTlsLibTestCase)
  strict private
    function Canonical(const AText: string): string;
    function Refused(const AText: string): Boolean;
  published
    procedure TestWellFormedUrlsParse;
    procedure TestCanonicalFormNormalisesCaseDefaultPortPathAndFragment;
    procedure TestSchemeIsCaseInsensitiveAndOnlyHttpFamily;
    procedure TestUserinfoIsRefused;
    procedure TestControlsBackslashAndNonAsciiAreRefused;
    procedure TestPercentEncodingMustBeWellFormed;
    procedure TestEmptyHostIsRefused;
    procedure TestHostForms;
    procedure TestNumericLookingHostsAreRefused;
    procedure TestPortRules;
    procedure TestIPv6HostRules;
    procedure TestLengthCap;
    procedure TestPathAndQueryKeepTheirCase;
  end;

implementation

{ TTestHttpUrl }

function TTestHttpUrl.Canonical(const AText: string): string;
var
  LUrl: THttpUrl;
begin
  if THttpUrl.TryParse(AText, LUrl) then
    Result := LUrl.ToString
  else
    Result := '<refused>';
end;

function TTestHttpUrl.Refused(const AText: string): Boolean;
var
  LUrl: THttpUrl;
begin
  Result := not THttpUrl.TryParse(AText, LUrl);
end;

procedure TTestHttpUrl.TestWellFormedUrlsParse;
var
  LUrl: THttpUrl;
begin
  CheckTrue(THttpUrl.TryParse('http://a.example/x', LUrl), 'plain http');
  CheckTrue(LUrl.Scheme = THttpScheme.Http, 'scheme');
  CheckEquals('a.example', LUrl.Host, 'host');
  CheckTrue(LUrl.HostKind = THttpHostKind.DnsName, 'a name');
  CheckEquals(80, LUrl.Port, 'the default port is applied');
  CheckEquals('/x', LUrl.PathAndQuery, 'path');
  CheckTrue(THttpUrl.TryParse('https://192.0.2.1:8443/crl?x=1', LUrl), 'an IPv4 host');
  CheckTrue(LUrl.HostKind = THttpHostKind.IPv4, 'IPv4');
  CheckEquals(8443, LUrl.Port, 'explicit port');
  CheckEquals('/crl?x=1', LUrl.PathAndQuery, 'path and query');
end;

procedure TTestHttpUrl.TestCanonicalFormNormalisesCaseDefaultPortPathAndFragment;
begin
  CheckEquals('http://a.example/', Canonical('http://a.example'), 'an empty path is "/"');
  CheckEquals('https://a.example/X?q', Canonical('HTTPS://A.Example:443/X?q'),
    'scheme and host lower-cased, the default port dropped, the path kept');
  CheckEquals('http://a.example/p', Canonical('http://a.example:/p'), 'an empty port is the default');
  CheckEquals('http://a.example/p', Canonical('http://a.example:80/p#frag'),
    ':80 and the fragment are dropped');
  CheckEquals('https://a.example:80/', Canonical('https://a.example:80'),
    'a port that is not the scheme default is kept');
  CheckEquals('http://a.example/?q', Canonical('http://a.example?q'), 'a query without a path');
  CheckEquals(Canonical('http://a.example/p'), Canonical('HTTP://A.EXAMPLE:80/p#x'),
    'spellings of one resource share canonical text');
end;

procedure TTestHttpUrl.TestSchemeIsCaseInsensitiveAndOnlyHttpFamily;
begin
  CheckEquals('http://a.example/', Canonical('HtTp://a.example/'), 'mixed-case http');
  CheckTrue(Refused('ftp://a.example/'), 'ftp');
  CheckTrue(Refused('file:///etc/passwd'), 'file');
  CheckTrue(Refused('ldap://a.example/'), 'ldap');
  CheckTrue(Refused('httpx://a.example/'), 'a longer scheme');
  CheckTrue(Refused('http:/a.example/'), 'one slash');
  CheckTrue(Refused('http//a.example/'), 'no colon');
  CheckTrue(Refused('a.example/x'), 'no scheme');
  CheckTrue(Refused(''), 'empty');
end;

procedure TTestHttpUrl.TestUserinfoIsRefused;
begin
  CheckTrue(Refused('http://u@a.example/'), 'user');
  CheckTrue(Refused('http://u:p@a.example/'), 'user and password');
  CheckTrue(Refused('http://trusted.example@evil.example/'), 'the display trick');
  CheckTrue(Refused('http://@a.example/'), 'an empty userinfo');
end;

procedure TTestHttpUrl.TestControlsBackslashAndNonAsciiAreRefused;
begin
  CheckTrue(Refused('http://a.example\x/'), 'a backslash in the authority');
  CheckTrue(Refused('http://a.example/p\q'), 'a backslash in the path');
  CheckTrue(Refused('http://a.example /'), 'a space');
  CheckTrue(Refused('http://a.example/'#13#10'X: y'), 'CR LF');
  CheckTrue(Refused('http://a.example/'#0), 'NUL');
  CheckTrue(Refused('http://a.example/'#127), 'DEL');
  CheckTrue(Refused('http://a.example/'#9), 'a tab');
  CheckTrue(Refused('http://a.example/'#$00E9), 'a non-ASCII character');
  CheckTrue(Refused('http://a.example/"'), 'a double quote');
  CheckTrue(Refused('http://a.example/<'), 'an angle bracket');
  CheckTrue(Refused('http://a.example/[x]'), 'square brackets in the path');
  CheckTrue(Refused('http://a.example/?q=[1]'), 'square brackets in the query');
  CheckTrue(Refused('http://a.example/p#[f]'), 'square brackets in the fragment');
end;

procedure TTestHttpUrl.TestPercentEncodingMustBeWellFormed;
begin
  CheckEquals('http://a.example/%7E', Canonical('http://a.example/%7e'),
    'well-formed, with upper-case hex digits');
  CheckEquals(Canonical('http://a.example/%7e?q=%aB'), Canonical('http://a.example/%7E?q=%Ab'),
    'spellings that differ only in percent-encoding case share canonical text');
  CheckTrue(Refused('http://a.example/%zz'), 'non-hex');
  CheckTrue(Refused('http://a.example/%a'), 'one digit at the end');
  CheckTrue(Refused('http://a.example/%'), 'a bare percent');
  CheckTrue(Refused('http://a%41.example/'), 'percent-encoding in the host');
end;

procedure TTestHttpUrl.TestEmptyHostIsRefused;
begin
  CheckTrue(Refused('http:///p'), 'no host');
  CheckTrue(Refused('http://:80/'), 'a port without a host');
  CheckTrue(Refused('http://?q'), 'a query without a host');
  CheckTrue(Refused('https://#f'), 'a fragment without a host');
end;

procedure TTestHttpUrl.TestHostForms;
begin
  CheckEquals('http://a-b.c.example/', Canonical('http://A-B.C.Example/'), 'LDH labels');
  CheckTrue(Refused('http://a_b.example/'), 'an underscore');
  CheckTrue(Refused('http://a..example/'), 'an empty label');
  CheckTrue(Refused('http://.example/'), 'a leading dot');
  CheckTrue(Refused('http://a.example./'), 'a trailing dot');
  CheckTrue(Refused('http://a*.example/'), 'a wildcard');
  CheckTrue(Refused('http://' + StringOfChar('a', 64) + '.example/'), 'a label over 63 characters');
  CheckTrue(Refused('http://::1/'), 'an unbracketed IPv6 literal');
end;

procedure TTestHttpUrl.TestNumericLookingHostsAreRefused;
begin
  // a resolver or another URL parser may read these as numbers, so one text could name two hosts
  CheckTrue(Refused('http://1.2.3/'), 'three parts');
  CheckTrue(Refused('http://01.2.3.4/'), 'a leading zero');
  CheckTrue(Refused('http://1.2.3.256/'), 'an octet above 255');
  CheckTrue(Refused('http://2130706433/'), 'a decimal address');
  CheckTrue(Refused('http://0x7f.1/'), 'a hex form');
  CheckTrue(Refused('http://a.0x7f/'), 'a numeric last label');
  CheckEquals('http://127.0.0.1/', Canonical('http://127.0.0.1/'), 'a strict dotted quad is accepted');
end;

procedure TTestHttpUrl.TestPortRules;
begin
  CheckTrue(Refused('http://a.example:0/'), 'port 0');
  CheckTrue(Refused('http://a.example:65536/'), 'above 65535');
  CheckTrue(Refused('http://a.example:999999/'), 'six digits');
  CheckTrue(Refused('http://a.example:+80/'), 'a sign');
  CheckTrue(Refused('http://a.example:8a/'), 'a non-digit');
  CheckTrue(Refused('http://a.example:80:80/'), 'two ports');
  CheckEquals('http://a.example:65535/', Canonical('http://a.example:65535/'), 'the top of the range');
  CheckEquals('http://a.example:1/', Canonical('http://a.example:1/'), 'the bottom of the range');
end;

procedure TTestHttpUrl.TestIPv6HostRules;
var
  LUrl: THttpUrl;
begin
  CheckTrue(THttpUrl.TryParse('http://[::1]:8080/p', LUrl), 'a bracketed literal with a port');
  CheckTrue(LUrl.HostKind = THttpHostKind.IPv6, 'IPv6');
  CheckEquals('::1', LUrl.Host, 'the host carries no brackets');
  CheckEquals('http://[::1]:8080/p', LUrl.ToString, 'ToString brackets it again');
  CheckEquals('http://[2001:db8::a]/', Canonical('HTTP://[2001:DB8::A]/'), 'hex digits lower-cased');
  CheckTrue(Refused('http://[fe80::1%25eth0]/'), 'a zone identifier');
  CheckTrue(Refused('http://[v1.x]/'), 'IPvFuture');
  CheckTrue(Refused('http://[::1/'), 'a missing bracket');
  CheckTrue(Refused('http://[::1]x/'), 'junk after the bracket');
  CheckTrue(Refused('http://[1.2.3.4::5]/'), 'an embedded quad at the head');
  CheckTrue(Refused('http://[::1]:0/'), 'port 0 on a literal');
  CheckTrue(Refused('http://[]/'), 'an empty literal');
end;

procedure TTestHttpUrl.TestLengthCap;
begin
  CheckTrue(not Refused('http://a.example/' + StringOfChar('a', 7900)), 'a long path under the cap');
  CheckTrue(Refused('http://a.example/' + StringOfChar('a', 8000)), 'over 8000 characters');
end;

procedure TTestHttpUrl.TestPathAndQueryKeepTheirCase;
begin
  CheckEquals('http://a.example/AbC?Q=Xy', Canonical('HTTP://A.EXAMPLE/AbC?Q=Xy#Z'),
    'only the scheme and host are lower-cased (RFC 3986 6.2.2.1)');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestHttpUrl);
{$ELSE}
  RegisterTest(TTestHttpUrl.Suite);
{$ENDIF FPC}

end.
