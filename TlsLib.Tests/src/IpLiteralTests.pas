{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit IpLiteralTests;

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
  TlpIpLiteral,
  TlsLibTestBase;

type
  TTestIpLiteral = class(TTlsLibTestCase)
  strict private
    function V4(const AText: string): Boolean;
    function V6(const AText: string): Boolean;
  published
    procedure TestIPv4ParsesToItsOctets;
    procedure TestIPv4RefusesAmbiguousOrMalformedQuads;
    procedure TestIPv6ParsesFullAndCompressedForms;
    procedure TestIPv6EmbeddedIPv4;
    procedure TestIPv6RefusesMalformedForms;
  end;

implementation

{ TTestIpLiteral }

function TTestIpLiteral.V4(const AText: string): Boolean;
var
  LBytes: TBytes;
begin
  Result := TIpLiteral.TryParseIPv4(AText, LBytes);
end;

function TTestIpLiteral.V6(const AText: string): Boolean;
var
  LBytes: TBytes;
begin
  Result := TIpLiteral.TryParseIPv6(AText, LBytes);
end;

procedure TTestIpLiteral.TestIPv4ParsesToItsOctets;
var
  LBytes: TBytes;
begin
  CheckTrue(TIpLiteral.TryParseIPv4('192.0.2.17', LBytes), 'a dotted quad parses');
  CheckEquals(4, System.Length(LBytes), 'four octets');
  CheckEquals(192, LBytes[0], 'first');
  CheckEquals(0, LBytes[1], 'second');
  CheckEquals(2, LBytes[2], 'third');
  CheckEquals(17, LBytes[3], 'fourth');
  CheckTrue(V4('0.0.0.0') and V4('255.255.255.255'), 'the range ends parse');
end;

procedure TTestIpLiteral.TestIPv4RefusesAmbiguousOrMalformedQuads;
begin
  CheckFalse(V4('01.2.3.4'), 'a leading zero may read as octal');
  CheckFalse(V4('1.2.3.256'), 'an octet above 255');
  CheckFalse(V4('1.2.3'), 'three parts');
  CheckFalse(V4('1.2.3.4.5'), 'five parts');
  CheckFalse(V4('1..3.4'), 'an empty part');
  CheckFalse(V4('1.2.3.a'), 'a letter');
  CheckFalse(V4('1.2.3.1000'), 'four digits');
  CheckFalse(V4(''), 'empty');
end;

procedure TTestIpLiteral.TestIPv6ParsesFullAndCompressedForms;
var
  LBytes: TBytes;
begin
  CheckTrue(TIpLiteral.TryParseIPv6('2001:db8:0:0:0:0:0:1', LBytes), 'the full form');
  CheckEquals(16, System.Length(LBytes), 'sixteen octets');
  CheckEquals($20, LBytes[0], 'high byte');
  CheckEquals($01, LBytes[1], 'next byte');
  CheckEquals($01, LBytes[15], 'last byte');
  CheckTrue(TIpLiteral.TryParseIPv6('::1', LBytes), 'loopback');
  CheckEquals(0, LBytes[0], 'the compressed head is zero');
  CheckEquals(1, LBytes[15], 'the tail is kept');
  CheckTrue(V6('::') and V6('2001:DB8::'), 'the unspecified address and a trailing "::"');
  CheckTrue(V6('FE80::1'), 'upper-case hex');
end;

procedure TTestIpLiteral.TestIPv6EmbeddedIPv4;
var
  LBytes: TBytes;
begin
  CheckTrue(TIpLiteral.TryParseIPv6('::ffff:1.2.3.4', LBytes), 'a trailing embedded quad');
  CheckEquals($FF, LBytes[10], 'the mapped marker');
  CheckEquals(1, LBytes[12], 'embedded first octet');
  CheckEquals(4, LBytes[15], 'embedded last octet');
  CheckFalse(V6('::1.2.3.4:5'), 'an embedded quad only in the final group');
  CheckFalse(V6('::ffff:1.2.3'), 'the embedded quad must itself be valid');
end;

procedure TTestIpLiteral.TestIPv6RefusesMalformedForms;
begin
  CheckFalse(V6('1.2.3.4'), 'no colon is not IPv6');
  CheckFalse(V6('1::2::3'), 'two "::"');
  CheckFalse(V6('1:2:3:4:5:6:7'), 'seven groups without "::"');
  CheckFalse(V6('1:2:3:4:5:6:7:8:9'), 'nine groups');
  CheckFalse(V6('1:2:3:4:5:6:7::8'), '"::" standing for no group');
  CheckFalse(V6('12345::1'), 'a five-digit group');
  CheckFalse(V6('g::1'), 'a non-hex digit');
  CheckFalse(V6(':1:2:3:4:5:6:7'), 'a leading single colon');
  CheckFalse(V6(''), 'empty');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestIpLiteral);
{$ELSE}
  RegisterTest(TTestIpLiteral.Suite);
{$ENDIF FPC}

end.
