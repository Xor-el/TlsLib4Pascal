{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ArrayUtilitiesTests;

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
  TlpArrayUtilities,
  TlsLibTestBase;

type
  /// <summary>The byte-array helpers, over literal arrays with hand-written expected signs.</summary>
  TTestArrayUtilities = class(TTlsLibTestCase)
  published
    procedure TestCompareEqualArraysIsZero;
    procedure TestCompareEmptyWithEmptyIsZero;
    procedure TestCompareEmptyBeforeNonEmpty;
    procedure TestCompareNonEmptyAfterEmpty;
    procedure TestComparePrefixSortsFirst;
    procedure TestCompareLongerAfterItsPrefix;
    procedure TestCompareFirstDifferingByteDecides;
    procedure TestCompareIsUnsigned;
    procedure TestCompareIsAntisymmetric;
  end;

implementation

{ TTestArrayUtilities }

procedure TTestArrayUtilities.TestCompareEqualArraysIsZero;
begin
  CheckEquals(0, TArrayUtilities.CompareLexicographic(TBytes.Create($01, $02, $03),
    TBytes.Create($01, $02, $03)));
end;

procedure TTestArrayUtilities.TestCompareEmptyWithEmptyIsZero;
begin
  CheckEquals(0, TArrayUtilities.CompareLexicographic(nil, nil));
end;

procedure TTestArrayUtilities.TestCompareEmptyBeforeNonEmpty;
begin
  Check(TArrayUtilities.CompareLexicographic(nil, TBytes.Create($00)) < 0,
    'empty sorts before a one-byte array');
end;

procedure TTestArrayUtilities.TestCompareNonEmptyAfterEmpty;
begin
  Check(TArrayUtilities.CompareLexicographic(TBytes.Create($00), nil) > 0,
    'a one-byte array sorts after empty');
end;

procedure TTestArrayUtilities.TestComparePrefixSortsFirst;
begin
  Check(TArrayUtilities.CompareLexicographic(TBytes.Create($01, $02),
    TBytes.Create($01, $02, $00)) < 0, 'a prefix sorts before the longer array');
end;

procedure TTestArrayUtilities.TestCompareLongerAfterItsPrefix;
begin
  Check(TArrayUtilities.CompareLexicographic(TBytes.Create($01, $02, $00),
    TBytes.Create($01, $02)) > 0, 'the longer array sorts after its prefix');
end;

procedure TTestArrayUtilities.TestCompareFirstDifferingByteDecides;
begin
  Check(TArrayUtilities.CompareLexicographic(TBytes.Create($01, $02, $FF),
    TBytes.Create($01, $03, $00)) < 0, 'the second byte decides, not the later bytes');
  Check(TArrayUtilities.CompareLexicographic(TBytes.Create($02, $00),
    TBytes.Create($01, $FF, $FF)) > 0, 'the first byte decides, not the length');
end;

procedure TTestArrayUtilities.TestCompareIsUnsigned;
begin
  Check(TArrayUtilities.CompareLexicographic(TBytes.Create($7F),
    TBytes.Create($80)) < 0, '$80 sorts after $7F');
  Check(TArrayUtilities.CompareLexicographic(TBytes.Create($FF),
    TBytes.Create($7F)) > 0, '$FF sorts after $7F');
  Check(TArrayUtilities.CompareLexicographic(TBytes.Create($00),
    TBytes.Create($FF)) < 0, '$FF sorts after $00');
end;

procedure TTestArrayUtilities.TestCompareIsAntisymmetric;
begin
  Check(TArrayUtilities.CompareLexicographic(TBytes.Create($01, $80),
    TBytes.Create($01, $7F)) > 0, 'forward direction is positive');
  Check(TArrayUtilities.CompareLexicographic(TBytes.Create($01, $7F),
    TBytes.Create($01, $80)) < 0, 'reverse direction is negative');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestArrayUtilities);
{$ELSE}
  RegisterTest(TTestArrayUtilities.Suite);
{$ENDIF FPC}

end.
