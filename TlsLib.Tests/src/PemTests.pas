{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit PemTests;

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
  TlpPem;

type
  TTestPem = class(TTestCase)
  private
    function Blocks(const ALabels: array of string): TArray<TPemBlock>;
  published
    procedure TestIndexOfPrivateKeyTakesTheFirstPrivateKeyBlock;
    procedure TestIndexOfPrivateKeySkipsCertificatesAndParameters;
    procedure TestIndexOfPrivateKeyAcceptsEveryPrivateKeyLabel;
    procedure TestIndexOfPrivateKeyIsMinusOneWithoutAKey;
    procedure TestIndexOfPrivateKeyIgnoresALabelThatOnlyContainsTheWords;
    procedure TestBeginTagCountSeesEveryBoundaryIncludingMidLine;
  end;

implementation

function TTestPem.Blocks(const ALabels: array of string): TArray<TPemBlock>;
var
  LI: Int32;
begin
  Result := nil;
  SetLength(Result, System.Length(ALabels));
  for LI := 0 to System.High(ALabels) do
    Result[LI].PemType := ALabels[LI];
end;

procedure TTestPem.TestIndexOfPrivateKeyTakesTheFirstPrivateKeyBlock;
begin
  CheckEquals(0, TPem.IndexOfPrivateKey(Blocks(['ENCRYPTED PRIVATE KEY', 'PRIVATE KEY'])),
    'an encrypted first block is the one chosen, not the plain key after it');
  CheckEquals(1, TPem.IndexOfPrivateKey(Blocks(['CERTIFICATE', 'PRIVATE KEY', 'EC PRIVATE KEY'])),
    'the first of several keys wins');
end;

procedure TTestPem.TestIndexOfPrivateKeySkipsCertificatesAndParameters;
begin
  CheckEquals(2, TPem.IndexOfPrivateKey(Blocks(['CERTIFICATE', 'EC PARAMETERS', 'EC PRIVATE KEY'])),
    'blocks that are not keys are passed over');
end;

procedure TTestPem.TestIndexOfPrivateKeyAcceptsEveryPrivateKeyLabel;
const
  PrivateKeyLabels: array [0 .. 3] of string = ('PRIVATE KEY', 'ENCRYPTED PRIVATE KEY',
    'RSA PRIVATE KEY', 'EC PRIVATE KEY');
var
  LI: Int32;
begin
  for LI := Low(PrivateKeyLabels) to High(PrivateKeyLabels) do
    CheckEquals(0, TPem.IndexOfPrivateKey(Blocks([PrivateKeyLabels[LI]])), PrivateKeyLabels[LI]);
end;

procedure TTestPem.TestIndexOfPrivateKeyIsMinusOneWithoutAKey;
begin
  CheckEquals(-1, TPem.IndexOfPrivateKey(nil), 'no blocks');
  CheckEquals(-1, TPem.IndexOfPrivateKey(Blocks(['CERTIFICATE', 'PUBLIC KEY'])),
    'only a certificate and a public key');
end;

procedure TTestPem.TestBeginTagCountSeesEveryBoundaryIncludingMidLine;
begin
  CheckEquals(0, TPem.BeginTagCount(nil), 'no data');
  CheckEquals(0, TPem.BeginTagCount(TEncoding.ASCII.GetBytes('-----BEGIN-----')),
    'a boundary needs the space after BEGIN');
  CheckEquals(2, TPem.BeginTagCount(TEncoding.ASCII.GetBytes(
    '-----BEGIN A-----'#10'x'#10'-----END A-----'#10'-----BEGIN B-----'#10'y'#10'-----END B-----')),
    'two blocks that start their lines');
  CheckEquals(2, TPem.BeginTagCount(TEncoding.ASCII.GetBytes(
    'note -----BEGIN A-----'#10'x'#10'-----END A-----'#10'-----BEGIN B-----'#10'y'#10'-----END B-----')),
    'a boundary after text on its line is counted though ReadBlocks does not frame it');
end;

procedure TTestPem.TestIndexOfPrivateKeyIgnoresALabelThatOnlyContainsTheWords;
begin
  CheckEquals(-1, TPem.IndexOfPrivateKey(Blocks(['PRIVATE KEY HINT', 'MY PRIVATE KEYS'])),
    'the label has to end in PRIVATE KEY');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestPem);
{$ELSE}
  RegisterTest(TTestPem.Suite);
{$ENDIF FPC}

end.
