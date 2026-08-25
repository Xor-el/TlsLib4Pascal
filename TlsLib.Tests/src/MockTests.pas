{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit MockTests;

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
  TlpICryptoProvider,
  TlpCryptoAlgorithms,
  MockRandom,
  MockCryptoProvider,
  TlsLibTestBase;

type
  TTestMocks = class(TTlsLibAlgorithmTestCase)
  published
    procedure TestMockRandomIsDeterministic;
    procedure TestMockRandomSeedsDiffer;
    procedure TestMockProviderInjectsRandom;
    procedure TestMockProviderDelegatesCrypto;
  end;

implementation

{ TTestMocks }

procedure TTestMocks.TestMockRandomIsDeterministic;
var
  LA, LB: IRandom;
begin
  LA := TMockRandom.Create(42);
  LB := TMockRandom.Create(42);
  CheckEqualBytes('same seed same stream', LA.GenerateBytes(48), LB.GenerateBytes(48));
end;

procedure TTestMocks.TestMockRandomSeedsDiffer;
var
  LA, LB: IRandom;
begin
  LA := TMockRandom.Create(1);
  LB := TMockRandom.Create(2);
  CheckFalse(AreEqual(LA.GenerateBytes(32), LB.GenerateBytes(32)),
    'different seeds differ');
end;

procedure TTestMocks.TestMockProviderInjectsRandom;
var
  LProvider: ICryptoProvider;
  LReference: IRandom;
begin
  LProvider := TMockCryptoProvider.Create(TMockRandom.Create(7) as IRandom);
  LReference := TMockRandom.Create(7);
  // the provider hands back the injected deterministic stream
  CheckEqualBytes('injected random', LReference.GenerateBytes(16),
    LProvider.Primitives.GetRandom.GenerateBytes(16));
end;

procedure TTestMocks.TestMockProviderDelegatesCrypto;
var
  LProvider: ICryptoProvider;
  LHash: IHash;
  LMsg: TBytes;
begin
  // crypto is delegated to the inner real provider
  LProvider := TMockCryptoProvider.Create(TMockRandom.Create(0) as IRandom);
  LHash := LProvider.Primitives.CreateHash(THashAlgorithm.SHA_256);
  LMsg := DecodeHex('616263'); // "abc"
  LHash.Update(LMsg, 0, System.Length(LMsg));
  CheckEqualBytes('delegated SHA-256(abc)',
    DecodeHex('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'),
    LHash.DoFinal);
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestMocks);
{$ELSE}
  RegisterTest(TTestMocks.Suite);
{$ENDIF FPC}

end.
