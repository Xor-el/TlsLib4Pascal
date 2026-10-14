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
  TlpCryptoDomainTypes,
  TlpTlsLibExceptions,
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
    // the lenient-KEM provider weakens only the KEM, so every AEAD still builds
    procedure TestLenientKemProviderStillBuildsEveryAead;
    // the missing-AEAD provider refuses exactly the AEAD it names
    procedure TestMissingAeadProviderRefusesOnlyTheNamedAead;
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
  LCrypto: ICryptoProvider;
  LReference: IRandom;
begin
  LCrypto := TMockCryptoProvider.Create(TMockRandom.Create(7) as IRandom);
  LReference := TMockRandom.Create(7);
  // the provider hands back the injected deterministic stream
  CheckEqualBytes('injected random', LReference.GenerateBytes(16),
    LCrypto.Primitives.GetRandom.GenerateBytes(16));
end;

procedure TTestMocks.TestMockProviderDelegatesCrypto;
var
  LCrypto: ICryptoProvider;
  LHash: IHash;
  LMsg: TBytes;
begin
  // crypto is delegated to the inner real provider
  LCrypto := TMockCryptoProvider.Create(TMockRandom.Create(0) as IRandom);
  LHash := LCrypto.Primitives.CreateHash(THashAlgorithm.SHA_256);
  LMsg := DecodeHex('616263'); // "abc"
  LHash.Update(LMsg, 0, System.Length(LMsg));
  CheckEqualBytes('delegated SHA-256(abc)',
    DecodeHex('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'),
    LHash.DoFinal);
end;

procedure TTestMocks.TestLenientKemProviderStillBuildsEveryAead;
var
  LProvider: ICryptoProvider;
begin
  LProvider := TMissingAeadProvider.CreateLenientKem(Crypto) as ICryptoProvider;
  CheckTrue(LProvider.Primitives.CreateAead(TAeadAlgorithm.AES_128_GCM) <> nil,
    'AES-128-GCM builds');
  CheckTrue(LProvider.Primitives.CreateAead(TAeadAlgorithm.AES_256_GCM) <> nil,
    'AES-256-GCM builds');
  CheckTrue(LProvider.Primitives.CreateAead(TAeadAlgorithm.CHACHA20_POLY1305) <> nil,
    'ChaCha20-Poly1305 builds');
end;

procedure TTestMocks.TestMissingAeadProviderRefusesOnlyTheNamedAead;
var
  LProvider: ICryptoProvider;
  LRefused: Boolean;
begin
  LProvider := TMissingAeadProvider.Create(Crypto, TAeadAlgorithm.AES_128_GCM) as ICryptoProvider;
  LRefused := False;
  try
    LProvider.Primitives.CreateAead(TAeadAlgorithm.AES_128_GCM);
  except
    on ENotSupportedTlsLibException do
      LRefused := True;
  end;
  CheckTrue(LRefused, 'the named AEAD is refused');
  CheckTrue(LProvider.Primitives.CreateAead(TAeadAlgorithm.AES_256_GCM) <> nil,
    'another AEAD builds');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestMocks);
{$ELSE}
  RegisterTest(TTestMocks.Suite);
{$ENDIF FPC}

end.
