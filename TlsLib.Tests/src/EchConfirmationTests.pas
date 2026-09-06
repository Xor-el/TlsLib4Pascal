{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit EchConfirmationTests;

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
  TlpCryptoDomainTypes,
  TlpICryptoProvider,
  TlpTls13KeySchedule,
  TlsLibTestBase;

type
  /// <summary>
  /// The ECH accept-confirmation derivations (RFC 9849 sec. 7.2 / 7.2.1):
  /// HKDF-Expand-Label(HKDF-Extract(0, inner.random), label, transcript, 8). Known
  /// answers are cross-checked against an independent HKDF reference; also covers hash
  /// agility (SHA-256 and SHA-384) and label domain separation.
  /// </summary>
  TTestEchConfirmation = class(TTlsLibAlgorithmTestCase)
  private
    function Hkdf(AHash: THashAlgorithm): IHkdf;
    function InnerRandom: TBytes;
  published
    procedure TestAcceptConfirmationSha256Kat;
    procedure TestAcceptConfirmationSha384Kat;
    procedure TestHrrAcceptConfirmationSha256Kat;
    procedure TestConfirmationIsEightBytes;
    procedure TestDifferentTranscriptDiffers;
    procedure TestAcceptAndHrrLabelsDiffer;
  end;

implementation

{ TTestEchConfirmation }

function TTestEchConfirmation.Hkdf(AHash: THashAlgorithm): IHkdf;
begin
  Result := Provider.Primitives.CreateHkdf(AHash);
end;

function TTestEchConfirmation.InnerRandom: TBytes;
begin
  Result := DecodeHex(
    '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
end;

procedure TTestEchConfirmation.TestAcceptConfirmationSha256Kat;
begin
  CheckEqualBytes('sha256 accept confirmation', DecodeHex('113047a36d18f54c'),
    TTls13KeySchedule.EchAcceptConfirmation(Hkdf(THashAlgorithm.SHA_256),
    InnerRandom, DecodeHex(
    '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f')));
end;

procedure TTestEchConfirmation.TestAcceptConfirmationSha384Kat;
begin
  CheckEqualBytes('sha384 accept confirmation', DecodeHex('cb7c043f7d5a6781'),
    TTls13KeySchedule.EchAcceptConfirmation(Hkdf(THashAlgorithm.SHA_384),
    InnerRandom, DecodeHex('202122232425262728292a2b2c2d2e2f' +
    '303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f')));
end;

procedure TTestEchConfirmation.TestHrrAcceptConfirmationSha256Kat;
begin
  CheckEqualBytes('sha256 hrr confirmation', DecodeHex('83497b1a4a59da99'),
    TTls13KeySchedule.EchHrrAcceptConfirmation(Hkdf(THashAlgorithm.SHA_256),
    InnerRandom, DecodeHex(
    '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f')));
end;

procedure TTestEchConfirmation.TestConfirmationIsEightBytes;
begin
  CheckEquals(8, System.Length(TTls13KeySchedule.EchAcceptConfirmation(
    Hkdf(THashAlgorithm.SHA_256), InnerRandom, InnerRandom)),
    'the confirmation is 8 bytes');
end;

procedure TTestEchConfirmation.TestDifferentTranscriptDiffers;
var
  LA, LB: TBytes;
begin
  LA := TTls13KeySchedule.EchAcceptConfirmation(Hkdf(THashAlgorithm.SHA_256),
    InnerRandom, DecodeHex(
    '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f'));
  LB := TTls13KeySchedule.EchAcceptConfirmation(Hkdf(THashAlgorithm.SHA_256),
    InnerRandom, DecodeHex(
    '212122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f'));
  CheckFalse(AreEqual(LA, LB), 'a different transcript yields a different confirmation');
end;

procedure TTestEchConfirmation.TestAcceptAndHrrLabelsDiffer;
var
  LTranscript, LAccept, LHrr: TBytes;
begin
  // same inputs, different labels -> domain separation
  LTranscript := DecodeHex(
    '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f');
  LAccept := TTls13KeySchedule.EchAcceptConfirmation(
    Hkdf(THashAlgorithm.SHA_256), InnerRandom, LTranscript);
  LHrr := TTls13KeySchedule.EchHrrAcceptConfirmation(
    Hkdf(THashAlgorithm.SHA_256), InnerRandom, LTranscript);
  CheckFalse(AreEqual(LAccept, LHrr),
    'the ServerHello and HRR labels domain-separate the confirmation');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestEchConfirmation);
{$ELSE}
  RegisterTest(TTestEchConfirmation.Suite);
{$ENDIF FPC}

end.
