{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit SystemCryptoHelperTests;

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
  TlpISecretBuffer,
  TlpSecretBuffer,
  TlpTlsLibExceptions,
  TlpHkdfComposition,
  TlsLibTestProviders,
  TlsLibTestBase;

type
  /// <summary>The platform-neutral helpers the native crypto overlays share, run over the
  /// portable provider's primitives so every platform and compiler exercises them.</summary>
  TTestSystemCryptoHelpers = class(TTlsLibAlgorithmTestCase)
  strict private
    // the composition under test, over the portable primitives
    function Composition(AAlgorithm: THashAlgorithm): IHkdf;
    // the independent reference: the portable provider's own HKDF
    function Reference(AAlgorithm: THashAlgorithm): IHkdf;
    // a fixed PRK from the reference, for the length and hook tests
    function ReferencePrk(AAlgorithm: THashAlgorithm): ISecretBuffer;
    procedure CheckVector(const ASalt, AIkm, AInfo, APrk, AOkm: string; ALength: Int32);
    procedure CheckMatchesReference(AAlgorithm: THashAlgorithm; AHashLen: Int32);
    procedure CheckExtractMatchesZeroSalt(const ASalt: ISecretBuffer);
    // whether Expand raises exactly EArgumentTlsLibException for ALength
    function ExpandRaisesArgument(AAlgorithm: THashAlgorithm; ALength: Int32): Boolean;
  strict protected
    function CreateCrypto: ICryptoProvider; override;
  published
    procedure TestHkdfRfc5869Case1;
    procedure TestHkdfRfc5869Case2;
    procedure TestHkdfRfc5869Case3;
    procedure TestHkdfMatchesReferenceSha256;
    procedure TestHkdfMatchesReferenceSha384;
    procedure TestHkdfMatchesReferenceSha512;
    procedure TestHkdfExtractNilSaltIsZeroSalt;
    procedure TestHkdfExtractEmptySaltIsZeroSalt;
    procedure TestHkdfExtractHashLenZeroSaltIsZeroSalt;
    procedure TestHkdfExpandRejectsNegativeLength;
    procedure TestHkdfExpandRejectsLengthOverCap;
    procedure TestHkdfExpandAcceptsExactCap;
    procedure TestHkdfExpandCapFollowsHashLength;
    procedure TestHkdfExpandZeroLengthIsEmpty;
    procedure TestHkdfHookNotConsultedForNegativeLength;
    procedure TestHkdfHookNotConsultedForZeroLength;
    procedure TestHkdfHookNotConsultedForLengthOverCap;
    procedure TestHkdfHookConsultedOnceForValidLength;
    procedure TestHkdfHookServedOkmIsReturnedVerbatim;
    procedure TestHkdfHookDeclinedFallsBackToHmacLoop;
    procedure TestHkdfRefusesNilPrimitives;
  end;

implementation

type
  // counts the in-module Expand consultations and serves a fixed sentinel when Serve is set
  TRecordingHkdf = class(THkdfComposition)
  public
  var
    Serve: Boolean;
    Calls: Int32;
  strict protected
    function TryExpandInModule(const APrk: ISecretBuffer; const AInfo: TBytes;
      ALength: Int32; out AOkm: ISecretBuffer): Boolean; override;
  end;

const
  // RFC 5869 Appendix A, test cases 1-3 (SHA-256)
  CIkm22 = '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b';
  CSalt13 = '000102030405060708090a0b0c';
  CInfo10 = 'f0f1f2f3f4f5f6f7f8f9';
  CPrk1 = '077709362c2e32df0ddc3f0dc47bba63' + '90b6c73bb50f9c3122ec844ad7c2b3e5';
  COkm1 = '3cb25f25faacd57a90434f64d0362f2a' + '2d2d0a90cf1a5a4c5db02d56ecc4c5bf' +
    '34007208d5b887185865';
  CIkm80 = '000102030405060708090a0b0c0d0e0f' + '101112131415161718191a1b1c1d1e1f' +
    '202122232425262728292a2b2c2d2e2f' + '303132333435363738393a3b3c3d3e3f' +
    '404142434445464748494a4b4c4d4e4f';
  CSalt80 = '606162636465666768696a6b6c6d6e6f' + '707172737475767778797a7b7c7d7e7f' +
    '808182838485868788898a8b8c8d8e8f' + '909192939495969798999a9b9c9d9e9f' +
    'a0a1a2a3a4a5a6a7a8a9aaabacadaeaf';
  CInfo80 = 'b0b1b2b3b4b5b6b7b8b9babbbcbdbebf' + 'c0c1c2c3c4c5c6c7c8c9cacbcccdcecf' +
    'd0d1d2d3d4d5d6d7d8d9dadbdcdddedf' + 'e0e1e2e3e4e5e6e7e8e9eaebecedeeef' +
    'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff';
  CPrk2 = '06a6b88c5853361a06104c9ceb35b45c' + 'ef760014904671014a193f40c15fc244';
  COkm2 = 'b11e398dc80327a1c8e7f78c596a4934' + '4f012eda2d4efad8a050cc4c19afa97c' +
    '59045a99cac7827271cb41c65e590e09' + 'da3275600c2f09b8367793a9aca3db71' +
    'cc30c58179ec3e87c14c01d5c1f3434f' + '1d87';
  CPrk3 = '19ef24a32c717b167f33a91d6f648bdf' + '96596776afdb6377ac434c1c293ccb04';
  COkm3 = '8da4e775a563c18f715f802a063c5a31' + 'b8a11f5c5ee1879ec3454e5f3c738d2d' +
    '9d201395faa4b61a96c8';

{ TRecordingHkdf }

function TRecordingHkdf.TryExpandInModule(const APrk: ISecretBuffer;
  const AInfo: TBytes; ALength: Int32; out AOkm: ISecretBuffer): Boolean;
begin
  Inc(Calls);
  Result := Serve;
  if Result then
    AOkm := TSecretBuffer.From(TBytes.Create($A5, $5A, $C3))
  else
    AOkm := nil;
end;

{ TTestSystemCryptoHelpers }

function TTestSystemCryptoHelpers.CreateCrypto: ICryptoProvider;
begin
  Result := TTlsLibTestProviders.Crypto(TCryptoProviderChoice.Portable);
end;

function TTestSystemCryptoHelpers.Composition(AAlgorithm: THashAlgorithm): IHkdf;
begin
  Result := THkdfComposition.Create(Crypto.Primitives, AAlgorithm) as IHkdf;
end;

function TTestSystemCryptoHelpers.Reference(AAlgorithm: THashAlgorithm): IHkdf;
begin
  Result := Crypto.Primitives.CreateHkdf(AAlgorithm);
end;

function TTestSystemCryptoHelpers.ReferencePrk(AAlgorithm: THashAlgorithm): ISecretBuffer;
begin
  Result := Reference(AAlgorithm).Extract(TSecretBuffer.From(DecodeHex(CSalt13)),
    TSecretBuffer.From(DecodeHex(CIkm22)));
end;

procedure TTestSystemCryptoHelpers.CheckVector(const ASalt, AIkm, AInfo, APrk,
  AOkm: string; ALength: Int32);
var
  LHkdf: IHkdf;
  LPrk, LOkm: ISecretBuffer;
begin
  LHkdf := Composition(THashAlgorithm.SHA_256);
  LPrk := LHkdf.Extract(TSecretBuffer.From(DecodeHex(ASalt)),
    TSecretBuffer.From(DecodeHex(AIkm)));
  CheckEqualBytes('HKDF-Extract PRK', DecodeHex(APrk), LPrk.ToBytes);
  LOkm := LHkdf.Expand(LPrk, DecodeHex(AInfo), ALength);
  CheckEqualBytes('HKDF-Expand OKM', DecodeHex(AOkm), LOkm.ToBytes);
end;

procedure TTestSystemCryptoHelpers.CheckMatchesReference(AAlgorithm: THashAlgorithm;
  AHashLen: Int32);
var
  LLengths: array[0..5] of Int32;
  LInfo: TBytes;
  LPrk: ISecretBuffer;
  LI: Int32;
begin
  LLengths[0] := 1;
  LLengths[1] := AHashLen - 1;
  LLengths[2] := AHashLen;
  LLengths[3] := AHashLen + 1;
  LLengths[4] := 2 * AHashLen + 1;
  LLengths[5] := 255 * AHashLen;
  LInfo := DecodeHex(CInfo10);
  LPrk := ReferencePrk(AAlgorithm);
  for LI := Low(LLengths) to High(LLengths) do
    CheckEqualBytes(Format('HKDF-Expand L=%d', [LLengths[LI]]),
      Reference(AAlgorithm).Expand(LPrk, LInfo, LLengths[LI]).ToBytes,
      Composition(AAlgorithm).Expand(LPrk, LInfo, LLengths[LI]).ToBytes);
  CheckEqualBytes('HKDF-Extract PRK',
    LPrk.ToBytes, Composition(AAlgorithm).Extract(TSecretBuffer.From(DecodeHex(CSalt13)),
      TSecretBuffer.From(DecodeHex(CIkm22))).ToBytes);
end;

procedure TTestSystemCryptoHelpers.CheckExtractMatchesZeroSalt(const ASalt: ISecretBuffer);
const
  CHashLen = 32;
var
  LIkm: ISecretBuffer;
  LExpected: TBytes;
begin
  LIkm := TSecretBuffer.From(DecodeHex(CIkm22));
  LExpected := Reference(THashAlgorithm.SHA_256).Extract(
    TSecretBuffer.Allocate(CHashLen), LIkm).ToBytes;
  CheckEquals(CHashLen, Length(LExpected), 'reference PRK length');
  CheckEqualBytes('HKDF-Extract PRK', LExpected,
    Composition(THashAlgorithm.SHA_256).Extract(ASalt, LIkm).ToBytes);
end;

function TTestSystemCryptoHelpers.ExpandRaisesArgument(AAlgorithm: THashAlgorithm;
  ALength: Int32): Boolean;
begin
  Result := False;
  try
    Composition(AAlgorithm).Expand(ReferencePrk(AAlgorithm), DecodeHex(CInfo10), ALength);
  except
    on E: EArgumentTlsLibException do
      Result := E.ClassType = EArgumentTlsLibException;
  end;
end;

procedure TTestSystemCryptoHelpers.TestHkdfRfc5869Case1;
begin
  CheckVector(CSalt13, CIkm22, CInfo10, CPrk1, COkm1, 42);
end;

procedure TTestSystemCryptoHelpers.TestHkdfRfc5869Case2;
begin
  CheckVector(CSalt80, CIkm80, CInfo80, CPrk2, COkm2, 82);
end;

procedure TTestSystemCryptoHelpers.TestHkdfRfc5869Case3;
begin
  CheckVector('', CIkm22, '', CPrk3, COkm3, 42);
end;

procedure TTestSystemCryptoHelpers.TestHkdfMatchesReferenceSha256;
begin
  CheckMatchesReference(THashAlgorithm.SHA_256, 32);
end;

procedure TTestSystemCryptoHelpers.TestHkdfMatchesReferenceSha384;
begin
  CheckMatchesReference(THashAlgorithm.SHA_384, 48);
end;

procedure TTestSystemCryptoHelpers.TestHkdfMatchesReferenceSha512;
begin
  CheckMatchesReference(THashAlgorithm.SHA_512, 64);
end;

procedure TTestSystemCryptoHelpers.TestHkdfExtractNilSaltIsZeroSalt;
begin
  CheckExtractMatchesZeroSalt(nil);
end;

procedure TTestSystemCryptoHelpers.TestHkdfExtractEmptySaltIsZeroSalt;
begin
  CheckExtractMatchesZeroSalt(TSecretBuffer.From(nil));
end;

procedure TTestSystemCryptoHelpers.TestHkdfExtractHashLenZeroSaltIsZeroSalt;
begin
  CheckExtractMatchesZeroSalt(TSecretBuffer.Allocate(32));
end;

procedure TTestSystemCryptoHelpers.TestHkdfExpandRejectsNegativeLength;
begin
  CheckTrue(ExpandRaisesArgument(THashAlgorithm.SHA_256, -1),
    'a negative length raises EArgumentTlsLibException');
end;

procedure TTestSystemCryptoHelpers.TestHkdfExpandRejectsLengthOverCap;
begin
  CheckTrue(ExpandRaisesArgument(THashAlgorithm.SHA_256, 255 * 32 + 1),
    'a length beyond 255 * HashLen raises EArgumentTlsLibException');
end;

procedure TTestSystemCryptoHelpers.TestHkdfExpandAcceptsExactCap;
var
  LOkm: ISecretBuffer;
begin
  LOkm := Composition(THashAlgorithm.SHA_256).Expand(ReferencePrk(THashAlgorithm.SHA_256),
    DecodeHex(CInfo10), 255 * 32);
  CheckEquals(255 * 32, LOkm.Len, 'Expand at the exact cap succeeds');
end;

procedure TTestSystemCryptoHelpers.TestHkdfExpandCapFollowsHashLength;
var
  LOkm: ISecretBuffer;
begin
  CheckTrue(ExpandRaisesArgument(THashAlgorithm.SHA_384, 255 * 48 + 1),
    'one past the SHA-384 cap raises EArgumentTlsLibException');
  LOkm := Composition(THashAlgorithm.SHA_384).Expand(ReferencePrk(THashAlgorithm.SHA_384),
    DecodeHex(CInfo10), 255 * 48);
  CheckEquals(255 * 48, LOkm.Len, 'Expand at the exact SHA-384 cap succeeds');
end;

procedure TTestSystemCryptoHelpers.TestHkdfExpandZeroLengthIsEmpty;
var
  LOkm: ISecretBuffer;
begin
  LOkm := Composition(THashAlgorithm.SHA_256).Expand(ReferencePrk(THashAlgorithm.SHA_256),
    DecodeHex(CInfo10), 0);
  CheckEquals(0, LOkm.Len, 'a zero length yields an empty buffer');
end;

procedure TTestSystemCryptoHelpers.TestHkdfHookNotConsultedForNegativeLength;
var
  LRecording: TRecordingHkdf;
  LHkdf: IHkdf;
  LRaised: Boolean;
begin
  LRecording := TRecordingHkdf.Create(Crypto.Primitives, THashAlgorithm.SHA_256);
  LHkdf := LRecording;
  LRecording.Serve := True;
  LRaised := False;
  try
    LHkdf.Expand(ReferencePrk(THashAlgorithm.SHA_256), DecodeHex(CInfo10), -1);
  except
    on EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a negative length raises');
  CheckEquals(0, LRecording.Calls, 'the hook is not consulted for a negative length');
end;

procedure TTestSystemCryptoHelpers.TestHkdfHookNotConsultedForZeroLength;
var
  LRecording: TRecordingHkdf;
  LHkdf: IHkdf;
begin
  LRecording := TRecordingHkdf.Create(Crypto.Primitives, THashAlgorithm.SHA_256);
  LHkdf := LRecording;
  LRecording.Serve := True;
  LHkdf.Expand(ReferencePrk(THashAlgorithm.SHA_256), DecodeHex(CInfo10), 0);
  CheckEquals(0, LRecording.Calls, 'the hook is not consulted for a zero length');
end;

procedure TTestSystemCryptoHelpers.TestHkdfHookNotConsultedForLengthOverCap;
var
  LRecording: TRecordingHkdf;
  LHkdf: IHkdf;
  LRaised: Boolean;
begin
  LRecording := TRecordingHkdf.Create(Crypto.Primitives, THashAlgorithm.SHA_256);
  LHkdf := LRecording;
  LRecording.Serve := True;
  LRaised := False;
  try
    LHkdf.Expand(ReferencePrk(THashAlgorithm.SHA_256), DecodeHex(CInfo10), 255 * 32 + 1);
  except
    on EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a length beyond the cap raises');
  CheckEquals(0, LRecording.Calls, 'the hook is not consulted beyond the cap');
end;

procedure TTestSystemCryptoHelpers.TestHkdfHookConsultedOnceForValidLength;
var
  LRecording: TRecordingHkdf;
  LHkdf: IHkdf;
begin
  LRecording := TRecordingHkdf.Create(Crypto.Primitives, THashAlgorithm.SHA_256);
  LHkdf := LRecording;
  LHkdf.Expand(ReferencePrk(THashAlgorithm.SHA_256), DecodeHex(CInfo10), 42);
  CheckEquals(1, LRecording.Calls, 'the hook is consulted once for a valid length');
end;

procedure TTestSystemCryptoHelpers.TestHkdfHookServedOkmIsReturnedVerbatim;
var
  LRecording: TRecordingHkdf;
  LHkdf: IHkdf;
begin
  LRecording := TRecordingHkdf.Create(Crypto.Primitives, THashAlgorithm.SHA_256);
  LHkdf := LRecording;
  LRecording.Serve := True;
  CheckEqualBytes('served OKM', TBytes.Create($A5, $5A, $C3),
    LHkdf.Expand(ReferencePrk(THashAlgorithm.SHA_256), DecodeHex(CInfo10), 42).ToBytes);
end;

procedure TTestSystemCryptoHelpers.TestHkdfHookDeclinedFallsBackToHmacLoop;
var
  LRecording: TRecordingHkdf;
  LHkdf: IHkdf;
  LPrk: ISecretBuffer;
begin
  LRecording := TRecordingHkdf.Create(Crypto.Primitives, THashAlgorithm.SHA_256);
  LHkdf := LRecording;
  LPrk := ReferencePrk(THashAlgorithm.SHA_256);
  CheckEqualBytes('fallback OKM',
    Reference(THashAlgorithm.SHA_256).Expand(LPrk, DecodeHex(CInfo10), 42).ToBytes,
    LHkdf.Expand(LPrk, DecodeHex(CInfo10), 42).ToBytes);
end;

procedure TTestSystemCryptoHelpers.TestHkdfRefusesNilPrimitives;
var
  LRaised: Boolean;
  LHkdf: IHkdf;
begin
  LRaised := False;
  try
    LHkdf := THkdfComposition.Create(nil, THashAlgorithm.SHA_256) as IHkdf;
  except
    on E: EArgumentTlsLibException do
      LRaised := E.ClassType = EArgumentTlsLibException;
  end;
  CheckTrue(LRaised, 'a nil primitives facet raises EArgumentTlsLibException');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestSystemCryptoHelpers);
{$ELSE}
  RegisterTest(TTestSystemCryptoHelpers.Suite);
{$ENDIF FPC}

end.
