{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ProviderTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  Classes,
  SyncObjs,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  TlpTlsAlert,
  TlpTlsLibExceptions,
  TlpISecretBuffer,
  TlpSecretBuffer,
  TlpICryptoProvider,
  TlpIKeyExchangePrivateKey,
  TlpAeadUtilities,
  TlpDer,
  TlpCryptoDomainTypes,
  TlsLibTestBase;

type
  // one RFC 5869 test case: the inputs and the PRK and OKM they must give
  THkdfVector = record
    Salt, Ikm, Info, Prk, Okm: TBytes;
  end;

  TTestCryptoProvider = class(TTlsLibAlgorithmTestCase)
  private
    function Rfc5869Vector(const ASaltHex, AIkmHex, AInfoHex, APrkHex,
      AOkmHex: string): THkdfVector;
    function SecretBytes(const ASecret: ISecretBuffer): TBytes;
    function IsAllZero(const AData: TBytes): Boolean;
    function PatternBytes(ALength, ASeed: Int32): TBytes;
    function CounterNonce(ANonceSize, AIndex: Int32): TBytes;
    // Seals a long, varied stream of records through one reused adapter and asserts
    // each sealed output is byte-identical to a fresh create-per-record reference,
    // and that a fresh opener round-trips every record.
    procedure CheckAeadReuseParity(AAlgorithm: TAeadAlgorithm;
      AKeySize, AMinLength: Int32);
    // the in-place AEAD span behaviours, run against whichever provider is passed so the
    // same guarantees are asserted for the portable adapter and the OS-native overlay
    procedure DoAeadInPlaceRoundTrip(const AProvider: ICryptoProvider);
    procedure DoAeadOpenTamperWipes(const AProvider: ICryptoProvider);
    procedure DoAeadSpanGuards(const AProvider: ICryptoProvider);
    procedure DoAeadNonceReuseRejected(const AProvider: ICryptoProvider);
    // a key handle from one primitive must never agree under another (the same-width foreign
    // scalar that once nil-cast to an AV)
    procedure DoAgreeRejectsForeignKeyHandle(const AProvider: ICryptoProvider);
    procedure DoAgreeRejectsCompressedPeerPoint(const AProvider: ICryptoProvider);
    procedure DoAeadSealWithoutInitRaisesTyped(const AProvider: ICryptoProvider);
    // The key, sample and mask named APrefix in AVec, run through a fresh sample mask.
    procedure CheckMaskKat(AAlgorithm: TSampleMaskAlgorithm; const AVec: TStringList;
      const APrefix: string);
    // A sample mask of AAlgorithm keyed with a pattern key of the right size.
    function KeyedMask(AAlgorithm: TSampleMaskAlgorithm; ASeed: Int32): ISampleMask;
    // Seals a pattern plaintext under the suite AIndex and returns the AEAD that opens it
    procedure SealForOpen(AIndex: Int32; out AAead: IAead; out ANonce, AAad, APlain,
      ASealed: TBytes);
    // Whether TryOpen of the damaged input is refused with nothing of the plaintext left behind
    procedure CheckTryOpenRefuses(const AName: string; const AAead: IAead;
      const ANonce, AAad, ASealed: TBytes; AAadOff, AAadLen: Int32);
  published
    procedure TestSha256Kat;
    procedure TestSha384Kat;
    procedure TestSha1Kat;
    procedure TestSha1CloneAndReuse;
    procedure TestKeyedFactoriesRefuseNonProtocolHashes;
    procedure TestHashCloneIsIndependent;
    procedure TestHashReuseAcrossDoFinal;
    procedure TestHmacReuseAcrossDoFinal;
    procedure TestHmacSha256Kat;
    procedure TestHkdfSha256Rfc5869;
    procedure TestHkdfIsSafeAcrossThreads;
    procedure TestHkdfExpandRejectsOverCapAndNegative;
    procedure TestAesGcmKat;
    procedure TestAes256GcmKat;
    procedure TestAesGcmRoundTrip;
    procedure TestChaCha20Poly1305Kat;
    procedure TestAeadOpenAuthFailureRaisesBadRecordMac;
    procedure TestAeadInPlaceRoundTripMatchesAllocating;
    procedure TestAeadInPlaceOpenTamperWipesDestination;
    procedure TestAeadSpanGuardsRejectBadOffsetsAndOverlap;
    procedure TestAeadReuseParityAes128Gcm;
    procedure TestAeadReuseParityAes256Gcm;
    procedure TestAeadReuseParityChaCha20Poly1305;
    procedure TestAeadLongConnectionRoundTrip;
    procedure TestAeadNonceReuseRejected;
    procedure TestRandomDistinctNonZero;
    procedure TestHasHardwareAesIsStable;
    procedure TestAgreeRejectsForeignKeyHandle;
    procedure TestX25519AgreeRejectsWrongLengthPeerKeyAsPeerInput;
    procedure TestAgreeRejectsCompressedPeerPoint;
    procedure TestDerEncodeLengthRoundTripsAcrossForms;
    procedure TestDerReadTlvRejectsOverflowAndNonMinimalLengths;
    procedure TestAeadSealWithoutInitRaisesTyped;
    procedure TestAes128SampleMaskKnownAnswers;
    procedure TestAes256SampleMaskKnownAnswer;
    procedure TestChaCha20SampleMaskKnownAnswers;
    procedure TestChaCha20SampleMaskAtTheCounterLimits;
    procedure TestSampleMaskShorterThanTheBlockIsAPrefix;
    procedure TestSampleMaskReportsItsSizes;
    procedure TestSampleMaskRejectsAWrongKeySize;
    procedure TestSampleMaskBeforeInitRaises;
    procedure TestSampleMaskRejectsABadSampleSpan;
    procedure TestSampleMaskRejectsABadMaskSpan;
    procedure TestSampleMaskReadsAndWritesAtOffsets;
    procedure TestSampleMaskMayShareItsSampleAndMaskArray;
    procedure TestSampleMaskRekeysOnASecondInit;
    procedure TestAeadTryOpenMatchesOpen;
    procedure TestAeadTryOpenRefusesATamperedTag;
    procedure TestAeadTryOpenRefusesATamperedCiphertext;
    procedure TestAeadTryOpenRefusesTamperedAssociatedData;
    procedure TestAeadTryOpenRefusesAnInputShorterThanTheTag;
    procedure TestAeadTryOpenStillRaisesOnABadArgument;
    procedure TestAeadAadSpanSealMatchesTheArraySeal;
    procedure TestAeadAadSpanOpenMatchesTheArrayOpen;
    procedure TestAeadAadSpanOpenRaisesBadRecordMac;
    procedure TestAeadAadSpanGuards;
    procedure TestAeadAadSpanOverflowingOffsetIsRefused;
    procedure TestAeadEmptyAadSpanAtTheEndIsAccepted;
    procedure TestAeadTryOpenRaisesOnABadArgumentBeforeAShortInput;
    procedure TestAeadAadSpansOfChangingLengthsOnOneInstance;
    procedure TestAeadRepeatedAadSpansOfOneLengthStayCorrect;
  end;

implementation

type
  // runs Extract then Expand on one shared HKDF object in a loop, once released, and counts the
  // rounds whose PRK or OKM differ from the vector's
  THkdfVectorWorker = class sealed(TThread)
  strict private
  var
    FHkdf: IHkdf;
    FVector: THkdfVector;
    FSalt, FIkm: ISecretBuffer;
    FRounds: Int32;
    FStart: TEvent;
    FMismatches: Int32;
    function Matches(const AExpected: TBytes; const AGot: ISecretBuffer): Boolean;
  public
    constructor Create(const AHkdf: IHkdf; const AVector: THkdfVector; ARounds: Int32;
      AStart: TEvent);
    procedure Execute; override;
    property Mismatches: Int32 read FMismatches;
  end;

const
  StartTimeoutMs = 60000;

{ THkdfVectorWorker }

constructor THkdfVectorWorker.Create(const AHkdf: IHkdf; const AVector: THkdfVector;
  ARounds: Int32; AStart: TEvent);
begin
  inherited Create(True);
  FreeOnTerminate := False;
  FHkdf := AHkdf;
  FVector := AVector;
  if System.Length(AVector.Salt) > 0 then
    FSalt := TSecretBuffer.From(AVector.Salt);
  FIkm := TSecretBuffer.From(AVector.Ikm);
  FRounds := ARounds;
  FStart := AStart;
end;

function THkdfVectorWorker.Matches(const AExpected: TBytes; const AGot: ISecretBuffer): Boolean;
var
  LGot: TBytes;
begin
  LGot := AGot.ToBytes;
  Result := (System.Length(LGot) = System.Length(AExpected)) and
    CompareMem(@LGot[0], @AExpected[0], System.Length(AExpected));
end;

procedure THkdfVectorWorker.Execute;
var
  LI: Int32;
  LPrk: ISecretBuffer;
begin
  FMismatches := 0;
  FStart.WaitFor(StartTimeoutMs);
  try
    for LI := 1 to FRounds do
    begin
      LPrk := FHkdf.Extract(FSalt, FIkm);
      if not Matches(FVector.Prk, LPrk) then
        Inc(FMismatches);
      if not Matches(FVector.Okm, FHkdf.Expand(LPrk, FVector.Info, System.Length(FVector.Okm))) then
        Inc(FMismatches);
    end;
  except
    Inc(FMismatches);
  end;
end;

{ TTestCryptoProvider }

function TTestCryptoProvider.SecretBytes(const ASecret: ISecretBuffer): TBytes;
begin
  Result := nil;
  SetLength(Result, ASecret.Len);
  if ASecret.Len > 0 then
    Move(ASecret.DataPtr^, Result[0], ASecret.Len);
end;

function TTestCryptoProvider.IsAllZero(const AData: TBytes): Boolean;
var
  LI: Int32;
begin
  Result := True;
  for LI := 0 to System.Length(AData) - 1 do
    if AData[LI] <> 0 then
      Exit(False);
end;

procedure TTestCryptoProvider.TestSha256Kat;
var
  LVec: TStringList;
  LHash: IHash;
  LMsg: TBytes;
begin
  LVec := LoadVectorFields('Crypto/Digest/Sha2.txt');
  try
    LHash := Crypto.Primitives.CreateHash(THashAlgorithm.SHA_256);
    CheckEquals(32, LHash.HashSize, 'SHA-256 size');
    LMsg := DecodeHex(LVec.Values['sha256_msg']);
    LHash.Update(LMsg, 0, System.Length(LMsg));
    CheckEqualBytes('SHA-256(abc)', DecodeHex(LVec.Values['sha256_digest']),
      LHash.DoFinal);
  finally
    LVec.Free;
  end;
end;

procedure TTestCryptoProvider.TestSha384Kat;
var
  LVec: TStringList;
  LHash: IHash;
  LMsg: TBytes;
begin
  LVec := LoadVectorFields('Crypto/Digest/Sha2.txt');
  try
    LHash := Crypto.Primitives.CreateHash(THashAlgorithm.SHA_384);
    CheckEquals(48, LHash.HashSize, 'SHA-384 size');
    LMsg := DecodeHex(LVec.Values['sha384_msg']);
    LHash.Update(LMsg, 0, System.Length(LMsg));
    CheckEqualBytes('SHA-384(abc)', DecodeHex(LVec.Values['sha384_digest']),
      LHash.DoFinal);
  finally
    LVec.Free;
  end;
end;

procedure TTestCryptoProvider.TestSha1Kat;
var
  LVec: TStringList;
  LHash: IHash;
  LChunk: TBytes;
  LI: Int32;

  procedure CheckDigest(const AName: string; const AMsg: TBytes; const ADigestHex: string);
  begin
    LHash := Crypto.Primitives.CreateHash(THashAlgorithm.SHA_1);
    CheckEquals(20, LHash.HashSize, AName + ' size');
    LHash.Update(AMsg, 0, System.Length(AMsg));
    CheckEqualBytes(AName, DecodeHex(ADigestHex), LHash.DoFinal);
  end;

begin
  LVec := LoadVectorFields('Crypto/Digest/Sha1.txt');
  try
    CheckDigest('SHA-1 of nothing', nil, LVec.Values['sha1_empty_digest']);
    CheckDigest('SHA-1(abc)', DecodeHex(LVec.Values['sha1_abc_msg']),
      LVec.Values['sha1_abc_digest']);
    CheckDigest('SHA-1 of the 448-bit message', DecodeHex(LVec.Values['sha1_448bit_msg']),
      LVec.Values['sha1_448bit_digest']);
    CheckDigest('SHA-1 of the DER name', DecodeHex(LVec.Values['sha1_name_msg']),
      LVec.Values['sha1_name_digest']);
    LChunk := nil;
    SetLength(LChunk, 1000);
    FillChar(LChunk[0], System.Length(LChunk), Ord('a'));
    LHash := Crypto.Primitives.CreateHash(THashAlgorithm.SHA_1);
    for LI := 1 to 1000 do
      LHash.Update(LChunk, 0, System.Length(LChunk));
    CheckEqualBytes('SHA-1 of a million a', DecodeHex(LVec.Values['sha1_million_a_digest']),
      LHash.DoFinal);
  finally
    LVec.Free;
  end;
end;

procedure TTestCryptoProvider.TestSha1CloneAndReuse;
var
  LVec: TStringList;
  LHash, LClone: IHash;
  LAbc, LAbcDigest, LEmptyDigest: TBytes;
begin
  LVec := LoadVectorFields('Crypto/Digest/Sha1.txt');
  try
    LAbc := DecodeHex(LVec.Values['sha1_abc_msg']);
    LAbcDigest := DecodeHex(LVec.Values['sha1_abc_digest']);
    LEmptyDigest := DecodeHex(LVec.Values['sha1_empty_digest']);
    LHash := Crypto.Primitives.CreateHash(THashAlgorithm.SHA_1);
    LHash.Update(LAbc, 0, 2);
    LClone := LHash.Clone;
    LClone.Update(LAbc, 2, 1);
    CheckEqualBytes('the clone finishes the abc digest', LAbcDigest, LClone.DoFinal);
    LHash.Update(LAbc, 2, 1);
    CheckEqualBytes('the original is unaffected by the clone', LAbcDigest, LHash.DoFinal);
    CheckEqualBytes('a finished hash digests nothing again', LEmptyDigest, LHash.DoFinal);
  finally
    LVec.Free;
  end;
end;

procedure TTestCryptoProvider.TestKeyedFactoriesRefuseNonProtocolHashes;
begin
  CheckKeyedFactoriesByHash(Crypto.Primitives);
end;

procedure TTestCryptoProvider.TestHashCloneIsIndependent;
var
  LHash, LClone: IHash;
begin
  // both should finish as SHA-256("abc")
  LHash := Crypto.Primitives.CreateHash(THashAlgorithm.SHA_256);
  LHash.Update(DecodeHex('61'), 0, 1); // 'a'
  LClone := LHash.Clone;
  LHash.Update(DecodeHex('6263'), 0, 2); // 'bc'
  LClone.Update(DecodeHex('6263'), 0, 2);
  CheckEqualBytes('clone independent', LHash.DoFinal, LClone.DoFinal);
end;

procedure TTestCryptoProvider.TestHashReuseAcrossDoFinal;
var
  LHash, LClone: IHash;
  LMsg, LFirst, LSecond, LFresh: TBytes;
begin
  // a reusable hash object resets itself at DoFinal, so a second use of the same instance must
  // digest identically to a fresh instance
  LMsg := DecodeHex('616263'); // 'abc'
  LHash := Crypto.Primitives.CreateHash(THashAlgorithm.SHA_256);
  LHash.Update(LMsg, 0, System.Length(LMsg));
  LFirst := LHash.DoFinal;
  LHash.Update(LMsg, 0, System.Length(LMsg)); // reuse the same instance
  LSecond := LHash.DoFinal;
  LHash := Crypto.Primitives.CreateHash(THashAlgorithm.SHA_256);
  LHash.Update(LMsg, 0, System.Length(LMsg));
  LFresh := LHash.DoFinal;
  CheckEqualBytes('the reused hash matches its first digest', LFirst, LSecond);
  CheckEqualBytes('and matches a fresh instance', LFresh, LSecond);
  // a clone of a reusable hash must itself reset+reuse after its own DoFinal (the duplicated
  // handle has to carry the reusable attribute)
  LHash := Crypto.Primitives.CreateHash(THashAlgorithm.SHA_256);
  LHash.Update(LMsg, 0, System.Length(LMsg));
  LClone := LHash.Clone;
  LFirst := LClone.DoFinal;
  LClone.Update(LMsg, 0, System.Length(LMsg)); // reuse the clone
  LSecond := LClone.DoFinal;
  CheckEqualBytes('the reused clone matches its first digest', LFirst, LSecond);
  CheckEqualBytes('and the reused clone matches a fresh instance', LFresh, LSecond);
end;

procedure TTestCryptoProvider.TestHmacReuseAcrossDoFinal;
var
  LHmac: IHmac;
  LKey: ISecretBuffer;
  LData, LFirst, LSecond, LFresh: TBytes;
begin
  // a reusable HMAC object re-keys with the same key at DoFinal, so a second use of the same
  // instance must match a fresh instance under the same key
  LKey := TSecretBuffer.From(DecodeHex('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b'));
  LData := DecodeHex('4869205468657265'); // 'Hi There'
  LHmac := Crypto.Primitives.CreateHmac(THashAlgorithm.SHA_256);
  LHmac.Init(LKey);
  LHmac.Update(LData, 0, System.Length(LData));
  LFirst := LHmac.DoFinal;
  LHmac.Update(LData, 0, System.Length(LData)); // reuse the same instance, same key
  LSecond := LHmac.DoFinal;
  LHmac := Crypto.Primitives.CreateHmac(THashAlgorithm.SHA_256);
  LHmac.Init(LKey);
  LHmac.Update(LData, 0, System.Length(LData));
  LFresh := LHmac.DoFinal;
  CheckEqualBytes('the reused HMAC matches its first MAC', LFirst, LSecond);
  CheckEqualBytes('and matches a fresh instance', LFresh, LSecond);
end;

procedure TTestCryptoProvider.TestHmacSha256Kat;
var
  LVec: TStringList;
  LHmac: IHmac;
  LData: TBytes;
begin
  LVec := LoadVectorFields('Crypto/Hmac/HmacSha256.txt');
  try
    LHmac := Crypto.Primitives.CreateHmac(THashAlgorithm.SHA_256);
    LHmac.Init(TSecretBuffer.From(DecodeHex(LVec.Values['key'])));
    LData := DecodeHex(LVec.Values['data']);
    LHmac.Update(LData, 0, System.Length(LData));
    CheckEqualBytes('HMAC-SHA256', DecodeHex(LVec.Values['mac']), LHmac.DoFinal);
  finally
    LVec.Free;
  end;
end;

procedure TTestCryptoProvider.TestHkdfSha256Rfc5869;
var
  LVec: TStringList;
  LHkdf: IHkdf;
  LPrk, LOkm: ISecretBuffer;
begin
  LVec := LoadVectorFields('Crypto/Hkdf/HkdfSha256.txt');
  try
    LHkdf := Crypto.Primitives.CreateHkdf(THashAlgorithm.SHA_256);
    LPrk := LHkdf.Extract(TSecretBuffer.From(DecodeHex(LVec.Values['salt'])),
      TSecretBuffer.From(DecodeHex(LVec.Values['ikm'])));
    CheckEqualBytes('HKDF-Extract PRK', DecodeHex(LVec.Values['prk']),
      SecretBytes(LPrk));
    LOkm := LHkdf.Expand(LPrk, DecodeHex(LVec.Values['info']),
      StrToInt(LVec.Values['length']));
    CheckEqualBytes('HKDF-Expand OKM', DecodeHex(LVec.Values['okm']),
      SecretBytes(LOkm));
  finally
    LVec.Free;
  end;
end;

function TTestCryptoProvider.Rfc5869Vector(const ASaltHex, AIkmHex, AInfoHex, APrkHex,
  AOkmHex: string): THkdfVector;
begin
  Result.Salt := DecodeHex(ASaltHex);
  Result.Ikm := DecodeHex(AIkmHex);
  Result.Info := DecodeHex(AInfoHex);
  Result.Prk := DecodeHex(APrkHex);
  Result.Okm := DecodeHex(AOkmHex);
end;

procedure TTestCryptoProvider.TestHkdfIsSafeAcrossThreads;
const
  WorkerCount = 6;
  Rounds = 3000;
var
  LHkdf: IHkdf;
  LStart: TEvent;
  LVectors: array [0 .. 2] of THkdfVector;
  LWorkers: array [0 .. WorkerCount - 1] of THkdfVectorWorker;
  LI: Int32;
begin
  // RFC 5869 A.1 to A.3 through one object shared by threads: the engine's inbound rekey, outbound
  // rekey and exporter all derive through one key schedule object
  LVectors[0] := Rfc5869Vector('000102030405060708090a0b0c',
    '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b', 'f0f1f2f3f4f5f6f7f8f9',
    '077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5',
    '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865');
  LVectors[1] := Rfc5869Vector('606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f' +
    '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf',
    '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f' +
    '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f',
    'b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf' +
    'd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef' +
    'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff',
    '06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244',
    'b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c' +
    '59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87');
  LVectors[2] := Rfc5869Vector('', '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b', '',
    '19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04',
    '8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8');

  LHkdf := Crypto.Primitives.CreateHkdf(THashAlgorithm.SHA_256);
  LStart := TEvent.Create(nil, True, False, '');
  for LI := 0 to High(LWorkers) do
    LWorkers[LI] := nil;
  try
    // alone first, so a vector that is wrong here is not blamed on the threads
    for LI := 0 to High(LVectors) do
    begin
      LWorkers[LI] := THkdfVectorWorker.Create(LHkdf, LVectors[LI], 1, LStart);
      LStart.SetEvent;
      LWorkers[LI].Start;
      LWorkers[LI].WaitFor;
      CheckEquals(0, LWorkers[LI].Mismatches, 'the RFC 5869 vector holds single-threaded');
      FreeAndNil(LWorkers[LI]);
    end;

    LStart.ResetEvent;
    for LI := 0 to High(LWorkers) do
      LWorkers[LI] := THkdfVectorWorker.Create(LHkdf, LVectors[LI mod System.Length(LVectors)],
        Rounds, LStart);
    for LI := 0 to High(LWorkers) do
      LWorkers[LI].Start;
    LStart.SetEvent;
    for LI := 0 to High(LWorkers) do
    begin
      LWorkers[LI].WaitFor;
      CheckEquals(0, LWorkers[LI].Mismatches, 'concurrent Extract and Expand calls do not interfere');
    end;
  finally
    for LI := 0 to High(LWorkers) do
      LWorkers[LI].Free;
    LStart.Free;
  end;
end;

procedure TTestCryptoProvider.TestHkdfExpandRejectsOverCapAndNegative;
const
  CHashLen = 32;
var
  LHkdf: IHkdf;
  LPrk, LOkm: ISecretBuffer;
  LInfo: TBytes;
  LRaised: Boolean;
begin
  LHkdf := Crypto.Primitives.CreateHkdf(THashAlgorithm.SHA_256);
  LPrk := LHkdf.Extract(TSecretBuffer.From(DecodeHex('000102030405060708090a0b0c0d0e0f')),
    TSecretBuffer.From(DecodeHex('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b')));
  LInfo := DecodeHex('f0f1f2f3f4f5f6f7f8f9');

  LRaised := False;
  try
    LHkdf.Expand(LPrk, LInfo, 255 * CHashLen + 1);
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'Expand beyond 255 * HashLen must raise EArgumentTlsLibException');

  LRaised := False;
  try
    LHkdf.Expand(LPrk, LInfo, -1);
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'Expand with a negative length must raise EArgumentTlsLibException');

  LOkm := LHkdf.Expand(LPrk, LInfo, 255 * CHashLen);
  CheckEquals(255 * CHashLen, LOkm.Len, 'Expand at the exact cap must succeed');
end;

procedure TTestCryptoProvider.TestAesGcmKat;
var
  LVec: TStringList;
  LAead: IAead;
  LNonce, LAad, LExpected, LSealed: TBytes;
begin
  LVec := LoadVectorFields('Crypto/Gcm/Aes128Gcm.txt');
  try
    LAead := Crypto.Primitives.CreateAead(TAeadAlgorithm.AES_128_GCM);
    LAead.Init(TSecretBuffer.From(DecodeHex(LVec.Values['key'])));
    LNonce := DecodeHex(LVec.Values['nonce']);
    LAad := DecodeHex(LVec.Values['aad']);
    LExpected := ConcatBytes(DecodeHex(LVec.Values['ciphertext']),
      DecodeHex(LVec.Values['tag']));
    LSealed := TAeadUtilities.Seal(LAead, LNonce, LAad, DecodeHex(LVec.Values['plaintext']));
    CheckEqualBytes('AES-128-GCM seal', LExpected, LSealed);
    CheckEqualBytes('AES-128-GCM open', DecodeHex(LVec.Values['plaintext']),
      TAeadUtilities.Open(LAead, LNonce, LAad, LSealed));
  finally
    LVec.Free;
  end;
end;

procedure TTestCryptoProvider.TestAes256GcmKat;
var
  LVec: TStringList;
  LAead: IAead;
  LNonce, LAad, LExpected, LSealed: TBytes;
begin
  LVec := LoadVectorFields('Crypto/Gcm/Aes256Gcm.txt');
  try
    LAead := Crypto.Primitives.CreateAead(TAeadAlgorithm.AES_256_GCM);
    CheckEquals(32, LAead.KeySize, 'AES-256-GCM key size');
    LAead.Init(TSecretBuffer.From(DecodeHex(LVec.Values['key'])));
    LNonce := DecodeHex(LVec.Values['nonce']);
    LAad := DecodeHex(LVec.Values['aad']);
    LExpected := ConcatBytes(DecodeHex(LVec.Values['ciphertext']),
      DecodeHex(LVec.Values['tag']));
    LSealed := TAeadUtilities.Seal(LAead, LNonce, LAad, DecodeHex(LVec.Values['plaintext']));
    CheckEqualBytes('AES-256-GCM seal', LExpected, LSealed);
    CheckEqualBytes('AES-256-GCM open', DecodeHex(LVec.Values['plaintext']),
      TAeadUtilities.Open(LAead, LNonce, LAad, LSealed));
  finally
    LVec.Free;
  end;
end;

procedure TTestCryptoProvider.TestAesGcmRoundTrip;
var
  LAead: IAead;
  LNonce, LAad, LPlain, LSealed: TBytes;
begin
  LAead := Crypto.Primitives.CreateAead(TAeadAlgorithm.AES_128_GCM);
  LAead.Init(TSecretBuffer.From(DecodeHex('000102030405060708090a0b0c0d0e0f')));
  LNonce := DecodeHex('101112131415161718191a1b');
  LAad := DecodeHex('cafe');
  LPlain := DecodeHex('48656c6c6f2c20544c5321'); // "Hello, TLS!"
  LSealed := TAeadUtilities.Seal(LAead, LNonce, LAad, LPlain);
  CheckEquals(System.Length(LPlain) + LAead.TagSize, System.Length(LSealed),
    'sealed length = plaintext + tag');
  CheckEqualBytes('AES-GCM round-trip', LPlain, TAeadUtilities.Open(LAead, LNonce, LAad, LSealed));
end;

procedure TTestCryptoProvider.TestChaCha20Poly1305Kat;
var
  LVec: TStringList;
  LAead: IAead;
  LNonce, LAad, LExpected, LSealed: TBytes;
begin
  LVec := LoadVectorFields('Crypto/ChaCha/ChaCha20Poly1305.txt');
  try
    LAead := Crypto.Primitives.CreateAead(TAeadAlgorithm.CHACHA20_POLY1305);
    LAead.Init(TSecretBuffer.From(DecodeHex(LVec.Values['key'])));
    LNonce := DecodeHex(LVec.Values['nonce']);
    LAad := DecodeHex(LVec.Values['aad']);
    LExpected := ConcatBytes(DecodeHex(LVec.Values['ciphertext']),
      DecodeHex(LVec.Values['tag']));
    LSealed := TAeadUtilities.Seal(LAead, LNonce, LAad, DecodeHex(LVec.Values['plaintext']));
    CheckEqualBytes('ChaCha20-Poly1305 seal', LExpected, LSealed);
    CheckEqualBytes('ChaCha20-Poly1305 open', DecodeHex(LVec.Values['plaintext']),
      TAeadUtilities.Open(LAead, LNonce, LAad, LSealed));
  finally
    LVec.Free;
  end;
end;

procedure TTestCryptoProvider.TestAeadOpenAuthFailureRaisesBadRecordMac;
var
  LAead: IAead;
  LNonce, LAad, LSealed: TBytes;
  LRaised: Boolean;
begin
  LAead := Crypto.Primitives.CreateAead(TAeadAlgorithm.AES_128_GCM);
  LAead.Init(TSecretBuffer.From(DecodeHex('000102030405060708090a0b0c0d0e0f')));
  LNonce := DecodeHex('101112131415161718191a1b');
  LAad := DecodeHex('');
  LSealed := TAeadUtilities.Seal(LAead, LNonce, LAad, DecodeHex('deadbeef'));
  // corrupt the last (tag) byte
  LSealed[System.Length(LSealed) - 1] := Byte(LSealed[System.Length(LSealed) - 1] xor $01);
  LRaised := False;
  try
    TAeadUtilities.Open(LAead, LNonce, LAad, LSealed);
  except
    on E: EFatalAlertTlsLibException do
      LRaised := Ord(E.AlertDescription) = Ord(TTlsAlertDescription.BadRecordMac);
  end;
  CheckTrue(LRaised, 'auth failure must raise bad_record_mac');
end;

// (algorithm, key size) for each AEAD suite, so the span tests can loop all three
type
  TAeadSuiteSpec = record
    Algorithm: TAeadAlgorithm;
    KeySize: Int32;
    Name: string;
  end;

const
  AeadSuiteSpecs: array [0 .. 2] of TAeadSuiteSpec = (
    (Algorithm: TAeadAlgorithm.AES_128_GCM; KeySize: 16; Name: 'AES-128-GCM'),
    (Algorithm: TAeadAlgorithm.AES_256_GCM; KeySize: 32; Name: 'AES-256-GCM'),
    (Algorithm: TAeadAlgorithm.CHACHA20_POLY1305; KeySize: 32; Name: 'ChaCha20-Poly1305'));
  AeadSpanSizes: array [0 .. 5] of Int32 = (0, 1, 16, 17, 255, 1400);

procedure TTestCryptoProvider.DoAeadInPlaceRoundTrip(const AProvider: ICryptoProvider);
const
  OFF = 5; // seal at a non-zero offset, as the record layer will
var
  LSi, LZi, LLen, LSealed, LOpened: Int32;
  LKey, LNonce, LAad, LPlain, LRef, LBuf: TBytes;
  LEnc, LDec, LRefAead: IAead;
begin
  for LSi := System.Low(AeadSuiteSpecs) to System.High(AeadSuiteSpecs) do
    for LZi := System.Low(AeadSpanSizes) to System.High(AeadSpanSizes) do
    begin
      LLen := AeadSpanSizes[LZi];
      LKey := PatternBytes(AeadSuiteSpecs[LSi].KeySize, LSi + 1);
      LNonce := PatternBytes(12, LSi + 2);
      LAad := PatternBytes(5, LSi + 3);
      LPlain := PatternBytes(LLen, LSi + 4);
      // allocating reference sealed bytes
      LRefAead := AProvider.Primitives.CreateAead(AeadSuiteSpecs[LSi].Algorithm);
      LRefAead.Init(TSecretBuffer.From(LKey));
      LRef := TAeadUtilities.Seal(LRefAead, LNonce, LAad, LPlain);
      // seal in place into a buffer at OFF, aliasing src = dest
      LBuf := nil;
      SetLength(LBuf, OFF + LLen + 16);
      if LLen > 0 then
        System.Move(LPlain[0], LBuf[OFF], LLen);
      LEnc := AProvider.Primitives.CreateAead(AeadSuiteSpecs[LSi].Algorithm);
      LEnc.Init(TSecretBuffer.From(LKey));
      LSealed := LEnc.Seal(LNonce, LAad, 0, System.Length(LAad), LBuf, OFF, LLen, LBuf, OFF);
      CheckEquals(LLen + 16, LSealed, AeadSuiteSpecs[LSi].Name + ': sealed length');
      CheckEqualBytes(AeadSuiteSpecs[LSi].Name + ': in-place seal matches allocating',
        LRef, System.Copy(LBuf, OFF, LSealed));
      // open in place, aliasing src = dest, and recover the plaintext
      LDec := AProvider.Primitives.CreateAead(AeadSuiteSpecs[LSi].Algorithm);
      LDec.Init(TSecretBuffer.From(LKey));
      LOpened := LDec.Open(LNonce, LAad, 0, System.Length(LAad), LBuf, OFF, LSealed, LBuf, OFF);
      CheckEquals(LLen, LOpened, AeadSuiteSpecs[LSi].Name + ': opened length');
      CheckEqualBytes(AeadSuiteSpecs[LSi].Name + ': in-place open round-trips',
        LPlain, System.Copy(LBuf, OFF, LOpened));
    end;
end;

procedure TTestCryptoProvider.DoAeadOpenTamperWipes(const AProvider: ICryptoProvider);
const
  OFF = 3;
var
  LSi, LI, LSealed: Int32;
  LKey, LNonce, LAad, LPlain, LBuf: TBytes;
  LEnc, LDec: IAead;
  LRaised, LWiped: Boolean;
begin
  // the wipe-on-auth-failure path differs per cipher mode, so assert it for every suite
  for LSi := System.Low(AeadSuiteSpecs) to System.High(AeadSuiteSpecs) do
  begin
    LKey := PatternBytes(AeadSuiteSpecs[LSi].KeySize, LSi + 7);
    LNonce := PatternBytes(12, LSi + 8);
    LAad := PatternBytes(5, LSi + 9);
    LPlain := PatternBytes(64, LSi + 10);
    LBuf := nil;
    SetLength(LBuf, OFF + 64 + 16);
    System.Move(LPlain[0], LBuf[OFF], 64);
    LEnc := AProvider.Primitives.CreateAead(AeadSuiteSpecs[LSi].Algorithm);
    LEnc.Init(TSecretBuffer.From(LKey));
    LSealed := LEnc.Seal(LNonce, LAad, 0, System.Length(LAad), LBuf, OFF, 64, LBuf, OFF);
    LBuf[OFF + LSealed - 1] := Byte(LBuf[OFF + LSealed - 1] xor $01); // corrupt the tag
    LDec := AProvider.Primitives.CreateAead(AeadSuiteSpecs[LSi].Algorithm);
    LDec.Init(TSecretBuffer.From(LKey));
    LRaised := False;
    try
      LDec.Open(LNonce, LAad, 0, System.Length(LAad), LBuf, OFF, LSealed, LBuf, OFF);
    except
      on E: EFatalAlertTlsLibException do
        LRaised := Ord(E.AlertDescription) = Ord(TTlsAlertDescription.BadRecordMac);
    end;
    CheckTrue(LRaised, AeadSuiteSpecs[LSi].Name + ': a tampered tag raises bad_record_mac');
    LWiped := True;
    for LI := OFF to OFF + 64 - 1 do
      if LBuf[LI] <> 0 then
        LWiped := False;
    CheckTrue(LWiped, AeadSuiteSpecs[LSi].Name +
      ': no unverified plaintext is left in the destination after a failed open');
  end;
end;

procedure TTestCryptoProvider.DoAeadSpanGuards(const AProvider: ICryptoProvider);
  function SealRaises(const AAead: IAead; const ANonce, AAad, ASrc: TBytes;
    ASrcOff, ALen: Int32; const ADest: TBytes; ADestOff: Int32): Boolean;
  begin
    Result := False;
    try
      AAead.Seal(ANonce, AAad, 0, System.Length(AAad), ASrc, ASrcOff, ALen, ADest, ADestOff);
    except
      on E: EArgumentTlsLibException do
        Result := True;
    end;
  end;
  function OpenRaisesArg(const AAead: IAead; const ANonce, AAad, ASrc: TBytes;
    ASrcOff, ALen: Int32; const ADest: TBytes; ADestOff: Int32): Boolean;
  begin
    Result := False;
    try
      AAead.Open(ANonce, AAad, 0, System.Length(AAad), ASrc, ASrcOff, ALen, ADest, ADestOff);
    except
      on E: EArgumentTlsLibException do
        Result := True;
    end;
  end;
var
  LKey, LNonce, LAad, LSrc, LDest, LCt, LOut: TBytes;
  LAead, LSealer: IAead;
  LRaised: Boolean;
begin
  LKey := PatternBytes(16, 1);
  LNonce := PatternBytes(12, 2);
  LAad := PatternBytes(5, 3);
  LSrc := PatternBytes(32, 4);
  LDest := nil;
  SetLength(LDest, 32 + 16);
  LAead := AProvider.Primitives.CreateAead(TAeadAlgorithm.AES_128_GCM);
  LAead.Init(TSecretBuffer.From(LKey));
  // Seal guards (validated before any keyed work, so one instance serves them all)
  CheckTrue(SealRaises(LAead, LNonce, LAad, LSrc, -1, 32, LDest, 0),
    'seal: a negative source offset is rejected');
  CheckTrue(SealRaises(LAead, LNonce, LAad, LSrc, 0, 40, LDest, 0),
    'seal: a length past the source end is rejected');
  CheckTrue(SealRaises(LAead, LNonce, LAad, LSrc, 0, 32, LDest, 8),
    'seal: a destination too small for ciphertext + tag is rejected');
  // same array, different offsets: only an exact alias is allowed
  CheckTrue(SealRaises(LAead, LNonce, LAad, LSrc, 0, 8, LSrc, 4),
    'seal: a partial overlap (same array, unequal offset) is rejected');
  // Open guards: produce one valid sealed buffer, then probe the Open-side checks
  LSealer := AProvider.Primitives.CreateAead(TAeadAlgorithm.AES_128_GCM);
  LSealer.Init(TSecretBuffer.From(LKey));
  LCt := TAeadUtilities.Seal(LSealer, LNonce, LAad, LSrc); // 32 + 16 = 48 bytes
  LOut := nil;
  SetLength(LOut, 32);
  CheckTrue(OpenRaisesArg(LAead, LNonce, LAad, LCt, -1, 48, LOut, 0),
    'open: a negative source offset is rejected');
  CheckTrue(OpenRaisesArg(LAead, LNonce, LAad, LCt, 0, 60, LOut, 0),
    'open: a length past the source end is rejected');
  CheckTrue(OpenRaisesArg(LAead, LNonce, LAad, LCt, 0, 48, LOut, 20),
    'open: a destination too small for the plaintext is rejected');
  // a length below the tag size cannot authenticate: bad_record_mac, not an argument error
  LRaised := False;
  try
    LAead.Open(LNonce, LAad, 0, System.Length(LAad), LCt, 0, 8, LOut, 0);
  except
    on E: EFatalAlertTlsLibException do
      LRaised := Ord(E.AlertDescription) = Ord(TTlsAlertDescription.BadRecordMac);
  end;
  CheckTrue(LRaised, 'open: a length shorter than the tag raises bad_record_mac');
end;

procedure TTestCryptoProvider.TestAeadInPlaceRoundTripMatchesAllocating;
begin
  DoAeadInPlaceRoundTrip(Crypto);
end;

procedure TTestCryptoProvider.TestAeadInPlaceOpenTamperWipesDestination;
begin
  DoAeadOpenTamperWipes(Crypto);
end;

procedure TTestCryptoProvider.TestAeadSpanGuardsRejectBadOffsetsAndOverlap;
begin
  DoAeadSpanGuards(Crypto);
end;

function TTestCryptoProvider.PatternBytes(ALength, ASeed: Int32): TBytes;
var
  LI: Int32;
begin
  Result := nil;
  SetLength(Result, ALength);
  for LI := 0 to ALength - 1 do
    Result[LI] := Byte((LI * 31 + ASeed * 17 + 7) and $FF);
end;

function TTestCryptoProvider.CounterNonce(ANonceSize, AIndex: Int32): TBytes;
begin
  Result := nil;
  SetLength(Result, ANonceSize);
  FillChar(Result[0], ANonceSize, 0);
  // a distinct, monotonic nonce per record: the record layer's sequence guarantee
  Result[ANonceSize - 1] := Byte(AIndex and $FF);
  Result[ANonceSize - 2] := Byte((AIndex shr 8) and $FF);
end;

procedure TTestCryptoProvider.CheckAeadReuseParity(AAlgorithm: TAeadAlgorithm;
  AKeySize, AMinLength: Int32);
const
  // varied lengths incl. empty, block boundaries, and off-boundary sizes
  CLengths: array [0 .. 11] of Int32 = (0, 1, 15, 16, 17, 31, 32, 33, 64, 100, 1400, 5);
var
  LReused, LFresh, LOpener: IAead;
  LKey: ISecretBuffer;
  LKeyBytes, LNonce, LAad, LPlain, LViaReused, LViaFresh: TBytes;
  LNonceSize, LI, LRecord, LLen: Int32;
begin
  LKeyBytes := PatternBytes(AKeySize, 99);
  LKey := TSecretBuffer.From(LKeyBytes);
  LReused := Crypto.Primitives.CreateAead(AAlgorithm);
  LReused.Init(LKey);
  LNonceSize := LReused.NonceSize;
  // a long stream: cycle the length matrix many times so the reused cipher is
  // re-Init'd across hundreds of records
  for LRecord := 0 to 299 do
  begin
    LI := LRecord mod System.Length(CLengths);
    // AES-GCM tolerates an empty record; ChaCha20-Poly1305 requires >= 1 byte,
    // which matches TLS (inner plaintext always carries a content-type byte)
    LLen := CLengths[LI];
    if LLen < AMinLength then
      LLen := AMinLength;
    LPlain := PatternBytes(LLen, LRecord);
    // alternate absent / present associated data
    if (LRecord and 1) = 0 then
      LAad := nil
    else
      LAad := PatternBytes(5 + (LRecord mod 11), LRecord + 3);
    LNonce := CounterNonce(LNonceSize, LRecord);
    // reference: a fresh adapter per record reproduces the old create-per-record path
    LFresh := Crypto.Primitives.CreateAead(AAlgorithm);
    LFresh.Init(LKey);
    LViaFresh := TAeadUtilities.Seal(LFresh, LNonce, LAad, LPlain);
    LViaReused := TAeadUtilities.Seal(LReused, LNonce, LAad, LPlain);
    CheckEqualBytes('reused seal == fresh seal', LViaFresh, LViaReused);
    // a fresh opener must round-trip the reused adapter's output
    LOpener := Crypto.Primitives.CreateAead(AAlgorithm);
    LOpener.Init(LKey);
    CheckEqualBytes('open round-trips reused seal', LPlain,
      TAeadUtilities.Open(LOpener, LNonce, LAad, LViaReused));
  end;
end;

procedure TTestCryptoProvider.TestAeadReuseParityAes128Gcm;
begin
  CheckAeadReuseParity(TAeadAlgorithm.AES_128_GCM, 16, 0);
end;

procedure TTestCryptoProvider.TestAeadReuseParityAes256Gcm;
begin
  CheckAeadReuseParity(TAeadAlgorithm.AES_256_GCM, 32, 0);
end;

procedure TTestCryptoProvider.TestAeadReuseParityChaCha20Poly1305;
begin
  CheckAeadReuseParity(TAeadAlgorithm.CHACHA20_POLY1305, 32, 1);
end;

procedure TTestCryptoProvider.TestAeadLongConnectionRoundTrip;
var
  LSender, LReceiver: IAead;
  LKey: ISecretBuffer;
  LNonce, LAad, LPlain, LSealed: TBytes;
  LEpoch, LRecord: Int32;
begin
  // two epochs (a KeyUpdate boundary): each is a fresh sender/receiver pair, and
  // each pair streams many sequential records with monotonic nonces
  for LEpoch := 0 to 1 do
  begin
    LKey := TSecretBuffer.From(PatternBytes(16, 40 + LEpoch));
    LSender := Crypto.Primitives.CreateAead(TAeadAlgorithm.AES_128_GCM);
    LSender.Init(LKey);
    LReceiver := Crypto.Primitives.CreateAead(TAeadAlgorithm.AES_128_GCM);
    LReceiver.Init(LKey);
    for LRecord := 0 to 255 do
    begin
      LPlain := PatternBytes(1 + (LRecord mod 200), LRecord + LEpoch);
      LAad := PatternBytes(5, LRecord);
      LNonce := CounterNonce(LSender.NonceSize, LRecord);
      LSealed := TAeadUtilities.Seal(LSender, LNonce, LAad, LPlain);
      CheckEqualBytes('long-connection record round-trips', LPlain,
        TAeadUtilities.Open(LReceiver, LNonce, LAad, LSealed));
    end;
  end;
end;

procedure TTestCryptoProvider.DoAeadNonceReuseRejected(const AProvider: ICryptoProvider);
var
  LAead: IAead;
  LNonce, LOtherNonce, LAad: TBytes;
  LRaised: Boolean;
begin
  // the reused live cipher lets the provider's encrypt-side guard catch a forced
  // (key, nonce) repeat - a net the old create-per-record adapter never had
  LAead := AProvider.Primitives.CreateAead(TAeadAlgorithm.AES_128_GCM);
  LAead.Init(TSecretBuffer.From(DecodeHex('000102030405060708090a0b0c0d0e0f')));
  LNonce := DecodeHex('101112131415161718191a1b');
  LAad := nil;
  TAeadUtilities.Seal(LAead, LNonce, LAad, DecodeHex('deadbeef'));
  LRaised := False;
  try
    TAeadUtilities.Seal(LAead, LNonce, LAad, DecodeHex('cafebabe'));
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'reusing a (key, nonce) for seal must be rejected');
  // no false positive: a different nonce under the same key still seals
  LOtherNonce := DecodeHex('101112131415161718191a1c');
  CheckEquals(4 + LAead.TagSize,
    System.Length(TAeadUtilities.Seal(LAead, LOtherNonce, LAad, DecodeHex('cafebabe'))),
    'a fresh nonce under the same key seals');
  // the guard tracks the current key: re-keying opens a fresh nonce space
  LAead.Init(TSecretBuffer.From(DecodeHex('0f0e0d0c0b0a09080706050403020100')));
  CheckEquals(4 + LAead.TagSize,
    System.Length(TAeadUtilities.Seal(LAead, LOtherNonce, LAad, DecodeHex('cafebabe'))),
    'the last nonce is forgotten on re-Init');
end;

procedure TTestCryptoProvider.TestAeadNonceReuseRejected;
begin
  DoAeadNonceReuseRejected(Crypto);
end;

procedure TTestCryptoProvider.TestRandomDistinctNonZero;
var
  LRandom: IRandom;
  LA, LB: TBytes;
begin
  LRandom := Crypto.Primitives.GetRandom;
  LA := LRandom.GenerateBytes(32);
  LB := LRandom.GenerateBytes(32);
  CheckEquals(32, System.Length(LA), 'length');
  CheckFalse(IsAllZero(LA), 'draw must not be all zero');
  CheckFalse(AreEqual(LA, LB), 'two draws must differ');
end;

procedure TTestCryptoProvider.TestHasHardwareAesIsStable;
begin
  // the default suite order reads it more than once per pass, so it must not flip
  CheckEquals(Crypto.Primitives.HasHardwareAes, Crypto.Primitives.HasHardwareAes,
    'HasHardwareAes answers the same twice');
end;

procedure TTestCryptoProvider.DoAgreeRejectsForeignKeyHandle(
  const AProvider: ICryptoProvider);
var
  LX, LP: IKeyAgreement;
  LXPriv, LPPriv: IKeyExchangePrivateKey;
  LXPub, LPPub: TBytes;
  LRaised: Boolean;
begin
  LX := AProvider.Primitives.CreateKeyAgreement(TKeyAgreementAlgorithm.X25519);
  LX.GenerateKeyPair(LXPriv, LXPub);
  LP := AProvider.Primitives.CreateKeyAgreement(TKeyAgreementAlgorithm.SECP256R1);
  LP.GenerateKeyPair(LPPriv, LPPub);
  // a same-width foreign scalar must be refused, not agreed under the wrong domain (once an AV)
  LRaised := False;
  try
    LP.Agree(LXPriv, LPPub);
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a P-256 agreement must reject an X25519 key handle');
  LRaised := False;
  try
    LX.Agree(LPPriv, LXPub);
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'an X25519 agreement must reject a P-256 key handle');
end;

procedure TTestCryptoProvider.TestAgreeRejectsForeignKeyHandle;
begin
  DoAgreeRejectsForeignKeyHandle(Crypto);
end;

procedure TTestCryptoProvider.DoAgreeRejectsCompressedPeerPoint(
  const AProvider: ICryptoProvider);
var
  LP: IKeyAgreement;
  LPriv: IKeyExchangePrivateKey;
  LPub, LCompressed, LHybrid: TBytes;
  LI: Int32;
  LRaised: Boolean;
begin
  LP := AProvider.Primitives.CreateKeyAgreement(TKeyAgreementAlgorithm.SECP256R1);
  LP.GenerateKeyPair(LPriv, LPub); // SEC1 uncompressed: 0x04 || X(32) || Y(32)
  // a SEC1 compressed encoding (0x02/0x03 || X, 33 bytes) is forbidden for TLS and HPKE EC points
  // (RFC 9846 4.3.8.2 / RFC 8422 5.1.2 / RFC 9180 7.1.1); the agreement must reject it, never decode it
  SetLength(LCompressed, 1 + 32);
  LCompressed[0] := $02 or (LPub[64] and 1);
  for LI := 1 to 32 do
    LCompressed[LI] := LPub[LI];
  LRaised := False;
  try
    LP.Agree(LPriv, LCompressed);
  except
    on E: EPeerInputTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a P-256 agreement must reject a compressed peer point');
  // a SEC1 hybrid encoding (0x06/0x07 || X || Y) is full 65-byte width, so the length check passes
  // and only the prefix check stops it; DecodePoint would otherwise accept hybrid
  LHybrid := System.Copy(LPub);
  LHybrid[0] := $06 or (LPub[64] and 1);
  LRaised := False;
  try
    LP.Agree(LPriv, LHybrid);
  except
    on E: EPeerInputTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a P-256 agreement must reject a hybrid-form peer point');
end;

procedure TTestCryptoProvider.TestX25519AgreeRejectsWrongLengthPeerKeyAsPeerInput;
var
  LX: IKeyAgreement;
  LPriv: IKeyExchangePrivateKey;
  LPub, LShort, LLong: TBytes;
  LRaised: Boolean;
  LI: Int32;
begin
  LX := Crypto.Primitives.CreateKeyAgreement(TKeyAgreementAlgorithm.X25519);
  LX.GenerateKeyPair(LPriv, LPub);
  LShort := System.Copy(LPub, 0, System.Length(LPub) - 1);
  LLong := ConcatBytes(LPub, TBytes.Create(0));
  // a peer key of the wrong length is peer input (the engine turns it into illegal_parameter), not
  // a raw backend exception
  for LI := 0 to 1 do
  begin
    LRaised := False;
    try
      if LI = 0 then
        LX.Agree(LPriv, LShort)
      else
        LX.Agree(LPriv, LLong);
    except
      on E: EPeerInputTlsLibException do
        LRaised := True;
    end;
    CheckTrue(LRaised, 'a wrong-length X25519 peer key is peer input');
  end;
end;

procedure TTestCryptoProvider.TestAgreeRejectsCompressedPeerPoint;
begin
  DoAgreeRejectsCompressedPeerPoint(Crypto);
end;

procedure TTestCryptoProvider.DoAeadSealWithoutInitRaisesTyped(
  const AProvider: ICryptoProvider);
var
  LAead: IAead;
  LNonce, LDest: TBytes;
  LRaised: Boolean;
begin
  // Seal before Init has no key: a typed state error, never a nil key passed to the mode
  LAead := AProvider.Primitives.CreateAead(TAeadAlgorithm.AES_128_GCM);
  LNonce := DecodeHex('101112131415161718191a1b');
  LDest := nil;
  SetLength(LDest, 4 + LAead.TagSize);
  LRaised := False;
  try
    LAead.Seal(LNonce, nil, 0, 0, DecodeHex('deadbeef'), 0, 4, LDest, 0);
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'sealing before Init raises a typed state error');
end;

procedure TTestCryptoProvider.TestAeadSealWithoutInitRaisesTyped;
begin
  DoAeadSealWithoutInitRaisesTyped(Crypto);
end;

procedure TTestCryptoProvider.TestDerEncodeLengthRoundTripsAcrossForms;
var
  LLengths: array [0 .. 8] of Int32;
  LI: Int32;
  LContent, LTlv: TBytes;
  LTag: Byte;
  LContentOff, LContentLen, LNext: Int32;
begin
  // each length form (short, 0x81, 0x82, 0x83) encodes the minimal way and reads back exactly,
  // including the 65536 boundary that the two-byte form cannot carry
  LLengths[0] := 0;
  LLengths[1] := $7F;
  LLengths[2] := $80;
  LLengths[3] := $FF;
  LLengths[4] := $100;
  LLengths[5] := $FFFF;
  LLengths[6] := $10000;
  LLengths[7] := $10001;
  LLengths[8] := $123456;
  for LI := 0 to System.High(LLengths) do
  begin
    LContent := nil;
    SetLength(LContent, LLengths[LI]);
    LTlv := TDer.Tlv($04, LContent);
    CheckTrue(TDer.ReadTlv(LTlv, 0, LTag, LContentOff, LContentLen, LNext),
      'a TLV with this length form parses');
    CheckEquals(LLengths[LI], LContentLen, 'the encoded length reads back');
    CheckEquals(System.Length(LTlv), LNext, 'the TLV ends where its length says');
  end;
end;

procedure TTestCryptoProvider.TestDerReadTlvRejectsOverflowAndNonMinimalLengths;
var
  LTag: Byte;
  LContentOff, LContentLen, LNext: Int32;
begin
  // tag 0x04, then a 4-byte length 0x7FFFFFFF whose content end would overflow Int32: rejected
  CheckFalse(TDer.ReadTlv(DecodeHex('04847FFFFFFF'), 0, LTag, LContentOff, LContentLen, LNext),
    'an overflowing 4-byte length is rejected');
  // each non-minimal vector carries its full content, so only minimality can refuse it
  CheckFalse(TDer.ReadTlv(DecodeHex('0481050102030405'), 0, LTag, LContentOff, LContentLen, LNext),
    'a length under 0x80 in long form is non-minimal');
  CheckFalse(TDer.ReadTlv(DecodeHex('048200050102030405'), 0, LTag, LContentOff, LContentLen, LNext),
    'a multi-byte length with a leading zero byte is non-minimal');
  CheckFalse(TDer.ReadTlv(DecodeHex('04820080' + StringOfChar('A', 256)), 0, LTag, LContentOff,
    LContentLen, LNext), 'a leading zero byte is non-minimal even when the length is 0x80 or more');
  CheckTrue(TDer.ReadTlv(DecodeHex('048180' + StringOfChar('A', 256)), 0, LTag, LContentOff,
    LContentLen, LNext), 'control: the minimal long form of 128 parses');
  CheckEquals(128, LContentLen, 'long-form content length');
  // the same content under the minimal short form parses
  CheckTrue(TDer.ReadTlv(DecodeHex('04050102030405'), 0, LTag, LContentOff, LContentLen, LNext),
    'control: the minimal encoding of the same TLV parses');
  CheckEquals(5, LContentLen, 'minimal-form content length');
  // a well-formed short-form TLV still parses
  CheckTrue(TDer.ReadTlv(DecodeHex('0403AABBCC'), 0, LTag, LContentOff, LContentLen, LNext),
    'a short-form TLV parses');
  CheckEquals(3, LContentLen, 'short-form content length');
end;

const
  MaskAlgorithms: array [0 .. 2] of TSampleMaskAlgorithm = (TSampleMaskAlgorithm.AES_128,
    TSampleMaskAlgorithm.AES_256, TSampleMaskAlgorithm.CHACHA20);
  MaskKeySizes: array [0 .. 2] of Int32 = (16, 32, 32);

procedure TTestCryptoProvider.CheckMaskKat(AAlgorithm: TSampleMaskAlgorithm;
  const AVec: TStringList; const APrefix: string);
var
  LMask: ISampleMask;
  LExpected, LActual: TBytes;
begin
  LExpected := DecodeHex(AVec.Values[APrefix + '_mask']);
  LMask := Crypto.Primitives.CreateSampleMask(AAlgorithm);
  LMask.Init(TSecretBuffer.From(DecodeHex(AVec.Values[APrefix + '_key'])));
  LActual := nil;
  SetLength(LActual, System.Length(LExpected));
  LMask.Compute(DecodeHex(AVec.Values[APrefix + '_sample']), 0, LActual, 0,
    System.Length(LExpected));
  CheckEqualBytes(APrefix + ' mask', LExpected, LActual);
end;

function TTestCryptoProvider.KeyedMask(AAlgorithm: TSampleMaskAlgorithm;
  ASeed: Int32): ISampleMask;
begin
  Result := Crypto.Primitives.CreateSampleMask(AAlgorithm);
  Result.Init(TSecretBuffer.From(PatternBytes(Result.KeySize, ASeed)));
end;

procedure TTestCryptoProvider.TestAes128SampleMaskKnownAnswers;
var
  LVec: TStringList;
begin
  LVec := LoadVectorFields('Crypto/SampleMask/Aes128.txt');
  try
    CheckMaskKat(TSampleMaskAlgorithm.AES_128, LVec, 'rfc9001_client');
    CheckMaskKat(TSampleMaskAlgorithm.AES_128, LVec, 'rfc9001_server');
    CheckMaskKat(TSampleMaskAlgorithm.AES_128, LVec, 'rfc9369_client');
    CheckMaskKat(TSampleMaskAlgorithm.AES_128, LVec, 'rfc9369_server');
    CheckMaskKat(TSampleMaskAlgorithm.AES_128, LVec, 'fips197');
  finally
    LVec.Free;
  end;
end;

procedure TTestCryptoProvider.TestAes256SampleMaskKnownAnswer;
var
  LVec: TStringList;
begin
  LVec := LoadVectorFields('Crypto/SampleMask/Aes256.txt');
  try
    CheckMaskKat(TSampleMaskAlgorithm.AES_256, LVec, 'fips197');
  finally
    LVec.Free;
  end;
end;

procedure TTestCryptoProvider.TestChaCha20SampleMaskKnownAnswers;
var
  LVec: TStringList;
begin
  LVec := LoadVectorFields('Crypto/SampleMask/ChaCha20.txt');
  try
    CheckMaskKat(TSampleMaskAlgorithm.CHACHA20, LVec, 'rfc9001_chacha');
    CheckMaskKat(TSampleMaskAlgorithm.CHACHA20, LVec, 'rfc9369_chacha');
    CheckMaskKat(TSampleMaskAlgorithm.CHACHA20, LVec, 'rfc8439_block');
  finally
    LVec.Free;
  end;
end;

procedure TTestCryptoProvider.TestChaCha20SampleMaskAtTheCounterLimits;
const
  // the stored cases run in order, so a later one shows nothing carried over from an earlier
  CaseCount = 5;
var
  LVec: TStringList;
  LCase: Int32;
  LExpected, LActual: TBytes;
  LMask: ISampleMask;
begin
  LVec := LoadVectorFields('Crypto/SampleMask/ChaCha20.txt');
  try
    // a sample may name the last block of the 32-bit counter, which must not be refused, and one
    // keyed mask serves every case
    LMask := Crypto.Primitives.CreateSampleMask(TSampleMaskAlgorithm.CHACHA20);
    LMask.Init(TSecretBuffer.From(DecodeHex(LVec.Values['limit_key'])));
    for LCase := 0 to CaseCount - 1 do
    begin
      LExpected := DecodeHex(LVec.Values[Format('limit_%d_mask', [LCase])]);
      LActual := nil;
      SetLength(LActual, System.Length(LExpected));
      LMask.Compute(DecodeHex(LVec.Values[Format('limit_%d_sample', [LCase])]), 0, LActual, 0,
        System.Length(LExpected));
      CheckEqualBytes(Format('counter case %d', [LCase]), LExpected, LActual);
    end;
  finally
    LVec.Free;
  end;
end;

procedure TTestCryptoProvider.TestSampleMaskShorterThanTheBlockIsAPrefix;
var
  LAi, LLen: Int32;
  LMask: ISampleMask;
  LSample, LFull, LShort: TBytes;
begin
  for LAi := System.Low(MaskAlgorithms) to System.High(MaskAlgorithms) do
  begin
    LMask := KeyedMask(MaskAlgorithms[LAi], LAi + 1);
    LSample := PatternBytes(16, LAi + 50);
    LFull := nil;
    SetLength(LFull, 16);
    LMask.Compute(LSample, 0, LFull, 0, 16);
    for LLen := 1 to 15 do
    begin
      LShort := nil;
      SetLength(LShort, LLen);
      LMask.Compute(LSample, 0, LShort, 0, LLen);
      CheckEqualBytes(Format('algorithm %d, length %d', [LAi, LLen]),
        System.Copy(LFull, 0, LLen), LShort);
    end;
  end;
end;

procedure TTestCryptoProvider.TestSampleMaskReportsItsSizes;
var
  LAi: Int32;
  LMask: ISampleMask;
begin
  for LAi := System.Low(MaskAlgorithms) to System.High(MaskAlgorithms) do
  begin
    LMask := Crypto.Primitives.CreateSampleMask(MaskAlgorithms[LAi]);
    CheckEquals(16, LMask.SampleSize, Format('sample size %d', [LAi]));
    CheckEquals(MaskKeySizes[LAi], LMask.KeySize, Format('key size %d', [LAi]));
  end;
end;

procedure TTestCryptoProvider.TestSampleMaskRejectsAWrongKeySize;
var
  LAi: Int32;
  LMask: ISampleMask;
  LRaised: Boolean;
begin
  for LAi := System.Low(MaskAlgorithms) to System.High(MaskAlgorithms) do
  begin
    LMask := Crypto.Primitives.CreateSampleMask(MaskAlgorithms[LAi]);
    LRaised := False;
    try
      LMask.Init(TSecretBuffer.From(PatternBytes(MaskKeySizes[LAi] - 1, 1)));
    except
      on E: EArgumentTlsLibException do
        LRaised := True;
    end;
    CheckTrue(LRaised, Format('algorithm %d: a key one byte short is refused', [LAi]));
    LRaised := False;
    try
      LMask.Init(TSecretBuffer.From(PatternBytes(MaskKeySizes[LAi] + 1, 1)));
    except
      on E: EArgumentTlsLibException do
        LRaised := True;
    end;
    CheckTrue(LRaised, Format('algorithm %d: a key one byte long is refused', [LAi]));
  end;
end;

procedure TTestCryptoProvider.TestSampleMaskBeforeInitRaises;
var
  LAi: Int32;
  LMask: ISampleMask;
  LMaskBytes: TBytes;
  LRaised: Boolean;
begin
  LMaskBytes := nil;
  SetLength(LMaskBytes, 5);
  for LAi := System.Low(MaskAlgorithms) to System.High(MaskAlgorithms) do
  begin
    LMask := Crypto.Primitives.CreateSampleMask(MaskAlgorithms[LAi]);
    LRaised := False;
    try
      LMask.Compute(PatternBytes(16, 1), 0, LMaskBytes, 0, 5);
    except
      on E: EInvalidOperationTlsLibException do
        LRaised := True;
    end;
    CheckTrue(LRaised, Format('algorithm %d: Compute without a key raises', [LAi]));
  end;
end;

procedure TTestCryptoProvider.TestSampleMaskRejectsABadSampleSpan;
var
  LAi: Int32;
  LMask: ISampleMask;
  LMaskBytes: TBytes;

  function Refused(const ASample: TBytes; ASampleOff: Int32): Boolean;
  begin
    Result := False;
    try
      LMask.Compute(ASample, ASampleOff, LMaskBytes, 0, 5);
    except
      on E: EArgumentTlsLibException do
        Result := True;
    end;
  end;

begin
  LMaskBytes := nil;
  SetLength(LMaskBytes, 5);
  for LAi := System.Low(MaskAlgorithms) to System.High(MaskAlgorithms) do
  begin
    LMask := KeyedMask(MaskAlgorithms[LAi], LAi);
    CheckTrue(Refused(PatternBytes(15, 1), 0), Format('%d: a 15-byte sample', [LAi]));
    CheckTrue(Refused(PatternBytes(16, 1), 1), Format('%d: a sample running past the end', [LAi]));
    CheckTrue(Refused(PatternBytes(32, 1), -1), Format('%d: a negative offset', [LAi]));
    CheckTrue(Refused(nil, 0), Format('%d: no sample', [LAi]));
    CheckFalse(Refused(PatternBytes(17, 1), 1), Format('%d: control, a sample ending at the end', [LAi]));
  end;
end;

procedure TTestCryptoProvider.TestSampleMaskRejectsABadMaskSpan;
var
  LAi: Int32;
  LMask: ISampleMask;
  LSample, LMaskBytes: TBytes;

  function Refused(AMaskOff, AMaskLen: Int32): Boolean;
  begin
    Result := False;
    try
      LMask.Compute(LSample, 0, LMaskBytes, AMaskOff, AMaskLen);
    except
      on E: EArgumentTlsLibException do
        Result := True;
    end;
  end;

begin
  LSample := PatternBytes(16, 2);
  LMaskBytes := nil;
  SetLength(LMaskBytes, 20);
  for LAi := System.Low(MaskAlgorithms) to System.High(MaskAlgorithms) do
  begin
    LMask := KeyedMask(MaskAlgorithms[LAi], LAi);
    CheckTrue(Refused(0, 0), Format('%d: an empty mask', [LAi]));
    CheckTrue(Refused(0, 17), Format('%d: a mask longer than the sample', [LAi]));
    CheckTrue(Refused(0, -1), Format('%d: a negative length', [LAi]));
    CheckTrue(Refused(-1, 5), Format('%d: a negative offset', [LAi]));
    CheckTrue(Refused(16, 5), Format('%d: a span past the end', [LAi]));
    CheckFalse(Refused(4, 16), Format('%d: control, a full mask ending at the end', [LAi]));
  end;
end;

procedure TTestCryptoProvider.TestSampleMaskReadsAndWritesAtOffsets;
var
  LAi, LI: Int32;
  LMask: ISampleMask;
  LSample, LWhole, LPlain, LOut: TBytes;
begin
  for LAi := System.Low(MaskAlgorithms) to System.High(MaskAlgorithms) do
  begin
    LMask := KeyedMask(MaskAlgorithms[LAi], LAi + 3);
    LSample := PatternBytes(16, LAi + 9);
    LPlain := nil;
    SetLength(LPlain, 5);
    LMask.Compute(LSample, 0, LPlain, 0, 5);
    // the sample sits mid-buffer, the mask lands mid-buffer between guard bytes
    LWhole := ConcatBytes(PatternBytes(7, 1), ConcatBytes(LSample, PatternBytes(9, 2)));
    LOut := nil;
    SetLength(LOut, 12);
    for LI := 0 to 11 do
      LOut[LI] := $EE;
    LMask.Compute(LWhole, 7, LOut, 3, 5);
    CheckEqualBytes(Format('%d: mask at the offset', [LAi]), LPlain, System.Copy(LOut, 3, 5));
    for LI := 0 to 11 do
      if (LI < 3) or (LI > 7) then
        CheckEquals($EE, LOut[LI], Format('%d: the guard byte %d is untouched', [LAi, LI]));
  end;
end;

procedure TTestCryptoProvider.TestSampleMaskMayShareItsSampleAndMaskArray;
var
  LAi: Int32;
  LMask: ISampleMask;
  LSample, LExpected, LShared: TBytes;
begin
  for LAi := System.Low(MaskAlgorithms) to System.High(MaskAlgorithms) do
  begin
    LMask := KeyedMask(MaskAlgorithms[LAi], LAi + 4);
    LSample := PatternBytes(16, LAi + 12);
    LExpected := nil;
    SetLength(LExpected, 5);
    LMask.Compute(LSample, 0, LExpected, 0, 5);
    LShared := System.Copy(LSample);
    LMask.Compute(LShared, 0, LShared, 0, 5);
    CheckEqualBytes(Format('%d: mask over the sample', [LAi]), LExpected,
      System.Copy(LShared, 0, 5));
  end;
end;

procedure TTestCryptoProvider.TestSampleMaskRekeysOnASecondInit;
var
  LAi: Int32;
  LMask: ISampleMask;
  LSample, LFirst, LSecond, LAgain: TBytes;
begin
  for LAi := System.Low(MaskAlgorithms) to System.High(MaskAlgorithms) do
  begin
    LSample := PatternBytes(16, LAi + 20);
    LMask := KeyedMask(MaskAlgorithms[LAi], 1);
    LFirst := nil;
    SetLength(LFirst, 5);
    LMask.Compute(LSample, 0, LFirst, 0, 5);
    LMask.Init(TSecretBuffer.From(PatternBytes(LMask.KeySize, 2)));
    LSecond := nil;
    SetLength(LSecond, 5);
    LMask.Compute(LSample, 0, LSecond, 0, 5);
    CheckFalse(AreEqual(LFirst, LSecond), Format('%d: a new key gives a new mask', [LAi]));
    LMask.Init(TSecretBuffer.From(PatternBytes(LMask.KeySize, 1)));
    LAgain := nil;
    SetLength(LAgain, 5);
    LMask.Compute(LSample, 0, LAgain, 0, 5);
    CheckEqualBytes(Format('%d: the first key again', [LAi]), LFirst, LAgain);
  end;
end;

procedure TTestCryptoProvider.SealForOpen(AIndex: Int32; out AAead: IAead;
  out ANonce, AAad, APlain, ASealed: TBytes);
var
  LKey: TBytes;
  LSealer: IAead;
begin
  LKey := PatternBytes(AeadSuiteSpecs[AIndex].KeySize, AIndex + 7);
  ANonce := PatternBytes(12, AIndex + 8);
  AAad := PatternBytes(13, AIndex + 9);
  APlain := PatternBytes(64, AIndex + 10);
  LSealer := Crypto.Primitives.CreateAead(AeadSuiteSpecs[AIndex].Algorithm);
  LSealer.Init(TSecretBuffer.From(LKey));
  ASealed := TAeadUtilities.Seal(LSealer, ANonce, AAad, APlain);
  AAead := Crypto.Primitives.CreateAead(AeadSuiteSpecs[AIndex].Algorithm);
  AAead.Init(TSecretBuffer.From(LKey));
end;

procedure TTestCryptoProvider.CheckTryOpenRefuses(const AName: string; const AAead: IAead;
  const ANonce, AAad, ASealed: TBytes; AAadOff, AAadLen: Int32);
var
  LDest: TBytes;
  LWritten: Int32;
  LI: Int32;
  LLeaked: Boolean;
begin
  LDest := nil;
  SetLength(LDest, 64);
  for LI := 0 to 63 do
    LDest[LI] := $A5;
  LWritten := -1;
  CheckFalse(AAead.TryOpen(ANonce, AAad, AAadOff, AAadLen, ASealed, 0, System.Length(ASealed),
    LDest, 0, LWritten), AName + ': refused');
  CheckEquals(0, LWritten, AName + ': no plaintext length');
  // each byte is either untouched or wiped, never a decrypted byte
  LLeaked := False;
  for LI := 0 to 63 do
    if (LDest[LI] <> $A5) and (LDest[LI] <> 0) then
      LLeaked := True;
  CheckFalse(LLeaked, AName + ': no plaintext left in the destination');
end;

procedure TTestCryptoProvider.TestAeadTryOpenMatchesOpen;
var
  LSi, LWritten, LOpened: Int32;
  LAead: IAead;
  LNonce, LAad, LPlain, LSealed, LByTry, LByOpen: TBytes;
begin
  for LSi := System.Low(AeadSuiteSpecs) to System.High(AeadSuiteSpecs) do
  begin
    SealForOpen(LSi, LAead, LNonce, LAad, LPlain, LSealed);
    LByTry := nil;
    SetLength(LByTry, 64);
    CheckTrue(LAead.TryOpen(LNonce, LAad, 0, System.Length(LAad), LSealed, 0,
      System.Length(LSealed), LByTry, 0, LWritten), AeadSuiteSpecs[LSi].Name + ': accepted');
    CheckEquals(64, LWritten, AeadSuiteSpecs[LSi].Name + ': plaintext length');
    CheckEqualBytes(AeadSuiteSpecs[LSi].Name + ' TryOpen', LPlain, LByTry);
    LByOpen := nil;
    SetLength(LByOpen, 64);
    LOpened := LAead.Open(LNonce, LAad, 0, System.Length(LAad), LSealed, 0, System.Length(LSealed), LByOpen, 0);
    CheckEquals(LWritten, LOpened, AeadSuiteSpecs[LSi].Name + ': Open length');
    CheckEqualBytes(AeadSuiteSpecs[LSi].Name + ' Open', LByTry, LByOpen);
  end;
end;

procedure TTestCryptoProvider.TestAeadTryOpenRefusesATamperedTag;
var
  LSi: Int32;
  LAead: IAead;
  LNonce, LAad, LPlain, LSealed: TBytes;
begin
  for LSi := System.Low(AeadSuiteSpecs) to System.High(AeadSuiteSpecs) do
  begin
    SealForOpen(LSi, LAead, LNonce, LAad, LPlain, LSealed);
    LSealed[System.High(LSealed)] := Byte(LSealed[System.High(LSealed)] xor $01);
    CheckTryOpenRefuses(AeadSuiteSpecs[LSi].Name, LAead, LNonce, LAad, LSealed, 0,
      System.Length(LAad));
  end;
end;

procedure TTestCryptoProvider.TestAeadTryOpenRefusesATamperedCiphertext;
var
  LSi: Int32;
  LAead: IAead;
  LNonce, LAad, LPlain, LSealed: TBytes;
begin
  for LSi := System.Low(AeadSuiteSpecs) to System.High(AeadSuiteSpecs) do
  begin
    SealForOpen(LSi, LAead, LNonce, LAad, LPlain, LSealed);
    LSealed[10] := Byte(LSealed[10] xor $80);
    CheckTryOpenRefuses(AeadSuiteSpecs[LSi].Name, LAead, LNonce, LAad, LSealed, 0,
      System.Length(LAad));
  end;
end;

procedure TTestCryptoProvider.TestAeadTryOpenRefusesTamperedAssociatedData;
var
  LSi: Int32;
  LAead: IAead;
  LNonce, LAad, LPlain, LSealed: TBytes;
begin
  for LSi := System.Low(AeadSuiteSpecs) to System.High(AeadSuiteSpecs) do
  begin
    SealForOpen(LSi, LAead, LNonce, LAad, LPlain, LSealed);
    // the data one byte short, then a byte changed
    CheckTryOpenRefuses(AeadSuiteSpecs[LSi].Name + ' short data', LAead, LNonce, LAad, LSealed,
      0, System.Length(LAad) - 1);
    LAad[3] := Byte(LAad[3] xor $01);
    CheckTryOpenRefuses(AeadSuiteSpecs[LSi].Name + ' changed data', LAead, LNonce, LAad,
      LSealed, 0, System.Length(LAad));
  end;
end;

procedure TTestCryptoProvider.TestAeadTryOpenRefusesAnInputShorterThanTheTag;
var
  LSi, LWritten: Int32;
  LAead: IAead;
  LNonce, LAad, LPlain, LSealed, LDest: TBytes;
begin
  for LSi := System.Low(AeadSuiteSpecs) to System.High(AeadSuiteSpecs) do
  begin
    SealForOpen(LSi, LAead, LNonce, LAad, LPlain, LSealed);
    LDest := nil;
    SetLength(LDest, 8);
    LWritten := -1;
    CheckFalse(LAead.TryOpen(LNonce, LAad, 0, System.Length(LAad), LSealed, 0,
      LAead.TagSize - 1, LDest, 0, LWritten), AeadSuiteSpecs[LSi].Name + ': refused');
    CheckEquals(0, LWritten, AeadSuiteSpecs[LSi].Name + ': no plaintext length');
    LWritten := -1;
    CheckFalse(LAead.TryOpen(LNonce, LAad, 0, System.Length(LAad), LSealed, 0, 0, LDest, 0,
      LWritten), AeadSuiteSpecs[LSi].Name + ': empty input refused');
  end;
end;

procedure TTestCryptoProvider.TestAeadTryOpenStillRaisesOnABadArgument;
var
  LSi, LWritten: Int32;
  LAead: IAead;
  LNonce, LAad, LPlain, LSealed, LDest: TBytes;
  LRaised: Boolean;
begin
  for LSi := System.Low(AeadSuiteSpecs) to System.High(AeadSuiteSpecs) do
  begin
    SealForOpen(LSi, LAead, LNonce, LAad, LPlain, LSealed);
    LDest := nil;
    SetLength(LDest, 64);
    LRaised := False;
    try
      LAead.TryOpen(System.Copy(LNonce, 0, 11), LAad, 0, System.Length(LAad), LSealed, 0,
        System.Length(LSealed), LDest, 0, LWritten);
    except
      on E: EArgumentTlsLibException do
        LRaised := True;
    end;
    CheckTrue(LRaised, AeadSuiteSpecs[LSi].Name + ': a wrong nonce size is an argument error');
    LRaised := False;
    try
      LAead.TryOpen(LNonce, LAad, 0, System.Length(LAad), LSealed, 0, System.Length(LSealed),
        LDest, 60, LWritten);
    except
      on E: EArgumentTlsLibException do
        LRaised := True;
    end;
    CheckTrue(LRaised, AeadSuiteSpecs[LSi].Name + ': a destination too small is an argument error');
  end;
end;

procedure TTestCryptoProvider.TestAeadAadSpanSealMatchesTheArraySeal;
var
  LSi, LSealedLen: Int32;
  LKey, LNonce, LAad, LPlain, LByArray, LBySpan, LBuffer: TBytes;
  LA, LB: IAead;
begin
  for LSi := System.Low(AeadSuiteSpecs) to System.High(AeadSuiteSpecs) do
  begin
    LKey := PatternBytes(AeadSuiteSpecs[LSi].KeySize, LSi + 1);
    LNonce := PatternBytes(12, LSi + 2);
    LAad := PatternBytes(13, LSi + 3);
    LPlain := PatternBytes(40, LSi + 4);
    LA := Crypto.Primitives.CreateAead(AeadSuiteSpecs[LSi].Algorithm);
    LA.Init(TSecretBuffer.From(LKey));
    LByArray := TAeadUtilities.Seal(LA, LNonce, LAad, LPlain);
    // the same data as a span of a larger buffer, with other bytes either side
    LBuffer := ConcatBytes(PatternBytes(6, 9), ConcatBytes(LAad, PatternBytes(5, 8)));
    LB := Crypto.Primitives.CreateAead(AeadSuiteSpecs[LSi].Algorithm);
    LB.Init(TSecretBuffer.From(LKey));
    LBySpan := nil;
    SetLength(LBySpan, System.Length(LPlain) + LB.TagSize);
    LSealedLen := LB.Seal(LNonce, LBuffer, 6, System.Length(LAad), LPlain, 0,
      System.Length(LPlain), LBySpan, 0);
    CheckEquals(System.Length(LByArray), LSealedLen, AeadSuiteSpecs[LSi].Name + ': length');
    CheckEqualBytes(AeadSuiteSpecs[LSi].Name + ' span seal', LByArray, LBySpan);
  end;
end;

procedure TTestCryptoProvider.TestAeadAadSpanOpenMatchesTheArrayOpen;
var
  LSi, LWritten, LOpened: Int32;
  LAead: IAead;
  LNonce, LAad, LPlain, LSealed, LBuffer, LBySpan, LByTry: TBytes;
begin
  for LSi := System.Low(AeadSuiteSpecs) to System.High(AeadSuiteSpecs) do
  begin
    SealForOpen(LSi, LAead, LNonce, LAad, LPlain, LSealed);
    LBuffer := ConcatBytes(PatternBytes(6, 9), ConcatBytes(LAad, PatternBytes(5, 8)));
    LBySpan := nil;
    SetLength(LBySpan, 64);
    LOpened := LAead.Open(LNonce, LBuffer, 6, System.Length(LAad), LSealed, 0,
      System.Length(LSealed), LBySpan, 0);
    CheckEquals(64, LOpened, AeadSuiteSpecs[LSi].Name + ': Open length');
    CheckEqualBytes(AeadSuiteSpecs[LSi].Name + ' span open', LPlain, LBySpan);
    LByTry := nil;
    SetLength(LByTry, 64);
    CheckTrue(LAead.TryOpen(LNonce, LBuffer, 6, System.Length(LAad), LSealed, 0,
      System.Length(LSealed), LByTry, 0, LWritten), AeadSuiteSpecs[LSi].Name + ': TryOpen');
    CheckEqualBytes(AeadSuiteSpecs[LSi].Name + ' span TryOpen', LPlain, LByTry);
    // a span one byte off no longer authenticates
    CheckTryOpenRefuses(AeadSuiteSpecs[LSi].Name + ' shifted span', LAead, LNonce, LBuffer,
      LSealed, 5, System.Length(LAad));
  end;
end;

procedure TTestCryptoProvider.TestAeadAadSpanOpenRaisesBadRecordMac;
var
  LSi: Int32;
  LAead: IAead;
  LNonce, LAad, LPlain, LSealed, LDest: TBytes;
  LRaised: Boolean;
begin
  for LSi := System.Low(AeadSuiteSpecs) to System.High(AeadSuiteSpecs) do
  begin
    SealForOpen(LSi, LAead, LNonce, LAad, LPlain, LSealed);
    LSealed[System.High(LSealed)] := Byte(LSealed[System.High(LSealed)] xor $01);
    LDest := nil;
    SetLength(LDest, 64);
    LRaised := False;
    try
      LAead.Open(LNonce, LAad, 0, System.Length(LAad), LSealed, 0, System.Length(LSealed),
        LDest, 0);
    except
      on E: EFatalAlertTlsLibException do
        LRaised := Ord(E.AlertDescription) = Ord(TTlsAlertDescription.BadRecordMac);
    end;
    CheckTrue(LRaised, AeadSuiteSpecs[LSi].Name + ': a tampered tag raises bad_record_mac');
  end;
end;

procedure TTestCryptoProvider.TestAeadAadSpanGuards;
var
  LSi, LWritten: Int32;
  LAead: IAead;
  LNonce, LAad, LPlain, LSealed, LDest: TBytes;

  function SpanRefused(AOff, ALen: Int32): Boolean;
  begin
    Result := False;
    try
      LAead.Open(LNonce, LAad, AOff, ALen, LSealed, 0, System.Length(LSealed), LDest, 0);
    except
      on E: EArgumentTlsLibException do
        Result := True;
    end;
  end;

  function SealSpanRefused(AOff, ALen: Int32): Boolean;
  begin
    Result := False;
    try
      LAead.Seal(PatternBytes(12, 1), LAad, AOff, ALen, LPlain, 0, 8, LDest, 0);
    except
      on E: EArgumentTlsLibException do
        Result := True;
    end;
  end;

  function TryOpenSpanRefused(AOff, ALen: Int32): Boolean;
  begin
    Result := False;
    try
      LAead.TryOpen(LNonce, LAad, AOff, ALen, LSealed, 0, System.Length(LSealed), LDest, 0,
        LWritten);
    except
      on E: EArgumentTlsLibException do
        Result := True;
    end;
  end;

begin
  for LSi := System.Low(AeadSuiteSpecs) to System.High(AeadSuiteSpecs) do
  begin
    SealForOpen(LSi, LAead, LNonce, LAad, LPlain, LSealed);
    LDest := nil;
    SetLength(LDest, 80);
    CheckTrue(SpanRefused(-1, 4), AeadSuiteSpecs[LSi].Name + ': Open, a negative offset');
    CheckTrue(SpanRefused(0, -1), AeadSuiteSpecs[LSi].Name + ': Open, a negative length');
    CheckTrue(SpanRefused(10, 4), AeadSuiteSpecs[LSi].Name + ': Open, a span past the end');
    CheckTrue(TryOpenSpanRefused(-1, 4), AeadSuiteSpecs[LSi].Name + ': TryOpen, a negative offset');
    CheckTrue(TryOpenSpanRefused(0, 14), AeadSuiteSpecs[LSi].Name + ': TryOpen, a span past the end');
    CheckTrue(SealSpanRefused(0, 14), AeadSuiteSpecs[LSi].Name + ': Seal, a span past the end');
    CheckTrue(SealSpanRefused(-1, 4), AeadSuiteSpecs[LSi].Name + ': Seal, a negative offset');
  end;
end;

procedure TTestCryptoProvider.TestAeadAadSpanOverflowingOffsetIsRefused;
var
  LSi, LOp, LWritten: Int32;
  LAead: IAead;
  LNonce, LAad, LPlain, LSealed, LDest: TBytes;

  function Refused(AOp, AOff, ALen: Int32): Boolean;
  begin
    Result := False;
    try
      case AOp of
        0:
          LAead.Seal(PatternBytes(12, 1), LAad, AOff, ALen, LPlain, 0, 8, LDest, 0);
        1:
          LAead.Open(LNonce, LAad, AOff, ALen, LSealed, 0, System.Length(LSealed), LDest, 0);
      else
        LAead.TryOpen(LNonce, LAad, AOff, ALen, LSealed, 0, System.Length(LSealed), LDest, 0,
          LWritten);
      end;
    except
      on E: EArgumentTlsLibException do
        Result := True;
    end;
  end;

begin
  for LSi := System.Low(AeadSuiteSpecs) to System.High(AeadSuiteSpecs) do
  begin
    SealForOpen(LSi, LAead, LNonce, LAad, LPlain, LSealed);
    LDest := nil;
    SetLength(LDest, 80);
    for LOp := 0 to 2 do
    begin
      CheckTrue(Refused(LOp, High(Int32), 1), Format('%s op %d: the largest offset', [
        AeadSuiteSpecs[LSi].Name, LOp]));
      CheckTrue(Refused(LOp, 1, High(Int32)), Format('%s op %d: the largest length', [
        AeadSuiteSpecs[LSi].Name, LOp]));
    end;
  end;
end;

procedure TTestCryptoProvider.TestAeadEmptyAadSpanAtTheEndIsAccepted;
var
  LSi, LWritten: Int32;
  LKey, LNonce, LAad, LPlain, LSealed, LSpanSealed, LRefSealed, LOpened: TBytes;
  LOpener, LSealer, LRef: IAead;
begin
  for LSi := System.Low(AeadSuiteSpecs) to System.High(AeadSuiteSpecs) do
  begin
    SealForOpen(LSi, LOpener, LNonce, LAad, LPlain, LSealed);
    LKey := PatternBytes(AeadSuiteSpecs[LSi].KeySize, LSi + 7);
    // an empty span at the end of a non-empty array is no associated data at all
    LSealer := Crypto.Primitives.CreateAead(AeadSuiteSpecs[LSi].Algorithm);
    LSealer.Init(TSecretBuffer.From(LKey));
    LSpanSealed := nil;
    SetLength(LSpanSealed, System.Length(LPlain) + LSealer.TagSize);
    LSealer.Seal(LNonce, LAad, System.Length(LAad), 0, LPlain, 0, System.Length(LPlain),
      LSpanSealed, 0);
    LRef := Crypto.Primitives.CreateAead(AeadSuiteSpecs[LSi].Algorithm);
    LRef.Init(TSecretBuffer.From(LKey));
    LRefSealed := TAeadUtilities.Seal(LRef, LNonce, nil, LPlain);
    CheckEqualBytes(AeadSuiteSpecs[LSi].Name + ' seal', LRefSealed, LSpanSealed);
    LOpened := nil;
    SetLength(LOpened, System.Length(LPlain));
    CheckTrue(LOpener.TryOpen(LNonce, LAad, System.Length(LAad), 0, LSpanSealed, 0,
      System.Length(LSpanSealed), LOpened, 0, LWritten), AeadSuiteSpecs[LSi].Name + ' open');
    CheckEqualBytes(AeadSuiteSpecs[LSi].Name + ' plaintext', LPlain, LOpened);
  end;
end;

procedure TTestCryptoProvider.TestAeadTryOpenRaisesOnABadArgumentBeforeAShortInput;
var
  LSi, LWritten: Int32;
  LAead: IAead;
  LNonce, LAad, LPlain, LSealed, LDest: TBytes;

  function Raises(const ANonce: TBytes; AAadOff, ASrcOff, ALen: Int32): Boolean;
  begin
    Result := False;
    try
      LAead.TryOpen(ANonce, LAad, AAadOff, 4, LSealed, ASrcOff, ALen, LDest, 0, LWritten);
    except
      on E: EArgumentTlsLibException do
        Result := True;
    end;
  end;

begin
  for LSi := System.Low(AeadSuiteSpecs) to System.High(AeadSuiteSpecs) do
  begin
    SealForOpen(LSi, LAead, LNonce, LAad, LPlain, LSealed);
    LDest := nil;
    SetLength(LDest, 8);
    CheckFalse(Raises(LNonce, 0, 0, LAead.TagSize - 1), AeadSuiteSpecs[LSi].Name +
      ': control, a well-formed short input is a failed authentication');
    CheckTrue(Raises(LNonce, -1, 0, LAead.TagSize - 1), AeadSuiteSpecs[LSi].Name +
      ': a short input with a bad associated-data span');
    CheckTrue(Raises(System.Copy(LNonce, 0, 11), 0, 0, LAead.TagSize - 1),
      AeadSuiteSpecs[LSi].Name + ': a short input with a wrong nonce size');
    CheckTrue(Raises(LNonce, 0, 0, -1), AeadSuiteSpecs[LSi].Name + ': a negative length');
    CheckTrue(Raises(LNonce, 0, System.Length(LSealed), 4), AeadSuiteSpecs[LSi].Name +
      ': a short input beyond the source');
  end;
end;

procedure TTestCryptoProvider.TestAeadAadSpansOfChangingLengthsOnOneInstance;
const
  // more distinct lengths than the provider keeps copies for, with repeats and an empty span
  Lengths: array [0 .. 16] of Int32 = (13, 5, 20, 0, 7, 13, 5, 1, 2, 3, 4, 6, 8, 9, 10, 11, 13);
var
  LSi, LI, LLen, LOff: Int32;
  LKey, LNonce, LBuffer, LPlain, LExact, LSealedSpan, LSealedRef, LOpened: TBytes;
  LSealer, LOpener, LRef: IAead;
begin
  for LSi := System.Low(AeadSuiteSpecs) to System.High(AeadSuiteSpecs) do
  begin
    LKey := PatternBytes(AeadSuiteSpecs[LSi].KeySize, LSi + 1);
    LBuffer := PatternBytes(64, LSi + 2);
    LPlain := PatternBytes(40, LSi + 3);
    LSealer := Crypto.Primitives.CreateAead(AeadSuiteSpecs[LSi].Algorithm);
    LSealer.Init(TSecretBuffer.From(LKey));
    LOpener := Crypto.Primitives.CreateAead(AeadSuiteSpecs[LSi].Algorithm);
    LOpener.Init(TSecretBuffer.From(LKey));
    for LI := System.Low(Lengths) to System.High(Lengths) do
    begin
      LLen := Lengths[LI];
      LOff := LI mod 5;
      LNonce := PatternBytes(12, LI + 30);
      LExact := System.Copy(LBuffer, LOff, LLen);
      LRef := Crypto.Primitives.CreateAead(AeadSuiteSpecs[LSi].Algorithm);
      LRef.Init(TSecretBuffer.From(LKey));
      LSealedRef := TAeadUtilities.Seal(LRef, LNonce, LExact, LPlain);
      LSealedSpan := nil;
      SetLength(LSealedSpan, System.Length(LSealedRef));
      LSealer.Seal(LNonce, LBuffer, LOff, LLen, LPlain, 0, System.Length(LPlain), LSealedSpan, 0);
      CheckEqualBytes(Format('%s: seal with a span of %d at %d', [AeadSuiteSpecs[LSi].Name,
        LLen, LOff]), LSealedRef, LSealedSpan);
      LOpened := nil;
      SetLength(LOpened, System.Length(LPlain));
      LOpener.Open(LNonce, LBuffer, LOff, LLen, LSealedSpan, 0, System.Length(LSealedSpan),
        LOpened, 0);
      CheckEqualBytes(Format('%s: open with a span of %d at %d', [AeadSuiteSpecs[LSi].Name,
        LLen, LOff]), LPlain, LOpened);
    end;
  end;
end;

procedure TTestCryptoProvider.TestAeadRepeatedAadSpansOfOneLengthStayCorrect;
var
  LSi, LI: Int32;
  LKey, LNonce, LBuffer, LPlain, LSealedSpan, LSealedRef: TBytes;
  LSealer, LRef: IAead;
begin
  // the same span length every call but new content, so a stale reused copy would show
  for LSi := System.Low(AeadSuiteSpecs) to System.High(AeadSuiteSpecs) do
  begin
    LKey := PatternBytes(AeadSuiteSpecs[LSi].KeySize, LSi + 1);
    LPlain := PatternBytes(40, LSi + 3);
    LSealer := Crypto.Primitives.CreateAead(AeadSuiteSpecs[LSi].Algorithm);
    LSealer.Init(TSecretBuffer.From(LKey));
    for LI := 0 to 11 do
    begin
      LBuffer := PatternBytes(32, LI * 7 + LSi);
      LNonce := PatternBytes(12, LI + 50);
      LRef := Crypto.Primitives.CreateAead(AeadSuiteSpecs[LSi].Algorithm);
      LRef.Init(TSecretBuffer.From(LKey));
      LSealedRef := TAeadUtilities.Seal(LRef, LNonce, System.Copy(LBuffer, 3, 13), LPlain);
      LSealedSpan := nil;
      SetLength(LSealedSpan, System.Length(LSealedRef));
      LSealer.Seal(LNonce, LBuffer, 3, 13, LPlain, 0, System.Length(LPlain), LSealedSpan, 0);
      CheckEqualBytes(Format('%s: call %d', [AeadSuiteSpecs[LSi].Name, LI]), LSealedRef,
        LSealedSpan);
    end;
  end;
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestCryptoProvider);
{$ELSE}
  RegisterTest(TTestCryptoProvider.Suite);
{$ENDIF FPC}

end.
