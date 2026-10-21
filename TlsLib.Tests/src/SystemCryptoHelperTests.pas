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
  Classes,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  TlpCryptoDomainTypes,
  TlpICryptoProvider,
  TlpICryptoBackendReport,
  TlpSystemCryptoTypes,
  TlpSystemCryptoStrictness,
  TlpINegotiation,
  TlpSignatureSchemeRegistry,
  TlpISecretBuffer,
  TlpISigningKey,
  TlpImportedCredential,
  TlpSecretBuffer,
  TlpArrayUtilities,
  TlpPem,
  TlpTlsLibExceptions,
  TlpHkdfComposition,
  TlpSignatureEncoding,
  TlpEcPrivateScalar,
  TlpSystemCryptoBase,
  MockCryptoProvider,
  MockSystemCrypto,
  TlsLibTestProviders,
  TlsLibTestBase;

type
  /// <summary>What the helper suites share: the portable provider and the key and PKCS#12
  /// fixtures. It has no tests of its own and is never registered.</summary>
  TSystemCryptoHelperTestCase = class abstract(TTlsLibAlgorithmTestCase)
  strict protected
    FKeys: TStringList;
    FPfx: TStringList;
    function CreateCrypto: ICryptoProvider; override;
  protected
    procedure SetUp; override;
  end;

  /// <summary>The platform-neutral helpers the native crypto overlays share, run over the
  /// portable provider's primitives so every platform and compiler exercises them.</summary>
  TTestSystemCryptoHelpers = class(TSystemCryptoHelperTestCase)
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
    // the class and message of the exception Expand raises for ALength, '' when it raises none
    function ExpandFailure(AAlgorithm: THashAlgorithm; ALength: Int32): string;
    // the failure Expand gives for an over-cap length
    function TooLongFailure(ALength, ACap: Int32): string;
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

  /// <summary>Records what the native import hook is handed; Served is its key, nil
  /// declines.</summary>
  TRecordingSigning = class(TForwardingSigningCrypto)
  public
  var
    Served: ISigningKey;
    Calls: Int32;
    SeenRef: TBytes;
    SeenCopy: TBytes;
    SeenPassword: ISecretBuffer;
  strict protected
    function TryImportNative(const ADer: TBytes; const APassword: ISecretBuffer;
      out AKey: ISigningKey): Boolean; override;
  end;

  /// <summary>Exposes the bytes a native signer and verifier have accumulated.</summary>
  TExposedSignatureInput = class(TSignatureInputBase)
  public
    property Buffered: TBytes read FBuffer;
  end;

  /// <summary>The ECDSA signature DER codec: RFC 6979 A.2.5 values, round trips, the portable
  /// signer as an independent encoder and the non-strict encodings the decoder refuses.</summary>
  TTestEcdsaSignatureEncoding = class(TSystemCryptoHelperTestCase)
  strict private
    function RepeatHex(const AUnit: string; ACount: Int32): string;
    function PaddedHex(const AHex: string; AFieldSize: Int32): string;
    function Decodes(const AHex: string; AFieldSize: Int32; out ARaw: TBytes): Boolean;
    procedure CheckRejects(const AName, AHex: string; AFieldSize: Int32);
    procedure CheckDecodesTo(const AName, ADerHex, ARHex, ASHex: string; AFieldSize: Int32);
    procedure CheckEncodes(const AName, ARawHex, ADerHex: string);
    procedure CheckRoundTrip(const AName: string; const ARaw: TBytes);
    procedure CheckRandomRoundTrips(AFieldSize: Int32);
    procedure CheckPortableSignatures(const AKeyField: string; AScheme: TSignatureScheme;
      AFieldSize: Int32);
  published
    procedure TestEncodeRfc6979Sha256Sample;
    procedure TestEncodeRfc6979Sha224Sample;
    procedure TestEncodeRfc6979Sha1Sample;
    procedure TestDecodeRfc6979Sha256Sample;
    procedure TestDecodeRfc6979Sha224Sample;
    procedure TestDecodeRfc6979Sha1Sample;
    procedure TestEncodeDropsLeadingZeroBytes;
    procedure TestEncodeP521UsesSingleByteLongFormLength;
    procedure TestRoundTripRandomP256;
    procedure TestRoundTripRandomP384;
    procedure TestRoundTripRandomP521;
    procedure TestRoundTripTopByteZero;
    procedure TestRoundTripTopBitSet;
    procedure TestRoundTripSingleLowByte;
    procedure TestDecodeAcceptsPortableP256Signatures;
    procedure TestDecodeAcceptsPortableP384Signatures;
    procedure TestDecodeAcceptsPortableP521Signatures;
    procedure TestDecodeAcceptsMinimalOnes;
    procedure TestDecodeAcceptsSignPaddedHighBit;
    procedure TestDecodeAcceptsFullWidthSignPaddedValue;
    procedure TestDecodeAcceptsWideValueAtLargerField;
    procedure TestDecodeRejectsEmpty;
    procedure TestDecodeRejectsSingleByte;
    procedure TestDecodeRejectsEmptySequence;
    procedure TestDecodeRejectsWrongOuterTag;
    procedure TestDecodeRejectsTrailingByte;
    procedure TestDecodeRejectsSequenceLengthOneShort;
    procedure TestDecodeRejectsSequenceLengthOneLong;
    procedure TestDecodeRejectsNonMinimalLongFormSequenceLength;
    procedure TestDecodeRejectsTwoByteLongFormSequenceLength;
    procedure TestDecodeRejectsWrongFirstElementTag;
    procedure TestDecodeRejectsWrongSecondElementTag;
    procedure TestDecodeRejectsLongFormIntegerLength;
    procedure TestDecodeRejectsEmptyInteger;
    procedure TestDecodeRejectsNegativeR;
    procedure TestDecodeRejectsNegativeS;
    procedure TestDecodeRejectsZeroPaddedR;
    procedure TestDecodeRejectsZeroPaddedS;
    procedure TestDecodeRejectsZeroR;
    procedure TestDecodeRejectsZeroS;
    procedure TestDecodeRejectsRWiderThanField;
    procedure TestDecodeRejectsSWiderThanField;
    procedure TestDecodeRejectsThirdInteger;
    procedure TestDecodeRejectsMissingS;
    procedure TestDecodeRejectsIntegerRunningPastEnd;
  end;

  /// <summary>The PKCS#1 v1.5 DigestInfo builder against the RFC 8017 9.2 Note 1
  /// prefixes.</summary>
  TTestPkcs1DigestInfo = class(TSystemCryptoHelperTestCase)
  strict private
    function AscendingDigest(ALength: Int32): TBytes;
    procedure CheckDigestInfo(AScheme: TSignatureScheme; AHashLength: Int32;
      const APrefixHex: string);
  published
    procedure TestSha256IsNote1Prefixed;
    procedure TestSha384IsNote1Prefixed;
    procedure TestSha512IsNote1Prefixed;
    procedure TestPssSchemeGivesNil;
    procedure TestEcdsaSchemeGivesNil;
    procedure TestEd25519SchemeGivesNil;
    procedure TestDigestOneByteShortGivesNil;
    procedure TestDigestOneByteLongGivesNil;
    procedure TestEmptyDigestGivesNil;
    procedure TestAnotherHashLengthGivesNil;
  end;

  /// <summary>The span checks and accumulation of the buffer native signers share.</summary>
  TTestSignatureInputBuffer = class(TSystemCryptoHelperTestCase)
  strict private
  var
    FHolder: IInterface;
    FBuffer: TExposedSignatureInput;
    function UpdateRaises(const AData: TBytes; AOffset, ALength: Int32): Boolean;
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestNegativeOffsetRaises;
    procedure TestNegativeLengthRaises;
    procedure TestSpanPastTheEndRaises;
    procedure TestEmptySpanPastTheEndRaises;
    procedure TestOffsetPlusLengthOverflowRaises;
    procedure TestEmptySpanAtTheEndIsNoOp;
    procedure TestSpanEndingAtTheEndIsAccepted;
    procedure TestSpansConcatenateInOrder;
  end;

  /// <summary>The key-import routing of the native signing base: the PEM first-block rule, the
  /// password and wipe handling around the native hook, and the forward-to-inner
  /// defaults.</summary>
  TTestForwardingSigningCrypto = class(TSystemCryptoHelperTestCase)
  strict private
  var
    FRecording: TRecordingSigning;
    FSigning: ISigningCrypto;
    function KeyBytes(const AField: string): TBytes;
    function ServedKey: ISigningKey;
    function ImportFailure(const ASigning: ISigningCrypto; const AData: TBytes;
      const APassword: ISecretBuffer): string;
    function SignedAndVerified(const ASigned, AVerified: TBytes): Boolean;
    procedure CheckSpki(const AName, AField: string; const AKey: ISigningKey);
    procedure CheckImportsLikeInner(const AField: string; const APassword: ISecretBuffer);
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestPlainPkcs8PemReachesHookOnce;
    procedure TestPlainPkcs8PemHookGetsDecodedBlock;
    procedure TestPlainPkcs8PemHookGetsNoPassword;
    procedure TestRsaPkcs1PemHookGetsDecodedBlock;
    procedure TestEcSec1PemHookGetsDecodedBlock;
    procedure TestHookKeyIsReturnedForPem;
    procedure TestEncryptedPemHookGetsDecodedBlock;
    procedure TestEncryptedPemHookGetsCallerPassword;
    procedure TestDeclinedEncryptedPemImportsViaInner;
    procedure TestMislabelledEncryptedPemSkipsHook;
    procedure TestMislabelledEncryptedPemFailsLikeInner;
    procedure TestMidLineBoundarySkipsHook;
    procedure TestMidLineBoundaryImportsLikeInner;
    procedure TestOnlyTheFirstPemBlockIsOffered;
    procedure TestFirstPemBlockIsTheOneOffered;
    procedure TestDeclinedFirstPemBlockImportsItViaInner;
    procedure TestUnterminatedPemSkipsHook;
    procedure TestUnterminatedPemFailsLikeInner;
    procedure TestDecodedPemBlockIsWipedAfterHook;
    procedure TestDerReachesHookOnce;
    procedure TestDerHookGetsCallersArray;
    procedure TestDerHookGetsCallersPassword;
    procedure TestDerHookKeyIsReturned;
    procedure TestDerDeclinedImportsViaInner;
    procedure TestDerCallerBytesStayIntact;
    procedure TestBareForwarderImportsDerLikeInner;
    procedure TestBareForwarderImportsPemLikeInner;
    procedure TestBareForwarderPassesPasswordForEncryptedDer;
    procedure TestBareForwarderPassesPasswordForEncryptedPem;
    procedure TestBareForwarderSignatureVerifies;
    procedure TestBareForwarderVerifierRejectsTamperedMessage;
    procedure TestBareForwarderImportsPkcs12LikeInner;
    procedure TestForwardingRefusesNilInner;
  end;

  /// <summary>The NIST private-scalar range and group orders, against SEC 2 text and an
  /// independent variable-time reference.</summary>
  TTestEcPrivateScalar = class(TSystemCryptoHelperTestCase)
  strict private
    function Order(ACurve: Int32): TBytes;
    // a ACurve-wide scalar holding only ALow in its last byte
    function SmallScalar(ACurve: Int32; ALow: Byte): TBytes;
    // the group order plus ADelta (|ADelta| < 256), carry and borrow propagated
    function OrderPlus(ACurve: Int32; ADelta: Int32): TBytes;
    // 2^ABit at the curve's field width
    function PowerOfTwo(ACurve: Int32; ABit: Int32): TBytes;
    function Reference(const AScalar: TBytes; ACurve: Int32): Boolean;
    procedure CheckMatchesReference(const AName: string; ACurve: Int32;
      const AScalar: TBytes);
    procedure CheckGroupOrder(ACurve: Int32);
  published
    procedure TestGroupOrderP256IsSec2;
    procedure TestGroupOrderP384IsSec2;
    procedure TestGroupOrderP521IsSec2;
    procedure TestGroupOrderRefusesX25519;
    procedure TestZeroIsRejected;
    procedure TestOneIsAccepted;
    procedure TestOrderMinusTwoIsAccepted;
    procedure TestOrderMinusOneIsAccepted;
    procedure TestOrderIsRejected;
    procedure TestOrderPlusOneIsRejected;
    procedure TestAllOnesIsRejected;
    procedure TestPowersOfTwoBelowTheOrderBitLengthAreAccepted;
    procedure TestScalarsAboveTheOrderAreRejected;
    procedure TestShorterWidthIsRejected;
    procedure TestLongerWidthIsRejected;
    procedure TestNilScalarIsRejected;
    procedure TestRandomScalarsMatchReference;
    procedure TestScalarsSharingAPrefixWithTheOrderMatchReference;
    procedure TestScalarsNearTheOrderMatchReference;
    procedure TestScalarsWithOneOrderBitFlippedMatchReference;
    procedure TestScalarsWithOneNonZeroByteMatchReference;
  end;

  /// <summary>The platform-neutral backend-report base, over fakes that stand in for a
  /// platform.</summary>
  TTestSystemBackendReport = class(TTlsLibTestCase)
  strict private
    procedure CheckNotNative(const AName: string; const AEntry: TCryptoBackendEntry);
    procedure CheckComposed(const AName: string; const AEntry: TCryptoBackendEntry);
    // the signing answer of a platform whose module decision is these three facts
    function ModuleFacet(ASchemeServed, AModulePresent,
      AFacetNative: Boolean): TCryptoBackendEntry;
  published
    procedure TestRandomDefaultsToNotNative;
    procedure TestHashDefaultsToNotNative;
    procedure TestHmacDefaultsToNotNative;
    procedure TestAeadDefaultsToNotNative;
    procedure TestKeyAgreementDefaultsToNotNative;
    procedure TestKemDefaultsToNotNative;
    procedure TestSigningDefaultsToNotNative;
    procedure TestVerificationDefaultsToNotNative;
    procedure TestHkdfIsNotNativeWhenHmacDefaults;
    procedure TestTls12PrfIsNotNativeWhenHmacDefaults;
    procedure TestHkdfIsComposedExactlyWhereHmacIsSystem;
    procedure TestTls12PrfIsComposedExactlyWhereHmacIsSystem;
    procedure TestHpkeFacetIsComposedWhenFlagged;
    procedure TestHpkeFacetIsNotNativeWhenNotFlagged;
    procedure TestPrimitivesAndSigningFacetsAreNeverWhole;
    procedure TestSigningKeyIsNotNativeEvenWhenMarked;
    procedure TestSigningKeyIsNotNativeWhenUnmarked;
    procedure TestVerifierIsNotNativeEvenWhenMarked;
    procedure TestVerifierIsNotNativeWhenUnmarked;
    // the per-scheme decision of a facet served by a separate OS module, one case each
    procedure TestModuleFacetSchemeNotServedIsNotNative;
    procedure TestModuleFacetAbsentModuleIsNoModule;
    procedure TestModuleFacetNativeIsSystem;
    procedure TestModuleFacetNotNativeIsPortable;
    // a scheme the module does not serve is NotNative before the module is judged absent
    procedure TestModuleFacetSchemeNotServedAndModuleAbsentIsNotNative;
  end;

  /// <summary>The strict-registry derivation over backend reports whose signing and
  /// verification coverage differ.</summary>
  TTestSystemCryptoStrictness = class(TSystemCryptoHelperTestCase)
  strict private
    // the signature schemes left and the names dropped for a report with this coverage
    function Remaining(const AReport: ICryptoBackendReport;
      out ADropped: TArray<string>): ISignatureSchemeRegistry;
  published
    procedure TestSigningWithoutVerificationDropsEveryScheme;
    procedure TestVerificationWithoutSigningDropsEveryScheme;
    procedure TestFullCoverageKeepsEveryScheme;
    procedure TestMixedCoverageKeepsOnlyTheSchemesServedInBothRoles;
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
  Password = 'tlslib';
  // the field widths of P-256, P-384 and P-521
  FieldSizes: array[0..2] of Int32 = (32, 48, 66);
  // the bit lengths of the P-256, P-384 and P-521 group orders
  OrderBitLengths: array[0..2] of Int32 = (256, 384, 521);
  Curves: array[0..2] of TKeyAgreementAlgorithm = (TKeyAgreementAlgorithm.SECP256R1,
    TKeyAgreementAlgorithm.SECP384R1, TKeyAgreementAlgorithm.SECP521R1);
  // SEC 2 n of secp256r1 (2.4.2), secp384r1 (2.5.1), secp521r1 (2.6.1), apart from production
  Sec2GroupOrders: array[0..2] of string = (
    'FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551',
    'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF' +
      'C7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973',
    '01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF' +
      'FA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409');
  // RFC 6979 A.2.5, NIST P-256, message "sample": the r and s of SHA-1, SHA-224 and SHA-256
  Sha1R = '61340C88C3AAEBEB4F6D667F672CA9759A6CCAA9FA8811313039EE4A35471D32';
  Sha1S = '6D7F147DAC089441BB2E2FE8F7A3FA264B9C475098FDCF6E00D7C996E1B8B7EB';
  Sha224R = '53B2FFF5D1752B2C689DF257C04C40A587FABABB3F6FC2702F1343AF7CA9AA3F';
  Sha224S = 'B9AFB64FDC03DC1A131C7D2386D11E349F070AA432A4ACC918BEA988BF75C74C';
  Sha256R = 'EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716';
  Sha256S = 'F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8';
  // RFC 8017 9.2 Note 1: the DigestInfo up to the digest, for SHA-256, SHA-384 and SHA-512
  Sha256DigestInfoPrefix = '3031300d060960864801650304020105000420';
  Sha384DigestInfoPrefix = '3041300d060960864801650304020205000430';
  Sha512DigestInfoPrefix = '3051300d060960864801650304020305000440';
  // the smallest valid Ecdsa-Sig-Value, r = s = 1
  MinimalSignature = '3006020101020101';

const
  // RFC 5869 Appendix A, test cases 1-3 (SHA-256)
  Ikm22 = '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b';
  Salt13 = '000102030405060708090a0b0c';
  Info10 = 'f0f1f2f3f4f5f6f7f8f9';
  Prk1 = '077709362c2e32df0ddc3f0dc47bba63' + '90b6c73bb50f9c3122ec844ad7c2b3e5';
  Okm1 = '3cb25f25faacd57a90434f64d0362f2a' + '2d2d0a90cf1a5a4c5db02d56ecc4c5bf' +
    '34007208d5b887185865';
  Ikm80 = '000102030405060708090a0b0c0d0e0f' + '101112131415161718191a1b1c1d1e1f' +
    '202122232425262728292a2b2c2d2e2f' + '303132333435363738393a3b3c3d3e3f' +
    '404142434445464748494a4b4c4d4e4f';
  Salt80 = '606162636465666768696a6b6c6d6e6f' + '707172737475767778797a7b7c7d7e7f' +
    '808182838485868788898a8b8c8d8e8f' + '909192939495969798999a9b9c9d9e9f' +
    'a0a1a2a3a4a5a6a7a8a9aaabacadaeaf';
  Info80 = 'b0b1b2b3b4b5b6b7b8b9babbbcbdbebf' + 'c0c1c2c3c4c5c6c7c8c9cacbcccdcecf' +
    'd0d1d2d3d4d5d6d7d8d9dadbdcdddedf' + 'e0e1e2e3e4e5e6e7e8e9eaebecedeeef' +
    'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff';
  Prk2 = '06a6b88c5853361a06104c9ceb35b45c' + 'ef760014904671014a193f40c15fc244';
  Okm2 = 'b11e398dc80327a1c8e7f78c596a4934' + '4f012eda2d4efad8a050cc4c19afa97c' +
    '59045a99cac7827271cb41c65e590e09' + 'da3275600c2f09b8367793a9aca3db71' +
    'cc30c58179ec3e87c14c01d5c1f3434f' + '1d87';
  Prk3 = '19ef24a32c717b167f33a91d6f648bdf' + '96596776afdb6377ac434c1c293ccb04';
  Okm3 = '8da4e775a563c18f715f802a063c5a31' + 'b8a11f5c5ee1879ec3454e5f3c738d2d' +
    '9d201395faa4b61a96c8';

type
  // a platform whose OS HMAC serves only some hashes
  TPartialHmacReport = class(TBareBackendReport)
  public
    function HmacBackend(AAlgorithm: THashAlgorithm): TCryptoBackendEntry; override;
  end;

  // a platform whose OS module serves signing and verification independently
  TSplitBackendReport = class(TBareBackendReport)
  strict private
  var
    FSigningNative: Boolean;
    FVerifyNative: Boolean;
  public
    constructor Create(ASigningNative, AVerifyNative: Boolean); reintroduce;
    function SigningBackend(AScheme: TSignatureScheme): TCryptoBackendEntry; override;
    function VerificationBackend(AScheme: TSignatureScheme): TCryptoBackendEntry; override;
  end;

  // a platform whose signing is served by a separate OS module, as the base helper decides it
  TModuleFacetReport = class(TBareBackendReport)
  strict private
  var
    FSchemeServed: Boolean;
    FModulePresent: Boolean;
    FFacetNative: Boolean;
  public
    constructor Create(ASchemeServed, AModulePresent, AFacetNative: Boolean); reintroduce;
    function SigningBackend(AScheme: TSignatureScheme): TCryptoBackendEntry; override;
  end;

  // a platform that signs every scheme natively but verifies only ECDSA natively
  TEcdsaVerifyOnlyReport = class(TBareBackendReport)
  public
    constructor Create; reintroduce;
    function SigningBackend(AScheme: TSignatureScheme): TCryptoBackendEntry; override;
    function VerificationBackend(AScheme: TSignatureScheme): TCryptoBackendEntry; override;
  end;

const
  // the hashes the fake OS HMAC serves
  HmacSystemHashes = [THashAlgorithm.SHA_256, THashAlgorithm.SHA_512];
  EcdsaSchemes = [TSignatureScheme.ECDSA_SECP256R1_SHA256, TSignatureScheme.ECDSA_SECP384R1_SHA384,
    TSignatureScheme.ECDSA_SECP521R1_SHA512];

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

{ TSystemCryptoHelperTestCase }

procedure TSystemCryptoHelperTestCase.SetUp;
begin
  inherited SetUp;
  FKeys := Own<TStringList>(LoadVectorFields('Certs/ImportKeys.txt'));
  FPfx := Own<TStringList>(LoadVectorFields('Certs/Pkcs12.txt'));
end;

function TSystemCryptoHelperTestCase.CreateCrypto: ICryptoProvider;
begin
  Result := TTlsLibTestProviders.Crypto(TCryptoProviderChoice.Portable);
end;

{ TTestSystemCryptoHelpers }

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
  Result := Reference(AAlgorithm).Extract(TSecretBuffer.From(DecodeHex(Salt13)),
    TSecretBuffer.From(DecodeHex(Ikm22)));
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
  LInfo := DecodeHex(Info10);
  LPrk := ReferencePrk(AAlgorithm);
  for LI := Low(LLengths) to High(LLengths) do
    CheckEqualBytes(Format('HKDF-Expand L=%d', [LLengths[LI]]),
      Reference(AAlgorithm).Expand(LPrk, LInfo, LLengths[LI]).ToBytes,
      Composition(AAlgorithm).Expand(LPrk, LInfo, LLengths[LI]).ToBytes);
  CheckEqualBytes('HKDF-Extract PRK',
    LPrk.ToBytes, Composition(AAlgorithm).Extract(TSecretBuffer.From(DecodeHex(Salt13)),
      TSecretBuffer.From(DecodeHex(Ikm22))).ToBytes);
end;

procedure TTestSystemCryptoHelpers.CheckExtractMatchesZeroSalt(const ASalt: ISecretBuffer);
const
  HashLen = 32;
var
  LIkm: ISecretBuffer;
  LExpected: TBytes;
begin
  LIkm := TSecretBuffer.From(DecodeHex(Ikm22));
  LExpected := Reference(THashAlgorithm.SHA_256).Extract(
    TSecretBuffer.Allocate(HashLen), LIkm).ToBytes;
  CheckEquals(HashLen, Length(LExpected), 'reference PRK length');
  CheckEqualBytes('HKDF-Extract PRK', LExpected,
    Composition(THashAlgorithm.SHA_256).Extract(ASalt, LIkm).ToBytes);
end;

function TTestSystemCryptoHelpers.ExpandFailure(AAlgorithm: THashAlgorithm;
  ALength: Int32): string;
begin
  Result := '';
  try
    Composition(AAlgorithm).Expand(ReferencePrk(AAlgorithm), DecodeHex(Info10), ALength);
  except
    on E: Exception do
      Result := E.ClassName + ': ' + E.Message;
  end;
end;

function TTestSystemCryptoHelpers.TooLongFailure(ALength, ACap: Int32): string;
begin
  Result := EArgumentTlsLibException.ClassName + ': ' +
    Format(SHkdfExpandTooLong, [ALength, ACap]);
end;

procedure TTestSystemCryptoHelpers.TestHkdfRfc5869Case1;
begin
  CheckVector(Salt13, Ikm22, Info10, Prk1, Okm1, 42);
end;

procedure TTestSystemCryptoHelpers.TestHkdfRfc5869Case2;
begin
  CheckVector(Salt80, Ikm80, Info80, Prk2, Okm2, 82);
end;

procedure TTestSystemCryptoHelpers.TestHkdfRfc5869Case3;
begin
  CheckVector('', Ikm22, '', Prk3, Okm3, 42);
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
  CheckEquals(EArgumentTlsLibException.ClassName + ': ' + SHkdfExpandNegative,
    ExpandFailure(THashAlgorithm.SHA_256, -1), 'a negative length is refused');
end;

procedure TTestSystemCryptoHelpers.TestHkdfExpandRejectsLengthOverCap;
begin
  CheckEquals(TooLongFailure(255 * 32 + 1, 255 * 32),
    ExpandFailure(THashAlgorithm.SHA_256, 255 * 32 + 1),
    'a length beyond 255 * HashLen is refused');
end;

procedure TTestSystemCryptoHelpers.TestHkdfExpandAcceptsExactCap;
var
  LOkm: ISecretBuffer;
begin
  LOkm := Composition(THashAlgorithm.SHA_256).Expand(ReferencePrk(THashAlgorithm.SHA_256),
    DecodeHex(Info10), 255 * 32);
  CheckEquals(255 * 32, LOkm.Len, 'Expand at the exact cap succeeds');
end;

procedure TTestSystemCryptoHelpers.TestHkdfExpandCapFollowsHashLength;
var
  LOkm: ISecretBuffer;
begin
  CheckEquals(TooLongFailure(255 * 48 + 1, 255 * 48),
    ExpandFailure(THashAlgorithm.SHA_384, 255 * 48 + 1),
    'one past the SHA-384 cap is refused');
  LOkm := Composition(THashAlgorithm.SHA_384).Expand(ReferencePrk(THashAlgorithm.SHA_384),
    DecodeHex(Info10), 255 * 48);
  CheckEquals(255 * 48, LOkm.Len, 'Expand at the exact SHA-384 cap succeeds');
end;

procedure TTestSystemCryptoHelpers.TestHkdfExpandZeroLengthIsEmpty;
var
  LOkm: ISecretBuffer;
begin
  LOkm := Composition(THashAlgorithm.SHA_256).Expand(ReferencePrk(THashAlgorithm.SHA_256),
    DecodeHex(Info10), 0);
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
    LHkdf.Expand(ReferencePrk(THashAlgorithm.SHA_256), DecodeHex(Info10), -1);
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
  LHkdf.Expand(ReferencePrk(THashAlgorithm.SHA_256), DecodeHex(Info10), 0);
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
    LHkdf.Expand(ReferencePrk(THashAlgorithm.SHA_256), DecodeHex(Info10), 255 * 32 + 1);
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
  LHkdf.Expand(ReferencePrk(THashAlgorithm.SHA_256), DecodeHex(Info10), 42);
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
    LHkdf.Expand(ReferencePrk(THashAlgorithm.SHA_256), DecodeHex(Info10), 42).ToBytes);
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
    Reference(THashAlgorithm.SHA_256).Expand(LPrk, DecodeHex(Info10), 42).ToBytes,
    LHkdf.Expand(LPrk, DecodeHex(Info10), 42).ToBytes);
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

{ TRecordingSigning }

function TRecordingSigning.TryImportNative(const ADer: TBytes;
  const APassword: ISecretBuffer; out AKey: ISigningKey): Boolean;
begin
  Inc(Calls);
  SeenRef := ADer;
  SeenCopy := System.Copy(ADer);
  SeenPassword := APassword;
  AKey := Served;
  Result := Served <> nil;
end;

{ TTestEcdsaSignatureEncoding }

function TTestEcdsaSignatureEncoding.RepeatHex(const AUnit: string; ACount: Int32): string;
var
  LI: Int32;
begin
  Result := '';
  for LI := 1 to ACount do
    Result := Result + AUnit;
end;

function TTestEcdsaSignatureEncoding.PaddedHex(const AHex: string; AFieldSize: Int32): string;
begin
  Result := StringOfChar('0', 2 * AFieldSize - Length(AHex)) + AHex;
end;

function TTestEcdsaSignatureEncoding.Decodes(const AHex: string; AFieldSize: Int32;
  out ARaw: TBytes): Boolean;
begin
  Result := TSignatureEncoding.TryDerDecodeEcdsa(DecodeHex(AHex), AFieldSize, ARaw);
end;

procedure TTestEcdsaSignatureEncoding.CheckRejects(const AName, AHex: string;
  AFieldSize: Int32);
var
  LRaw: TBytes;
begin
  CheckFalse(Decodes(AHex, AFieldSize, LRaw), AName + ' is rejected');
end;

procedure TTestEcdsaSignatureEncoding.CheckDecodesTo(const AName, ADerHex, ARHex,
  ASHex: string; AFieldSize: Int32);
var
  LRaw: TBytes;
begin
  CheckTrue(Decodes(ADerHex, AFieldSize, LRaw), AName + ' decodes');
  CheckEqualBytes(AName + ' r||s',
    DecodeHex(PaddedHex(ARHex, AFieldSize) + PaddedHex(ASHex, AFieldSize)), LRaw);
end;

procedure TTestEcdsaSignatureEncoding.CheckEncodes(const AName, ARawHex, ADerHex: string);
begin
  CheckEqualBytes(AName, DecodeHex(ADerHex),
    TSignatureEncoding.DerEncodeEcdsa(DecodeHex(ARawHex)));
end;

procedure TTestEcdsaSignatureEncoding.CheckRoundTrip(const AName: string;
  const ARaw: TBytes);
var
  LBack: TBytes;
begin
  CheckTrue(TSignatureEncoding.TryDerDecodeEcdsa(TSignatureEncoding.DerEncodeEcdsa(ARaw),
    Length(ARaw) div 2, LBack), AName + ' decodes after encoding');
  CheckEqualBytes(AName + ' round trip', ARaw, LBack);
end;

procedure TTestEcdsaSignatureEncoding.CheckRandomRoundTrips(AFieldSize: Int32);
var
  LI: Int32;
  LRaw: TBytes;
begin
  for LI := 1 to 32 do
  begin
    LRaw := Crypto.Primitives.GetRandom.GenerateBytes(2 * AFieldSize);
    // r and s must be non-zero
    LRaw[AFieldSize - 1] := LRaw[AFieldSize - 1] or 1;
    LRaw[2 * AFieldSize - 1] := LRaw[2 * AFieldSize - 1] or 1;
    CheckRoundTrip(Format('field %d, sample %d', [AFieldSize, LI]), LRaw);
  end;
end;

procedure TTestEcdsaSignatureEncoding.CheckPortableSignatures(const AKeyField: string;
  AScheme: TSignatureScheme; AFieldSize: Int32);
var
  LKey: ISigningKey;
  LSigner: ISignatureSigner;
  LMessage, LSignature, LRaw: TBytes;
  LI: Int32;
begin
  LKey := Crypto.Signing.ImportSigningKey(DecodeHex(FKeys.Values[AKeyField]), nil);
  for LI := 0 to 63 do
  begin
    LMessage := TBytes.Create(Byte(LI), 1, 2, 3);
    LSigner := Crypto.Signing.CreateSignatureSigner(AScheme, LKey);
    LSigner.Update(LMessage, 0, Length(LMessage));
    LSignature := LSigner.Sign;
    CheckTrue(TSignatureEncoding.TryDerDecodeEcdsa(LSignature, AFieldSize, LRaw),
      Format('%s signature %d decodes', [AKeyField, LI]));
    // the backend's own encoder is the independent reference
    CheckEqualBytes(Format('%s signature %d re-encodes', [AKeyField, LI]), LSignature,
      TSignatureEncoding.DerEncodeEcdsa(LRaw));
  end;
end;

procedure TTestEcdsaSignatureEncoding.TestEncodeRfc6979Sha256Sample;
begin
  CheckEncodes('SHA-256 sample', Sha256R + Sha256S,
    '3046' + '022100' + Sha256R + '022100' + Sha256S);
end;

procedure TTestEcdsaSignatureEncoding.TestEncodeRfc6979Sha224Sample;
begin
  CheckEncodes('SHA-224 sample', Sha224R + Sha224S,
    '3045' + '0220' + Sha224R + '022100' + Sha224S);
end;

procedure TTestEcdsaSignatureEncoding.TestEncodeRfc6979Sha1Sample;
begin
  CheckEncodes('SHA-1 sample', Sha1R + Sha1S,
    '3044' + '0220' + Sha1R + '0220' + Sha1S);
end;

procedure TTestEcdsaSignatureEncoding.TestDecodeRfc6979Sha256Sample;
begin
  CheckDecodesTo('SHA-256 sample', '3046' + '022100' + Sha256R + '022100' + Sha256S,
    Sha256R, Sha256S, 32);
end;

procedure TTestEcdsaSignatureEncoding.TestDecodeRfc6979Sha224Sample;
begin
  CheckDecodesTo('SHA-224 sample', '3045' + '0220' + Sha224R + '022100' + Sha224S,
    Sha224R, Sha224S, 32);
end;

procedure TTestEcdsaSignatureEncoding.TestDecodeRfc6979Sha1Sample;
begin
  CheckDecodesTo('SHA-1 sample', '3044' + '0220' + Sha1R + '0220' + Sha1S,
    Sha1R, Sha1S, 32);
end;

procedure TTestEcdsaSignatureEncoding.TestEncodeDropsLeadingZeroBytes;
begin
  // r loses two zero bytes; s loses one and regains one to clear its sign bit
  CheckEncodes('leading zeros', '0000' + RepeatHex('11', 30) + '0080' + RepeatHex('22', 30),
    '3042' + '021e' + RepeatHex('11', 30) + '0220' + '0080' + RepeatHex('22', 30));
end;

procedure TTestEcdsaSignatureEncoding.TestEncodeP521UsesSingleByteLongFormLength;
begin
  CheckEncodes('P-521 content of 0x88 bytes',
    '01' + RepeatHex('22', 65) + '01' + RepeatHex('33', 65),
    '308188' + '0242' + '01' + RepeatHex('22', 65) + '0242' + '01' + RepeatHex('33', 65));
end;

procedure TTestEcdsaSignatureEncoding.TestRoundTripRandomP256;
begin
  CheckRandomRoundTrips(32);
end;

procedure TTestEcdsaSignatureEncoding.TestRoundTripRandomP384;
begin
  CheckRandomRoundTrips(48);
end;

procedure TTestEcdsaSignatureEncoding.TestRoundTripRandomP521;
begin
  CheckRandomRoundTrips(66);
end;

procedure TTestEcdsaSignatureEncoding.TestRoundTripTopByteZero;
var
  LI: Int32;
  LRaw: TBytes;
begin
  for LI := Low(FieldSizes) to High(FieldSizes) do
  begin
    LRaw := DecodeHex(RepeatHex('5a', 2 * FieldSizes[LI]));
    LRaw[0] := 0;
    LRaw[FieldSizes[LI]] := 0;
    CheckRoundTrip(Format('field %d', [FieldSizes[LI]]), LRaw);
  end;
end;

procedure TTestEcdsaSignatureEncoding.TestRoundTripTopBitSet;
var
  LI: Int32;
begin
  for LI := Low(FieldSizes) to High(FieldSizes) do
    CheckRoundTrip(Format('field %d', [FieldSizes[LI]]),
      DecodeHex(RepeatHex('ff', 2 * FieldSizes[LI])));
end;

procedure TTestEcdsaSignatureEncoding.TestRoundTripSingleLowByte;
var
  LI: Int32;
  LRaw: TBytes;
begin
  for LI := Low(FieldSizes) to High(FieldSizes) do
  begin
    LRaw := DecodeHex(RepeatHex('00', 2 * FieldSizes[LI]));
    LRaw[FieldSizes[LI] - 1] := 1;
    LRaw[2 * FieldSizes[LI] - 1] := 1;
    CheckRoundTrip(Format('field %d', [FieldSizes[LI]]), LRaw);
  end;
end;

procedure TTestEcdsaSignatureEncoding.TestDecodeAcceptsPortableP256Signatures;
begin
  CheckPortableSignatures('ec256_pkcs8_der', TSignatureScheme.ECDSA_SECP256R1_SHA256, 32);
end;

procedure TTestEcdsaSignatureEncoding.TestDecodeAcceptsPortableP384Signatures;
begin
  CheckPortableSignatures('ec384_pkcs8_der', TSignatureScheme.ECDSA_SECP384R1_SHA384, 48);
end;

procedure TTestEcdsaSignatureEncoding.TestDecodeAcceptsPortableP521Signatures;
begin
  CheckPortableSignatures('ec521_pkcs8_der', TSignatureScheme.ECDSA_SECP521R1_SHA512, 66);
end;

procedure TTestEcdsaSignatureEncoding.TestDecodeAcceptsMinimalOnes;
begin
  CheckDecodesTo('r = s = 1', MinimalSignature, '01', '01', 32);
end;

procedure TTestEcdsaSignatureEncoding.TestDecodeAcceptsSignPaddedHighBit;
begin
  CheckDecodesTo('r = 0x80, s = 0xFF', '3008' + '02020080' + '020200ff', '80', 'ff', 32);
end;

procedure TTestEcdsaSignatureEncoding.TestDecodeAcceptsFullWidthSignPaddedValue;
begin
  CheckDecodesTo('33-byte r with a sign byte at field 32',
    '3026' + '0221' + '0080' + RepeatHex('11', 31) + '020101', '80' + RepeatHex('11', 31),
    '01', 32);
end;

procedure TTestEcdsaSignatureEncoding.TestDecodeAcceptsWideValueAtLargerField;
begin
  // the same 33-byte r that field 32 refuses
  CheckDecodesTo('33-byte r at field 48', '3026' + '0221' + '01' + RepeatHex('11', 32) +
    '020101', '01' + RepeatHex('11', 32), '01', 48);
end;

procedure TTestEcdsaSignatureEncoding.TestDecodeRejectsEmpty;
begin
  CheckRejects('empty input', '', 32);
end;

procedure TTestEcdsaSignatureEncoding.TestDecodeRejectsSingleByte;
begin
  CheckRejects('a single byte', '30', 32);
end;

procedure TTestEcdsaSignatureEncoding.TestDecodeRejectsEmptySequence;
begin
  CheckRejects('an empty SEQUENCE', '3000', 32);
end;

procedure TTestEcdsaSignatureEncoding.TestDecodeRejectsWrongOuterTag;
begin
  CheckRejects('a SET outer tag', '3106020101020101', 32);
end;

procedure TTestEcdsaSignatureEncoding.TestDecodeRejectsTrailingByte;
begin
  CheckRejects('a byte after the SEQUENCE', MinimalSignature + '00', 32);
end;

procedure TTestEcdsaSignatureEncoding.TestDecodeRejectsSequenceLengthOneShort;
begin
  CheckRejects('a SEQUENCE length one short', '3005020101020101', 32);
end;

procedure TTestEcdsaSignatureEncoding.TestDecodeRejectsSequenceLengthOneLong;
begin
  CheckRejects('a SEQUENCE length one long', '3007020101020101', 32);
end;

procedure TTestEcdsaSignatureEncoding.TestDecodeRejectsNonMinimalLongFormSequenceLength;
begin
  CheckRejects('a long-form length below 0x80', '308106020101020101', 32);
end;

procedure TTestEcdsaSignatureEncoding.TestDecodeRejectsTwoByteLongFormSequenceLength;
begin
  CheckRejects('a two-byte long-form length', '30820006020101020101', 32);
end;

procedure TTestEcdsaSignatureEncoding.TestDecodeRejectsWrongFirstElementTag;
begin
  CheckRejects('a BIT STRING r', '3006030101020101', 32);
end;

procedure TTestEcdsaSignatureEncoding.TestDecodeRejectsWrongSecondElementTag;
begin
  CheckRejects('a BIT STRING s', '3006020101030101', 32);
end;

procedure TTestEcdsaSignatureEncoding.TestDecodeRejectsLongFormIntegerLength;
begin
  CheckRejects('a long-form INTEGER length', '300702810101020101', 32);
end;

procedure TTestEcdsaSignatureEncoding.TestDecodeRejectsEmptyInteger;
begin
  CheckRejects('an empty INTEGER', '30050200020101', 32);
end;

procedure TTestEcdsaSignatureEncoding.TestDecodeRejectsNegativeR;
begin
  CheckRejects('a negative r', '3006020180020101', 32);
end;

procedure TTestEcdsaSignatureEncoding.TestDecodeRejectsNegativeS;
begin
  CheckRejects('a negative s', '3006020101020180', 32);
end;

procedure TTestEcdsaSignatureEncoding.TestDecodeRejectsZeroPaddedR;
begin
  CheckRejects('r = 00 01', '300702020001020101', 32);
end;

procedure TTestEcdsaSignatureEncoding.TestDecodeRejectsZeroPaddedS;
begin
  CheckRejects('s = 00 7F', '30070201010202007f', 32);
end;

procedure TTestEcdsaSignatureEncoding.TestDecodeRejectsZeroR;
begin
  CheckRejects('r = 0', '3006020100020101', 32);
end;

procedure TTestEcdsaSignatureEncoding.TestDecodeRejectsZeroS;
begin
  CheckRejects('s = 0', '3006020101020100', 32);
end;

procedure TTestEcdsaSignatureEncoding.TestDecodeRejectsRWiderThanField;
begin
  CheckRejects('a 33-byte r at field 32',
    '3026' + '0221' + '01' + RepeatHex('11', 32) + '020101', 32);
end;

procedure TTestEcdsaSignatureEncoding.TestDecodeRejectsSWiderThanField;
begin
  CheckRejects('a 33-byte s at field 32',
    '3026' + '020101' + '0221' + '01' + RepeatHex('11', 32), 32);
end;

procedure TTestEcdsaSignatureEncoding.TestDecodeRejectsThirdInteger;
begin
  CheckRejects('a third INTEGER', '3009020101020101020101', 32);
end;

procedure TTestEcdsaSignatureEncoding.TestDecodeRejectsMissingS;
begin
  CheckRejects('a missing s', '3003020101', 32);
end;

procedure TTestEcdsaSignatureEncoding.TestDecodeRejectsIntegerRunningPastEnd;
begin
  CheckRejects('an s that runs past the end', '3006020101020501', 32);
end;

{ TTestPkcs1DigestInfo }

function TTestPkcs1DigestInfo.AscendingDigest(ALength: Int32): TBytes;
var
  LI: Int32;
begin
  Result := nil;
  SetLength(Result, ALength);
  for LI := 0 to ALength - 1 do
    Result[LI] := Byte(LI);
end;

procedure TTestPkcs1DigestInfo.CheckDigestInfo(AScheme: TSignatureScheme;
  AHashLength: Int32; const APrefixHex: string);
var
  LDigest: TBytes;
begin
  LDigest := AscendingDigest(AHashLength);
  CheckEqualBytes('DigestInfo', ConcatBytes(DecodeHex(APrefixHex), LDigest),
    TSignatureEncoding.Pkcs1DigestInfo(AScheme, LDigest));
end;

procedure TTestPkcs1DigestInfo.TestSha256IsNote1Prefixed;
begin
  CheckDigestInfo(TSignatureScheme.RSA_PKCS1_SHA256, 32, Sha256DigestInfoPrefix);
end;

procedure TTestPkcs1DigestInfo.TestSha384IsNote1Prefixed;
begin
  CheckDigestInfo(TSignatureScheme.RSA_PKCS1_SHA384, 48, Sha384DigestInfoPrefix);
end;

procedure TTestPkcs1DigestInfo.TestSha512IsNote1Prefixed;
begin
  CheckDigestInfo(TSignatureScheme.RSA_PKCS1_SHA512, 64, Sha512DigestInfoPrefix);
end;

procedure TTestPkcs1DigestInfo.TestPssSchemeGivesNil;
begin
  CheckTrue(TSignatureEncoding.Pkcs1DigestInfo(TSignatureScheme.RSA_PSS_RSAE_SHA256,
    AscendingDigest(32)) = nil, 'an rsa_pss_rsae scheme has no DigestInfo');
end;

procedure TTestPkcs1DigestInfo.TestEcdsaSchemeGivesNil;
begin
  CheckTrue(TSignatureEncoding.Pkcs1DigestInfo(TSignatureScheme.ECDSA_SECP256R1_SHA256,
    AscendingDigest(32)) = nil, 'an ecdsa scheme has no DigestInfo');
end;

procedure TTestPkcs1DigestInfo.TestEd25519SchemeGivesNil;
begin
  CheckTrue(TSignatureEncoding.Pkcs1DigestInfo(TSignatureScheme.ED25519,
    AscendingDigest(32)) = nil, 'ed25519 has no DigestInfo');
end;

procedure TTestPkcs1DigestInfo.TestDigestOneByteShortGivesNil;
begin
  CheckTrue(TSignatureEncoding.Pkcs1DigestInfo(TSignatureScheme.RSA_PKCS1_SHA256,
    AscendingDigest(31)) = nil, 'a 31-byte SHA-256 digest is refused');
end;

procedure TTestPkcs1DigestInfo.TestDigestOneByteLongGivesNil;
begin
  CheckTrue(TSignatureEncoding.Pkcs1DigestInfo(TSignatureScheme.RSA_PKCS1_SHA256,
    AscendingDigest(33)) = nil, 'a 33-byte SHA-256 digest is refused');
end;

procedure TTestPkcs1DigestInfo.TestEmptyDigestGivesNil;
begin
  CheckTrue(TSignatureEncoding.Pkcs1DigestInfo(TSignatureScheme.RSA_PKCS1_SHA256,
    AscendingDigest(0)) = nil, 'an empty digest is refused');
end;

procedure TTestPkcs1DigestInfo.TestAnotherHashLengthGivesNil;
begin
  CheckTrue(TSignatureEncoding.Pkcs1DigestInfo(TSignatureScheme.RSA_PKCS1_SHA384,
    AscendingDigest(32)) = nil, 'a SHA-256 length digest under SHA-384 is refused');
end;

{ TTestSignatureInputBuffer }

procedure TTestSignatureInputBuffer.SetUp;
begin
  inherited SetUp;
  FBuffer := TExposedSignatureInput.Create;
  FHolder := FBuffer;
end;

procedure TTestSignatureInputBuffer.TearDown;
begin
  FHolder := nil;
  FBuffer := nil;
  inherited TearDown;
end;

function TTestSignatureInputBuffer.UpdateRaises(const AData: TBytes; AOffset,
  ALength: Int32): Boolean;
begin
  Result := False;
  try
    FBuffer.Update(AData, AOffset, ALength);
  except
    on E: EArgumentTlsLibException do
      Result := E.ClassType = EArgumentTlsLibException;
  end;
end;

procedure TTestSignatureInputBuffer.TestNegativeOffsetRaises;
begin
  CheckTrue(UpdateRaises(TBytes.Create(1, 2, 3, 4), -1, 1), 'a negative offset raises');
end;

procedure TTestSignatureInputBuffer.TestNegativeLengthRaises;
begin
  CheckTrue(UpdateRaises(TBytes.Create(1, 2, 3, 4), 0, -1), 'a negative length raises');
end;

procedure TTestSignatureInputBuffer.TestSpanPastTheEndRaises;
begin
  CheckTrue(UpdateRaises(TBytes.Create(1, 2, 3, 4), 2, 3), 'a span past the end raises');
end;

procedure TTestSignatureInputBuffer.TestEmptySpanPastTheEndRaises;
begin
  CheckTrue(UpdateRaises(TBytes.Create(1, 2, 3, 4), 5, 0), 'an offset past the end raises');
end;

procedure TTestSignatureInputBuffer.TestOffsetPlusLengthOverflowRaises;
begin
  CheckTrue(UpdateRaises(TBytes.Create(1, 2, 3, 4), High(Int32), 1),
    'an offset + length beyond Int32 raises');
end;

procedure TTestSignatureInputBuffer.TestEmptySpanAtTheEndIsNoOp;
begin
  CheckFalse(UpdateRaises(TBytes.Create(1, 2, 3, 4), 4, 0), 'an empty span at the end is valid');
  CheckEquals(0, Length(FBuffer.Buffered), 'and adds nothing');
end;

procedure TTestSignatureInputBuffer.TestSpanEndingAtTheEndIsAccepted;
begin
  FBuffer.Update(TBytes.Create(1, 2, 3, 4), 1, 3);
  CheckEqualBytes('the span', TBytes.Create(2, 3, 4), FBuffer.Buffered);
end;

procedure TTestSignatureInputBuffer.TestSpansConcatenateInOrder;
begin
  FBuffer.Update(TBytes.Create(1, 2, 3, 4), 0, 2);
  FBuffer.Update(TBytes.Create(9, 9, 9), 0, 0);
  FBuffer.Update(TBytes.Create(5, 6, 7), 1, 2);
  CheckEqualBytes('the spans', TBytes.Create(1, 2, 6, 7), FBuffer.Buffered);
end;

{ TTestForwardingSigningCrypto }

procedure TTestForwardingSigningCrypto.SetUp;
begin
  inherited SetUp;
  FRecording := TRecordingSigning.Create(Crypto.Signing);
  FSigning := FRecording;
end;

procedure TTestForwardingSigningCrypto.TearDown;
begin
  FSigning := nil;
  FRecording := nil;
  inherited TearDown;
end;

function TTestForwardingSigningCrypto.KeyBytes(const AField: string): TBytes;
begin
  Result := DecodeHex(FKeys.Values[AField]);
end;

function TTestForwardingSigningCrypto.ServedKey: ISigningKey;
begin
  // an Ed25519 key tells the hook's key apart from any key the inner facet would return
  Result := Crypto.Signing.ImportSigningKey(KeyBytes('ed25519_pkcs8_der'), nil);
end;

function TTestForwardingSigningCrypto.ImportFailure(const ASigning: ISigningCrypto;
  const AData: TBytes; const APassword: ISecretBuffer): string;
begin
  Result := '';
  try
    ASigning.ImportSigningKey(AData, APassword);
  except
    on E: Exception do
      Result := E.ClassName + ': ' + E.Message;
  end;
end;

function TTestForwardingSigningCrypto.SignedAndVerified(const ASigned,
  AVerified: TBytes): Boolean;
var
  LBare: ISigningCrypto;
  LSigner: ISignatureSigner;
  LVerifier: ISignatureVerifier;
  LSignature: TBytes;
begin
  LBare := TForwardingSigningCrypto.Create(Crypto.Signing) as ISigningCrypto;
  LSigner := LBare.CreateSignatureSigner(TSignatureScheme.ECDSA_SECP256R1_SHA256,
    LBare.ImportSigningKey(KeyBytes('ec256_pkcs8_der'), nil));
  LSigner.Update(ASigned, 0, Length(ASigned));
  LSignature := LSigner.Sign;
  LVerifier := LBare.CreateSignatureVerifier(TSignatureScheme.ECDSA_SECP256R1_SHA256,
    KeyBytes('ec256_pub'));
  LVerifier.Update(AVerified, 0, Length(AVerified));
  Result := LVerifier.Verify(LSignature);
end;

procedure TTestForwardingSigningCrypto.CheckSpki(const AName, AField: string;
  const AKey: ISigningKey);
begin
  CheckEqualBytes(AName, KeyBytes(AField), AKey.PublicKeyInfo);
end;

procedure TTestForwardingSigningCrypto.CheckImportsLikeInner(const AField: string;
  const APassword: ISecretBuffer);
var
  LBare: ISigningCrypto;
begin
  LBare := TForwardingSigningCrypto.Create(Crypto.Signing) as ISigningCrypto;
  CheckEqualBytes(AField + ' SPKI',
    Crypto.Signing.ImportSigningKey(KeyBytes(AField), APassword).PublicKeyInfo,
    LBare.ImportSigningKey(KeyBytes(AField), APassword).PublicKeyInfo);
end;

procedure TTestForwardingSigningCrypto.TestPlainPkcs8PemReachesHookOnce;
begin
  FSigning.ImportSigningKey(KeyBytes('ec256_pkcs8_pem'), TSecretBuffer.FromString(Password));
  CheckEquals(1, FRecording.Calls, 'the hook is called once');
end;

procedure TTestForwardingSigningCrypto.TestPlainPkcs8PemHookGetsDecodedBlock;
begin
  FSigning.ImportSigningKey(KeyBytes('ec256_pkcs8_pem'), TSecretBuffer.FromString(Password));
  CheckEqualBytes('the decoded PKCS#8', KeyBytes('ec256_pkcs8_der'), FRecording.SeenCopy);
end;

procedure TTestForwardingSigningCrypto.TestPlainPkcs8PemHookGetsNoPassword;
begin
  FSigning.ImportSigningKey(KeyBytes('ec256_pkcs8_pem'), TSecretBuffer.FromString(Password));
  CheckTrue(FRecording.SeenPassword = nil,
    'a plain block is offered without the caller password');
end;

procedure TTestForwardingSigningCrypto.TestRsaPkcs1PemHookGetsDecodedBlock;
begin
  FSigning.ImportSigningKey(KeyBytes('rsa_pkcs1_pem'), nil);
  CheckEqualBytes('the decoded RSAPrivateKey', KeyBytes('rsa_pkcs1_der'), FRecording.SeenCopy);
end;

procedure TTestForwardingSigningCrypto.TestEcSec1PemHookGetsDecodedBlock;
begin
  FSigning.ImportSigningKey(KeyBytes('ec256_sec1_pem'), nil);
  CheckEqualBytes('the decoded ECPrivateKey', KeyBytes('ec256_sec1_der'), FRecording.SeenCopy);
end;

procedure TTestForwardingSigningCrypto.TestHookKeyIsReturnedForPem;
begin
  FRecording.Served := ServedKey;
  CheckSpki('the key the hook served', 'ed25519_pub',
    FSigning.ImportSigningKey(KeyBytes('ec256_pkcs8_pem'), nil));
end;

procedure TTestForwardingSigningCrypto.TestEncryptedPemHookGetsDecodedBlock;
var
  LBlocks: TArray<TPemBlock>;
begin
  FSigning.ImportSigningKey(KeyBytes('rsa_enc_pem'), TSecretBuffer.FromString(Password));
  LBlocks := TPem.ReadBlocks(KeyBytes('rsa_enc_pem'));
  CheckEqualBytes('the decoded EncryptedPrivateKeyInfo', LBlocks[0].Content,
    FRecording.SeenCopy);
end;

procedure TTestForwardingSigningCrypto.TestEncryptedPemHookGetsCallerPassword;
var
  LPassword: ISecretBuffer;
begin
  LPassword := TSecretBuffer.FromString(Password);
  FSigning.ImportSigningKey(KeyBytes('rsa_enc_pem'), LPassword);
  CheckTrue(FRecording.SeenPassword = LPassword, 'an encrypted block is offered with the password');
end;

procedure TTestForwardingSigningCrypto.TestDeclinedEncryptedPemImportsViaInner;
begin
  CheckSpki('the inner facet decrypts it', 'rsa_pub',
    FSigning.ImportSigningKey(KeyBytes('rsa_enc_pem'), TSecretBuffer.FromString(Password)));
end;

procedure TTestForwardingSigningCrypto.TestMislabelledEncryptedPemSkipsHook;
begin
  ImportFailure(FSigning, KeyBytes('ec256_mislabelled_pem'),
    TSecretBuffer.FromString(Password));
  CheckEquals(0, FRecording.Calls,
    'plaintext PKCS#8 under an ENCRYPTED PRIVATE KEY label is not offered');
end;

procedure TTestForwardingSigningCrypto.TestMislabelledEncryptedPemFailsLikeInner;
var
  LExpected: string;
begin
  LExpected := ImportFailure(Crypto.Signing, KeyBytes('ec256_mislabelled_pem'),
    TSecretBuffer.FromString(Password));
  CheckTrue(LExpected <> '', 'the inner facet refuses the block');
  CheckEquals(LExpected, ImportFailure(FSigning, KeyBytes('ec256_mislabelled_pem'),
    TSecretBuffer.FromString(Password)), 'the same failure');
end;

procedure TTestForwardingSigningCrypto.TestMidLineBoundarySkipsHook;
begin
  FSigning.ImportSigningKey(ConcatBytes(TEncoding.ASCII.GetBytes('note '), ConcatBytes(
    KeyBytes('ed25519_pkcs8_pem'), KeyBytes('rsa_pkcs8_pem'))), nil);
  CheckEquals(0, FRecording.Calls, 'a boundary after text on its line is not offered');
end;

procedure TTestForwardingSigningCrypto.TestMidLineBoundaryImportsLikeInner;
var
  LData: TBytes;
begin
  LData := ConcatBytes(TEncoding.ASCII.GetBytes('note '), ConcatBytes(
    KeyBytes('ed25519_pkcs8_pem'), KeyBytes('rsa_pkcs8_pem')));
  // a hook that would accept the framed block serves a key neither PEM holds
  FRecording.Served := Crypto.Signing.ImportSigningKey(KeyBytes('ec256_pkcs8_der'), nil);
  CheckEqualBytes('the inner facet picks the key',
    Crypto.Signing.ImportSigningKey(LData, nil).PublicKeyInfo,
    FSigning.ImportSigningKey(LData, nil).PublicKeyInfo);
end;

procedure TTestForwardingSigningCrypto.TestOnlyTheFirstPemBlockIsOffered;
begin
  FSigning.ImportSigningKey(ConcatBytes(KeyBytes('ed25519_pkcs8_pem'),
    KeyBytes('rsa_pkcs8_pem')), nil);
  CheckEquals(1, FRecording.Calls, 'a declined first block is not followed by a later one');
end;

procedure TTestForwardingSigningCrypto.TestFirstPemBlockIsTheOneOffered;
begin
  FSigning.ImportSigningKey(ConcatBytes(KeyBytes('ed25519_pkcs8_pem'),
    KeyBytes('rsa_pkcs8_pem')), nil);
  CheckEqualBytes('the first block', KeyBytes('ed25519_pkcs8_der'), FRecording.SeenCopy);
end;

procedure TTestForwardingSigningCrypto.TestDeclinedFirstPemBlockImportsItViaInner;
begin
  CheckSpki('the inner facet takes the first block', 'ed25519_pub',
    FSigning.ImportSigningKey(ConcatBytes(KeyBytes('ed25519_pkcs8_pem'),
    KeyBytes('rsa_pkcs8_pem')), nil));
end;

procedure TTestForwardingSigningCrypto.TestUnterminatedPemSkipsHook;
begin
  ImportFailure(FSigning, TEncoding.ASCII.GetBytes('-----BEGIN PRIVATE KEY-----'#13#10'AAAA'#13#10),
    nil);
  CheckEquals(0, FRecording.Calls, 'a block with no END boundary is not offered');
end;

procedure TTestForwardingSigningCrypto.TestUnterminatedPemFailsLikeInner;
var
  LData: TBytes;
  LExpected: string;
begin
  LData := TEncoding.ASCII.GetBytes('-----BEGIN PRIVATE KEY-----'#13#10'AAAA'#13#10);
  // a hook offered the truncated block would serve a key instead of failing
  FRecording.Served := ServedKey;
  LExpected := ImportFailure(Crypto.Signing, LData, nil);
  CheckTrue(LExpected <> '', 'the inner facet refuses the block');
  CheckEquals(LExpected, ImportFailure(FSigning, LData, nil), 'the same failure');
end;

procedure TTestForwardingSigningCrypto.TestDecodedPemBlockIsWipedAfterHook;
begin
  FSigning.ImportSigningKey(KeyBytes('ec256_pkcs8_pem'), nil);
  CheckTrue(Length(FRecording.SeenRef) > 0, 'the hook saw a block');
  CheckTrue(TArrayUtilities.IsAllZero(FRecording.SeenRef), 'the decoded block is wiped');
end;

procedure TTestForwardingSigningCrypto.TestDerReachesHookOnce;
begin
  FSigning.ImportSigningKey(KeyBytes('ec256_pkcs8_der'), nil);
  CheckEquals(1, FRecording.Calls, 'the hook is called once');
end;

procedure TTestForwardingSigningCrypto.TestDerHookGetsCallersArray;
var
  LData: TBytes;
begin
  LData := KeyBytes('ec256_pkcs8_der');
  FSigning.ImportSigningKey(LData, nil);
  CheckTrue(Pointer(FRecording.SeenRef) = Pointer(LData), 'the hook gets the DER as given');
end;

procedure TTestForwardingSigningCrypto.TestDerHookGetsCallersPassword;
var
  LPassword: ISecretBuffer;
begin
  LPassword := TSecretBuffer.FromString(Password);
  FSigning.ImportSigningKey(KeyBytes('ec256_enc_der'), LPassword);
  CheckTrue(FRecording.SeenPassword = LPassword, 'the hook gets the caller password');
end;

procedure TTestForwardingSigningCrypto.TestDerHookKeyIsReturned;
begin
  FRecording.Served := ServedKey;
  CheckSpki('the key the hook served', 'ed25519_pub',
    FSigning.ImportSigningKey(KeyBytes('ec256_pkcs8_der'), nil));
end;

procedure TTestForwardingSigningCrypto.TestDerDeclinedImportsViaInner;
begin
  CheckSpki('the inner facet imports it', 'ec256_pub',
    FSigning.ImportSigningKey(KeyBytes('ec256_pkcs8_der'), nil));
end;

procedure TTestForwardingSigningCrypto.TestDerCallerBytesStayIntact;
var
  LData: TBytes;
begin
  LData := KeyBytes('ec256_pkcs8_der');
  FRecording.Served := ServedKey;
  FSigning.ImportSigningKey(LData, nil);
  CheckEqualBytes('the caller DER', KeyBytes('ec256_pkcs8_der'), LData);
end;

procedure TTestForwardingSigningCrypto.TestBareForwarderImportsDerLikeInner;
begin
  CheckImportsLikeInner('ec256_pkcs8_der', nil);
end;

procedure TTestForwardingSigningCrypto.TestBareForwarderImportsPemLikeInner;
begin
  CheckImportsLikeInner('ec256_pkcs8_pem', nil);
end;

procedure TTestForwardingSigningCrypto.TestBareForwarderPassesPasswordForEncryptedDer;
begin
  CheckImportsLikeInner('ec256_enc_der', TSecretBuffer.FromString(Password));
end;

procedure TTestForwardingSigningCrypto.TestBareForwarderPassesPasswordForEncryptedPem;
begin
  CheckImportsLikeInner('rsa_enc_pem', TSecretBuffer.FromString(Password));
end;

procedure TTestForwardingSigningCrypto.TestBareForwarderSignatureVerifies;
var
  LMessage: TBytes;
begin
  LMessage := TEncoding.ASCII.GetBytes('The quick brown fox');
  CheckTrue(SignedAndVerified(LMessage, LMessage), 'a signature made through it verifies');
end;

procedure TTestForwardingSigningCrypto.TestBareForwarderVerifierRejectsTamperedMessage;
begin
  CheckFalse(SignedAndVerified(TEncoding.ASCII.GetBytes('The quick brown fox'),
    TEncoding.ASCII.GetBytes('The quick brown fax')), 'a different message does not verify');
end;

procedure TTestForwardingSigningCrypto.TestBareForwarderImportsPkcs12LikeInner;
var
  LBare: ISigningCrypto;
  LExpected, LActual: TImportedCredential;
  LI: Int32;
begin
  LBare := TForwardingSigningCrypto.Create(Crypto.Signing) as ISigningCrypto;
  LExpected := Crypto.Signing.ImportPkcs12(DecodeHex(FPfx.Values['chain_pfx']),
    TSecretBuffer.FromString(Password));
  LActual := LBare.ImportPkcs12(DecodeHex(FPfx.Values['chain_pfx']),
    TSecretBuffer.FromString(Password));
  CheckEquals(Length(LExpected.CertificateChain), Length(LActual.CertificateChain),
    'chain length');
  for LI := 0 to Length(LExpected.CertificateChain) - 1 do
    CheckEqualBytes(Format('certificate %d', [LI]), LExpected.CertificateChain[LI],
      LActual.CertificateChain[LI]);
  CheckEqualBytes('key SPKI', LExpected.PrivateKey.PublicKeyInfo,
    LActual.PrivateKey.PublicKeyInfo);
end;

procedure TTestForwardingSigningCrypto.TestForwardingRefusesNilInner;
var
  LRaised: Boolean;
  LSigning: ISigningCrypto;
begin
  LRaised := False;
  try
    LSigning := TForwardingSigningCrypto.Create(nil) as ISigningCrypto;
  except
    on E: EArgumentTlsLibException do
      LRaised := E.ClassType = EArgumentTlsLibException;
  end;
  CheckTrue(LRaised, 'a nil inner facet raises EArgumentTlsLibException');
end;

{ TTestEcPrivateScalar }

function TTestEcPrivateScalar.Order(ACurve: Int32): TBytes;
begin
  Result := DecodeHex(Sec2GroupOrders[ACurve]);
end;

function TTestEcPrivateScalar.SmallScalar(ACurve: Int32; ALow: Byte): TBytes;
begin
  Result := nil;
  SetLength(Result, FieldSizes[ACurve]);
  Result[High(Result)] := ALow;
end;

function TTestEcPrivateScalar.OrderPlus(ACurve: Int32; ADelta: Int32): TBytes;
var
  LI, LSum, LCarry: Int32;
begin
  Result := Order(ACurve);
  LCarry := ADelta;
  LI := High(Result);
  while (LCarry <> 0) and (LI >= 0) do
  begin
    LSum := Int32(Result[LI]) + LCarry;
    if LSum < 0 then
    begin
      Result[LI] := Byte(LSum + 256);
      LCarry := -1;
    end
    else
    begin
      Result[LI] := Byte(LSum and $FF);
      LCarry := LSum shr 8;
    end;
    Dec(LI);
  end;
end;

function TTestEcPrivateScalar.PowerOfTwo(ACurve: Int32; ABit: Int32): TBytes;
begin
  Result := nil;
  SetLength(Result, FieldSizes[ACurve]);
  Result[High(Result) - ABit div 8] := Byte(1 shl (ABit mod 8));
end;

function TTestEcPrivateScalar.Reference(const AScalar: TBytes; ACurve: Int32): Boolean;
begin
  Result := (not TArrayUtilities.IsAllZero(AScalar)) and
    (TArrayUtilities.CompareLexicographic(AScalar, Order(ACurve)) < 0);
end;

procedure TTestEcPrivateScalar.CheckMatchesReference(const AName: string; ACurve: Int32;
  const AScalar: TBytes);
begin
  CheckTrue(Reference(AScalar, ACurve) = TEcPrivateScalar.IsInRange(AScalar, Order(ACurve)),
    Format('%s (curve %d, scalar %s)', [AName, ACurve, EncodeHex(AScalar)]));
end;

procedure TTestEcPrivateScalar.CheckGroupOrder(ACurve: Int32);
begin
  CheckEqualBytes(Format('group order of curve %d', [ACurve]), Order(ACurve),
    TEcPrivateScalar.GroupOrder(Curves[ACurve]));
end;

procedure TTestEcPrivateScalar.TestGroupOrderP256IsSec2;
begin
  CheckGroupOrder(0);
end;

procedure TTestEcPrivateScalar.TestGroupOrderP384IsSec2;
begin
  CheckGroupOrder(1);
end;

procedure TTestEcPrivateScalar.TestGroupOrderP521IsSec2;
begin
  CheckGroupOrder(2);
end;

procedure TTestEcPrivateScalar.TestGroupOrderRefusesX25519;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    TEcPrivateScalar.GroupOrder(TKeyAgreementAlgorithm.X25519);
  except
    on E: EArgumentTlsLibException do
      LRaised := E.ClassType = EArgumentTlsLibException;
  end;
  CheckTrue(LRaised, 'a non-NIST algorithm raises EArgumentTlsLibException');
end;

procedure TTestEcPrivateScalar.TestZeroIsRejected;
var
  LI: Int32;
begin
  for LI := 0 to 2 do
    CheckFalse(TEcPrivateScalar.IsInRange(SmallScalar(LI, 0), Order(LI)),
      Format('zero (curve %d)', [LI]));
end;

procedure TTestEcPrivateScalar.TestOneIsAccepted;
var
  LI: Int32;
begin
  for LI := 0 to 2 do
    CheckTrue(TEcPrivateScalar.IsInRange(SmallScalar(LI, 1), Order(LI)),
      Format('one (curve %d)', [LI]));
end;

procedure TTestEcPrivateScalar.TestOrderMinusTwoIsAccepted;
var
  LI: Int32;
begin
  for LI := 0 to 2 do
    CheckTrue(TEcPrivateScalar.IsInRange(OrderPlus(LI, -2), Order(LI)),
      Format('n-2 (curve %d)', [LI]));
end;

procedure TTestEcPrivateScalar.TestOrderMinusOneIsAccepted;
var
  LI: Int32;
begin
  for LI := 0 to 2 do
    CheckTrue(TEcPrivateScalar.IsInRange(OrderPlus(LI, -1), Order(LI)),
      Format('n-1 (curve %d)', [LI]));
end;

procedure TTestEcPrivateScalar.TestOrderIsRejected;
var
  LI: Int32;
begin
  for LI := 0 to 2 do
    CheckFalse(TEcPrivateScalar.IsInRange(Order(LI), Order(LI)), Format('n (curve %d)', [LI]));
end;

procedure TTestEcPrivateScalar.TestOrderPlusOneIsRejected;
var
  LI: Int32;
begin
  for LI := 0 to 2 do
    CheckFalse(TEcPrivateScalar.IsInRange(OrderPlus(LI, 1), Order(LI)),
      Format('n+1 (curve %d)', [LI]));
end;

procedure TTestEcPrivateScalar.TestAllOnesIsRejected;
var
  LI, LJ: Int32;
  LScalar: TBytes;
begin
  for LI := 0 to 2 do
  begin
    LScalar := nil;
    SetLength(LScalar, FieldSizes[LI]);
    for LJ := 0 to High(LScalar) do
      LScalar[LJ] := $FF;
    CheckFalse(TEcPrivateScalar.IsInRange(LScalar, Order(LI)),
      Format('all 0xFF (curve %d)', [LI]));
  end;
end;

procedure TTestEcPrivateScalar.TestPowersOfTwoBelowTheOrderBitLengthAreAccepted;
var
  LI, LBit: Int32;
begin
  // n lies strictly between 2^(bits-1) and 2^bits, so 2^k < n exactly when k < bits
  for LI := 0 to 2 do
    for LBit := 0 to OrderBitLengths[LI] - 1 do
      CheckTrue(TEcPrivateScalar.IsInRange(PowerOfTwo(LI, LBit), Order(LI)),
        Format('2^%d (curve %d)', [LBit, LI]));
end;

procedure TTestEcPrivateScalar.TestScalarsAboveTheOrderAreRejected;
var
  LI, LBit, LPos, LChecked: Int32;
  LN, LScalar: TBytes;
begin
  for LI := 0 to 2 do
  begin
    LChecked := 0;
    // the powers of two that fit the width and are not below n (only P-521 has any)
    for LBit := OrderBitLengths[LI] to FieldSizes[LI] * 8 - 1 do
    begin
      CheckFalse(TEcPrivateScalar.IsInRange(PowerOfTwo(LI, LBit), Order(LI)),
        Format('2^%d (curve %d)', [LBit, LI]));
      Inc(LChecked);
    end;
    // n's leading bytes then a larger byte, so each byte position decides a comparison above n
    LN := Order(LI);
    for LPos := 0 to High(LN) do
      if LN[LPos] < $FF then
      begin
        LScalar := Order(LI);
        LScalar[LPos] := Byte(LScalar[LPos] + 1);
        CheckFalse(TEcPrivateScalar.IsInRange(LScalar, Order(LI)),
          Format('n raised at byte %d (curve %d)', [LPos, LI]));
        Inc(LChecked);
      end;
    CheckTrue(LChecked > 0, Format('values above n were checked (curve %d)', [LI]));
  end;
end;

procedure TTestEcPrivateScalar.TestShorterWidthIsRejected;
var
  LI: Int32;
  LScalar: TBytes;
begin
  // a one that would be in range at the right width
  for LI := 0 to 2 do
  begin
    LScalar := System.Copy(SmallScalar(LI, 1), 1, FieldSizes[LI] - 1);
    CheckFalse(TEcPrivateScalar.IsInRange(LScalar, Order(LI)),
      Format('one byte short (curve %d)', [LI]));
  end;
end;

procedure TTestEcPrivateScalar.TestLongerWidthIsRejected;
var
  LI: Int32;
  LScalar: TBytes;
begin
  for LI := 0 to 2 do
  begin
    LScalar := TArrayUtilities.Concat(TBytes.Create(0), SmallScalar(LI, 1));
    CheckFalse(TEcPrivateScalar.IsInRange(LScalar, Order(LI)),
      Format('one byte long (curve %d)', [LI]));
  end;
end;

procedure TTestEcPrivateScalar.TestNilScalarIsRejected;
var
  LI: Int32;
begin
  for LI := 0 to 2 do
    CheckFalse(TEcPrivateScalar.IsInRange(nil, Order(LI)), Format('nil (curve %d)', [LI]));
end;

procedure TTestEcPrivateScalar.TestRandomScalarsMatchReference;
var
  LI, LJ: Int32;
  LScalar: TBytes;
begin
  for LI := 0 to 2 do
    for LJ := 1 to 2000 do
    begin
      LScalar := Crypto.Primitives.GetRandom.GenerateBytes(FieldSizes[LI]);
      // P-521's top byte is 0 or 1 for any in-range value, so keep the draw near that
      if LI = 2 then
        LScalar[0] := LScalar[0] and 1;
      CheckMatchesReference(Format('sample %d', [LJ]), LI, LScalar);
    end;
end;

procedure TTestEcPrivateScalar.TestScalarsSharingAPrefixWithTheOrderMatchReference;
var
  LI, LJ, LShared: Int32;
  LScalar, LN: TBytes;
begin
  for LI := 0 to 2 do
  begin
    LN := Order(LI);
    for LJ := 1 to 2000 do
    begin
      LScalar := Crypto.Primitives.GetRandom.GenerateBytes(FieldSizes[LI]);
      LShared := Crypto.Primitives.GetRandom.GenerateBytes(1)[0] mod (FieldSizes[LI] + 1);
      if LShared > 0 then
        Move(LN[0], LScalar[0], LShared);
      CheckMatchesReference(Format('sample %d, shared %d', [LJ, LShared]), LI, LScalar);
    end;
  end;
end;

procedure TTestEcPrivateScalar.TestScalarsNearTheOrderMatchReference;
var
  LI, LDelta: Int32;
begin
  for LI := 0 to 2 do
    for LDelta := -40 to 40 do
      CheckMatchesReference(Format('n + (%d)', [LDelta]), LI, OrderPlus(LI, LDelta));
end;

procedure TTestEcPrivateScalar.TestScalarsWithOneOrderBitFlippedMatchReference;
var
  LI, LBit: Int32;
  LScalar: TBytes;
begin
  for LI := 0 to 2 do
    for LBit := 0 to FieldSizes[LI] * 8 - 1 do
    begin
      LScalar := Order(LI);
      LScalar[High(LScalar) - LBit div 8] := LScalar[High(LScalar) - LBit div 8] xor
        Byte(1 shl (LBit mod 8));
      CheckMatchesReference(Format('bit %d flipped', [LBit]), LI, LScalar);
    end;
end;

procedure TTestEcPrivateScalar.TestScalarsWithOneNonZeroByteMatchReference;
const
  Values: array [0 .. 2] of Byte = ($01, $80, $FF);
var
  LI, LPos, LV: Int32;
  LScalar: TBytes;
begin
  for LI := 0 to 2 do
    for LPos := 0 to FieldSizes[LI] - 1 do
      for LV := 0 to 2 do
      begin
        LScalar := nil;
        SetLength(LScalar, FieldSizes[LI]);
        LScalar[LPos] := Values[LV];
        CheckMatchesReference(Format('byte %d = %d', [LPos, Values[LV]]), LI, LScalar);
      end;
end;

{ TPartialHmacReport }

function TPartialHmacReport.HmacBackend(AAlgorithm: THashAlgorithm): TCryptoBackendEntry;
begin
  if AAlgorithm in HmacSystemHashes then
    Result := Ent(TCryptoBackend.System, TCryptoBackendReason.NotFallback)
  else
    Result := Ent(TCryptoBackend.Portable, TCryptoBackendReason.NotPresent);
end;

{ TSplitBackendReport }

constructor TSplitBackendReport.Create(ASigningNative, AVerifyNative: Boolean);
begin
  inherited Create(False);
  FSigningNative := ASigningNative;
  FVerifyNative := AVerifyNative;
end;

function TSplitBackendReport.SigningBackend(AScheme: TSignatureScheme): TCryptoBackendEntry;
begin
  if FSigningNative then
    Result := Ent(TCryptoBackend.System, TCryptoBackendReason.NotFallback)
  else
    Result := NotNative;
end;

function TSplitBackendReport.VerificationBackend(
  AScheme: TSignatureScheme): TCryptoBackendEntry;
begin
  if FVerifyNative then
    Result := Ent(TCryptoBackend.System, TCryptoBackendReason.NotFallback)
  else
    Result := NotNative;
end;

{ TModuleFacetReport }

constructor TModuleFacetReport.Create(ASchemeServed, AModulePresent, AFacetNative: Boolean);
begin
  inherited Create(False);
  FSchemeServed := ASchemeServed;
  FModulePresent := AModulePresent;
  FFacetNative := AFacetNative;
end;

function TModuleFacetReport.SigningBackend(AScheme: TSignatureScheme): TCryptoBackendEntry;
begin
  Result := ModuleFacetBackend(FSchemeServed, FModulePresent, FFacetNative);
end;

{ TEcdsaVerifyOnlyReport }

constructor TEcdsaVerifyOnlyReport.Create;
begin
  inherited Create(False);
end;

function TEcdsaVerifyOnlyReport.SigningBackend(AScheme: TSignatureScheme): TCryptoBackendEntry;
begin
  Result := Ent(TCryptoBackend.System, TCryptoBackendReason.NotFallback);
end;

function TEcdsaVerifyOnlyReport.VerificationBackend(
  AScheme: TSignatureScheme): TCryptoBackendEntry;
begin
  if AScheme in EcdsaSchemes then
    Result := Ent(TCryptoBackend.System, TCryptoBackendReason.NotFallback)
  else
    Result := NotNative;
end;

{ TTestSystemBackendReport }

procedure TTestSystemBackendReport.CheckNotNative(const AName: string;
  const AEntry: TCryptoBackendEntry);
begin
  CheckTrue(AEntry.Backend = TCryptoBackend.Portable, AName + ': portable');
  CheckTrue(AEntry.Reason = TCryptoBackendReason.NoNativeImpl, AName + ': no native impl');
end;

procedure TTestSystemBackendReport.CheckComposed(const AName: string;
  const AEntry: TCryptoBackendEntry);
begin
  CheckTrue(AEntry.Backend = TCryptoBackend.Composed, AName + ': composed');
  CheckTrue(AEntry.Reason = TCryptoBackendReason.NotFallback, AName + ': not a fallback');
end;

function TTestSystemBackendReport.ModuleFacet(ASchemeServed, AModulePresent,
  AFacetNative: Boolean): TCryptoBackendEntry;
var
  LReport: ICryptoBackendReport;
begin
  LReport := TModuleFacetReport.Create(ASchemeServed, AModulePresent, AFacetNative)
    as ICryptoBackendReport;
  Result := LReport.SigningBackend(TSignatureScheme.ECDSA_SECP256R1_SHA256);
end;

procedure TTestSystemBackendReport.TestRandomDefaultsToNotNative;
var
  LReport: ICryptoBackendReport;
begin
  LReport := TBareBackendReport.Create(False);
  CheckNotNative('random', LReport.RandomBackend);
end;

procedure TTestSystemBackendReport.TestHashDefaultsToNotNative;
var
  LReport: ICryptoBackendReport;
  LHash: THashAlgorithm;
begin
  LReport := TBareBackendReport.Create(False);
  for LHash := Low(THashAlgorithm) to High(THashAlgorithm) do
    CheckNotNative(Format('hash %d', [Ord(LHash)]), LReport.HashBackend(LHash));
end;

procedure TTestSystemBackendReport.TestHmacDefaultsToNotNative;
var
  LReport: ICryptoBackendReport;
  LHash: THashAlgorithm;
begin
  LReport := TBareBackendReport.Create(False);
  for LHash := Low(THashAlgorithm) to High(THashAlgorithm) do
    CheckNotNative(Format('hmac %d', [Ord(LHash)]), LReport.HmacBackend(LHash));
end;

procedure TTestSystemBackendReport.TestAeadDefaultsToNotNative;
var
  LReport: ICryptoBackendReport;
  LAead: TAeadAlgorithm;
begin
  LReport := TBareBackendReport.Create(False);
  for LAead := Low(TAeadAlgorithm) to High(TAeadAlgorithm) do
    CheckNotNative(Format('aead %d', [Ord(LAead)]), LReport.AeadBackend(LAead));
end;

procedure TTestSystemBackendReport.TestKeyAgreementDefaultsToNotNative;
var
  LReport: ICryptoBackendReport;
  LGroup: TKeyAgreementAlgorithm;
begin
  LReport := TBareBackendReport.Create(False);
  for LGroup := Low(TKeyAgreementAlgorithm) to High(TKeyAgreementAlgorithm) do
    CheckNotNative(Format('key agreement %d', [Ord(LGroup)]),
      LReport.KeyAgreementBackend(LGroup));
end;

procedure TTestSystemBackendReport.TestKemDefaultsToNotNative;
var
  LReport: ICryptoBackendReport;
  LKem: TKemAlgorithm;
begin
  LReport := TBareBackendReport.Create(False);
  for LKem := Low(TKemAlgorithm) to High(TKemAlgorithm) do
    CheckNotNative(Format('kem %d', [Ord(LKem)]), LReport.KemBackend(LKem));
end;

procedure TTestSystemBackendReport.TestSigningDefaultsToNotNative;
var
  LReport: ICryptoBackendReport;
  LScheme: TSignatureScheme;
begin
  LReport := TBareBackendReport.Create(False);
  for LScheme := Low(TSignatureScheme) to High(TSignatureScheme) do
    CheckNotNative(Format('signing %d', [Ord(LScheme)]), LReport.SigningBackend(LScheme));
end;

procedure TTestSystemBackendReport.TestVerificationDefaultsToNotNative;
var
  LReport: ICryptoBackendReport;
  LScheme: TSignatureScheme;
begin
  LReport := TBareBackendReport.Create(False);
  for LScheme := Low(TSignatureScheme) to High(TSignatureScheme) do
    CheckNotNative(Format('verification %d', [Ord(LScheme)]), LReport.VerificationBackend(LScheme));
end;

procedure TTestSystemBackendReport.TestHkdfIsNotNativeWhenHmacDefaults;
var
  LReport: ICryptoBackendReport;
  LHash: THashAlgorithm;
begin
  LReport := TBareBackendReport.Create(True);
  for LHash := Low(THashAlgorithm) to High(THashAlgorithm) do
    CheckNotNative(Format('hkdf %d', [Ord(LHash)]), LReport.HkdfBackend(LHash));
end;

procedure TTestSystemBackendReport.TestTls12PrfIsNotNativeWhenHmacDefaults;
var
  LReport: ICryptoBackendReport;
  LHash: THashAlgorithm;
begin
  LReport := TBareBackendReport.Create(True);
  for LHash := Low(THashAlgorithm) to High(THashAlgorithm) do
    CheckNotNative(Format('prf %d', [Ord(LHash)]), LReport.Tls12PrfBackend(LHash));
end;

procedure TTestSystemBackendReport.TestHkdfIsComposedExactlyWhereHmacIsSystem;
var
  LReport: ICryptoBackendReport;
  LHash: THashAlgorithm;
begin
  LReport := TPartialHmacReport.Create(False);
  for LHash := Low(THashAlgorithm) to High(THashAlgorithm) do
    if LHash in HmacSystemHashes then
      CheckComposed(Format('hkdf %d', [Ord(LHash)]), LReport.HkdfBackend(LHash))
    else
      CheckNotNative(Format('hkdf %d', [Ord(LHash)]), LReport.HkdfBackend(LHash));
end;

procedure TTestSystemBackendReport.TestTls12PrfIsComposedExactlyWhereHmacIsSystem;
var
  LReport: ICryptoBackendReport;
  LHash: THashAlgorithm;
begin
  LReport := TPartialHmacReport.Create(False);
  for LHash := Low(THashAlgorithm) to High(THashAlgorithm) do
    if LHash in HmacSystemHashes then
      CheckComposed(Format('prf %d', [Ord(LHash)]), LReport.Tls12PrfBackend(LHash))
    else
      CheckNotNative(Format('prf %d', [Ord(LHash)]), LReport.Tls12PrfBackend(LHash));
end;

procedure TTestSystemBackendReport.TestHpkeFacetIsComposedWhenFlagged;
var
  LReport: ICryptoBackendReport;
begin
  LReport := TBareBackendReport.Create(True);
  CheckComposed('hpke facet', LReport.FacetBackend(TCryptoFacet.Hpke));
end;

procedure TTestSystemBackendReport.TestHpkeFacetIsNotNativeWhenNotFlagged;
var
  LReport: ICryptoBackendReport;
begin
  LReport := TBareBackendReport.Create(False);
  CheckNotNative('hpke facet', LReport.FacetBackend(TCryptoFacet.Hpke));
end;

procedure TTestSystemBackendReport.TestPrimitivesAndSigningFacetsAreNeverWhole;
var
  LReport: ICryptoBackendReport;
begin
  LReport := TPartialHmacReport.Create(True);
  CheckNotNative('primitives facet', LReport.FacetBackend(TCryptoFacet.Primitives));
  CheckNotNative('signing facet', LReport.FacetBackend(TCryptoFacet.Signing));
end;

procedure TTestSystemBackendReport.TestSigningKeyIsNotNativeEvenWhenMarked;
var
  LReport: ICryptoBackendReport;
  LKey: ISigningKey;
begin
  LReport := TBareBackendReport.Create(False);
  LKey := TFakeSystemSigningKey.Create(nil);
  CheckNotNative('a marker any class can list', LReport.SigningKeyBackend(LKey));
end;

procedure TTestSystemBackendReport.TestSigningKeyIsNotNativeWhenUnmarked;
var
  LReport: ICryptoBackendReport;
  LKey: ISigningKey;
begin
  LReport := TBareBackendReport.Create(False);
  LKey := TMockSigningKey.Create;
  CheckNotNative('an unmarked key', LReport.SigningKeyBackend(LKey));
end;

procedure TTestSystemBackendReport.TestVerifierIsNotNativeEvenWhenMarked;
var
  LReport: ICryptoBackendReport;
  LVerifier: ISignatureVerifier;
begin
  LReport := TBareBackendReport.Create(False);
  LVerifier := TFakeSystemVerifier.Create as ISignatureVerifier;
  CheckNotNative('a marker any class can list', LReport.VerifierBackend(LVerifier));
end;

procedure TTestSystemBackendReport.TestVerifierIsNotNativeWhenUnmarked;
var
  LReport: ICryptoBackendReport;
  LVerifier: ISignatureVerifier;
begin
  LReport := TBareBackendReport.Create(False);
  LVerifier := TRejectingSignatureVerifier.Create as ISignatureVerifier;
  CheckNotNative('an unmarked verifier', LReport.VerifierBackend(LVerifier));
end;

procedure TTestSystemBackendReport.TestModuleFacetSchemeNotServedIsNotNative;
begin
  CheckNotNative('a scheme the module does not serve', ModuleFacet(False, True, True));
end;

procedure TTestSystemBackendReport.TestModuleFacetAbsentModuleIsNoModule;
var
  LEntry: TCryptoBackendEntry;
begin
  LEntry := ModuleFacet(True, False, True);
  CheckTrue(LEntry.Backend = TCryptoBackend.Portable, 'an absent module is portable');
  CheckTrue(LEntry.Reason = TCryptoBackendReason.NoModule, 'and the reason is the module');
end;

procedure TTestSystemBackendReport.TestModuleFacetNativeIsSystem;
var
  LEntry: TCryptoBackendEntry;
begin
  LEntry := ModuleFacet(True, True, True);
  CheckTrue(LEntry.Backend = TCryptoBackend.System, 'a working facet is system-backed');
  CheckTrue(LEntry.Reason = TCryptoBackendReason.NotFallback, 'and is not a fallback');
end;

procedure TTestSystemBackendReport.TestModuleFacetNotNativeIsPortable;
begin
  CheckNotNative('a present module whose facet is not native', ModuleFacet(True, True, False));
end;

procedure TTestSystemBackendReport.TestModuleFacetSchemeNotServedAndModuleAbsentIsNotNative;
begin
  CheckNotNative('an unserved scheme on a host with no module', ModuleFacet(False, False, False));
end;

{ TTestSystemCryptoStrictness }

function TTestSystemCryptoStrictness.Remaining(const AReport: ICryptoBackendReport;
  out ADropped: TArray<string>): ISignatureSchemeRegistry;
var
  LProvider: ICryptoProvider;
begin
  CheckTrue(System.Length(TSignatureSchemeRegistry.CreateDefault.Items) > 0,
    'the default registry offers schemes, so none of the checks below is vacuous');
  LProvider := TOverlayCryptoProvider.Create(Crypto, nil, nil, AReport, nil) as ICryptoProvider;
  Result := TSystemCryptoStrictness.NativeSignatureSchemes(LProvider, ADropped);
end;

procedure TTestSystemCryptoStrictness.TestSigningWithoutVerificationDropsEveryScheme;
var
  LDropped: TArray<string>;
begin
  CheckEquals(0, System.Length(Remaining(TSplitBackendReport.Create(True, False)
    as ICryptoBackendReport, LDropped).Items),
    'a scheme with no native verification is not offered');
  CheckEquals(System.Length(TSignatureSchemeRegistry.CreateDefault.Items),
    System.Length(LDropped), 'each one is reported dropped');
end;

procedure TTestSystemCryptoStrictness.TestVerificationWithoutSigningDropsEveryScheme;
var
  LDropped: TArray<string>;
begin
  CheckEquals(0, System.Length(Remaining(TSplitBackendReport.Create(False, True)
    as ICryptoBackendReport, LDropped).Items),
    'a scheme with no native signing is not offered');
  CheckEquals(System.Length(TSignatureSchemeRegistry.CreateDefault.Items),
    System.Length(LDropped), 'each one is reported dropped');
end;

procedure TTestSystemCryptoStrictness.TestFullCoverageKeepsEveryScheme;
var
  LDropped: TArray<string>;
begin
  CheckEquals(System.Length(TSignatureSchemeRegistry.CreateDefault.Items),
    System.Length(Remaining(TSplitBackendReport.Create(True, True) as ICryptoBackendReport,
    LDropped).Items), 'native in both roles is kept');
  CheckEquals(0, System.Length(LDropped), 'nothing is dropped');
end;

procedure TTestSystemCryptoStrictness.TestMixedCoverageKeepsOnlyTheSchemesServedInBothRoles;
var
  LDropped: TArray<string>;
  LKept: TArray<TSignatureScheme>;
  LI: Int32;
begin
  LKept := Remaining(TEcdsaVerifyOnlyReport.Create as ICryptoBackendReport, LDropped).Items;
  CheckEquals(3, System.Length(LKept), 'the three ECDSA schemes are served in both roles');
  for LI := 0 to System.Length(LKept) - 1 do
    CheckTrue(LKept[LI] in EcdsaSchemes, 'only an ECDSA scheme is kept');
  CheckEquals(System.Length(TSignatureSchemeRegistry.CreateDefault.Items),
    System.Length(LKept) + System.Length(LDropped), 'every other scheme is reported dropped');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestSystemCryptoHelpers);
  RegisterTest(TTestEcdsaSignatureEncoding);
  RegisterTest(TTestPkcs1DigestInfo);
  RegisterTest(TTestSignatureInputBuffer);
  RegisterTest(TTestForwardingSigningCrypto);
  RegisterTest(TTestEcPrivateScalar);
  RegisterTest(TTestSystemBackendReport);
  RegisterTest(TTestSystemCryptoStrictness);
{$ELSE}
  RegisterTest(TTestSystemCryptoHelpers.Suite);
  RegisterTest(TTestEcdsaSignatureEncoding.Suite);
  RegisterTest(TTestPkcs1DigestInfo.Suite);
  RegisterTest(TTestSignatureInputBuffer.Suite);
  RegisterTest(TTestForwardingSigningCrypto.Suite);
  RegisterTest(TTestEcPrivateScalar.Suite);
  RegisterTest(TTestSystemBackendReport.Suite);
  RegisterTest(TTestSystemCryptoStrictness.Suite);
{$ENDIF FPC}

end.
