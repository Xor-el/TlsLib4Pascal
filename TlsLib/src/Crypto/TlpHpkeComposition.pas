{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpHpkeComposition;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpArrayUtilities,
  TlpCryptoDomainTypes,
  TlpDer,
  TlpICryptoProvider,
  TlpISecretBuffer,
  TlpSecretBuffer,
  TlpSecureMemory,
  TlpTlsLibExceptions;

type
  /// <summary>
  /// The RFC 9180 base-mode HPKE facet, composed entirely over the provider's own
  /// <see cref="ICryptoPrimitives" /> (key agreement + HKDF + AEAD). The single implementation
  /// serves both the portable and the OS-native provider: it uses whatever primitives the seam
  /// hands back, so on the native overlay the KEM/KDF/AEAD run on CNG where available.
  /// </summary>
  THpkeComposition = class(TInterfacedObject, IHpkeCrypto)
  strict private
  var
    FPrimitives: ICryptoPrimitives;
  public
    constructor Create(const APrimitives: ICryptoPrimitives);
    function Suite(AKem, AKdf, AAead: UInt16): IHpkeSuite;
    function ImportRecipientKey(AKem: UInt16;
      const APrivateKey: ISecretBuffer): IHpkeRecipientKey;
    procedure GenerateKeyPair(AKem: UInt16; out APublicKey: TBytes;
      out APrivateKey: ISecretBuffer);
    function ImportPrivateKey(AKem: UInt16; const APkcs8Der: TBytes): ISecretBuffer;
    function SupportedSuites(AKem: UInt16): TArray<THpkeSuiteId>;
    function ValidatePublicKey(AKem: UInt16; const APublicKey: TBytes): Boolean;
    function RandomEncapsulation(AKem: UInt16): TBytes;
  end;

implementation

resourcestring
  SHpkeUnsupportedKem = 'the HPKE KEM is not supported';
  SHpkeRecipientKemMismatch =
    'the HPKE suite KEM does not match the recipient key';
  SHpkeMalformedPrivateKey = 'the HPKE recipient private key is malformed';
  SHpkeMalformedEnc = 'the HPKE encapsulated key could not be processed';
  SHpkeMalformedPublicKey = 'the HPKE recipient public key is malformed';
  SHpkeMessageLimit = 'the HPKE context sequence number is exhausted';

type
  // A base-mode HPKE encryption context (RFC 9180 sec. 5.2). One keyed AEAD + base nonce +
  // sequence; serves as both the sender's sealer and the recipient's opener.
  THpkeContext = class(TInterfacedObject, IHpkeSealer, IHpkeOpener)
  strict private
  var
    FAead: IAead;
    FBaseNonce: TBytes;
    FSeq: UInt64;
    function ComputeNonce: TBytes;
    procedure AdvanceSequence;
  public
    constructor Create(const AAead: IAead; const ABaseNonce: TBytes);
    function Seal(const AAad, APlaintext: TBytes): TBytes;
    function Open(const AAad, ACiphertext: TBytes): TBytes;
  end;

  // The RFC 9180 base-mode primitives, all as class functions over an ICryptoPrimitives so
  // they carry no state and pass only ids/bytes/secrets (never a small record by value).
  THpkeCore = class sealed(TObject)
  strict private
    class function I2OSP2(AValue: Int32): TBytes; static;
    class function KemKdfHash(AKem: UInt16): THashAlgorithm; static;
    class function KemNsecret(AKem: UInt16): Int32; static;
    class function KemSuiteId(AKem: UInt16): TBytes; static;
    class function HpkeSuiteId(AKem, AKdf, AAead: UInt16): TBytes; static;
    // LabeledExtract(salt, label, ikm) = Extract(salt, "HPKE-v1" || suite_id || label || ikm)
    class function LabeledExtract(const APrimitives: ICryptoPrimitives;
      AHash: THashAlgorithm; const ASuiteId, ASalt: TBytes; const ALabel: string;
      const AIkm: ISecretBuffer): ISecretBuffer; static;
    // LabeledExpand(prk, label, info, L) = Expand(prk, I2OSP(L,2)||"HPKE-v1"||suite_id||label||info, L)
    class function LabeledExpand(const APrimitives: ICryptoPrimitives;
      AHash: THashAlgorithm; const ASuiteId: TBytes; const APrk: ISecretBuffer;
      const ALabel: string; const AInfo: TBytes; ALen: Int32): ISecretBuffer; static;
    class function ExtractAndExpand(const APrimitives: ICryptoPrimitives; AKem: UInt16;
      const ADh: ISecretBuffer; const AKemContext: TBytes): ISecretBuffer; static;
  public
    class function KemKeyAgreement(AKem: UInt16): TKeyAgreementAlgorithm; static;
    class function KemNsk(AKem: UInt16): Int32; static;
    class function KdfHash(AKdf: UInt16): THashAlgorithm; static;
    class function AeadAlgorithm(AAead: UInt16): TAeadAlgorithm; static;
    class function IsKnownKem(AKem: UInt16): Boolean; static;
    class function IsKnownKdf(AKdf: UInt16): Boolean; static;
    class function IsRealAead(AAead: UInt16): Boolean; static;
    // Encap(pkR) -> (shared_secret, enc); raises (via Agree) on a malformed/degenerate pkR
    class procedure Encap(const APrimitives: ICryptoPrimitives; AKem: UInt16;
      const ARecipientPublicKey: TBytes; out ASharedSecret: ISecretBuffer;
      out AEnc: TBytes); static;
    // Decap(enc, skR) -> shared_secret; ARecipientPublicKey is the recipient's own derived public
    class function Decap(const APrimitives: ICryptoPrimitives; AKem: UInt16;
      const AEnc: TBytes; const APrivateKey: ISecretBuffer;
      const ARecipientPublicKey: TBytes): ISecretBuffer; static;
    // the base-mode key schedule (RFC 9180 sec. 5.1) yielding a ready context
    class function NewBaseContext(const APrimitives: ICryptoPrimitives;
      AKem, AKdf, AAead: UInt16; const ASharedSecret: ISecretBuffer;
      const AInfo: TBytes): THpkeContext; static;
  end;

  THpkeCompositionSuite = class(TInterfacedObject, IHpkeSuite)
  strict private
  var
    FPrimitives: ICryptoPrimitives;
    FKem, FKdf, FAead: UInt16;
  public
    constructor Create(const APrimitives: ICryptoPrimitives; AKem, AKdf, AAead: UInt16);
    function Kem: UInt16;
    function Kdf: UInt16;
    function Aead: UInt16;
    function AeadTagLength: Int32;
    procedure SetupSealer(const ARecipientPublicKey, AInfo: TBytes;
      out AEnc: TBytes; out ASealer: IHpkeSealer);
  end;

  THpkeCompositionRecipientKey = class(TInterfacedObject, IHpkeRecipientKey)
  strict private
  var
    FPrimitives: ICryptoPrimitives;
    FKem: UInt16;
    FPrivateKey: ISecretBuffer;
    FPublicKey: TBytes;
  public
    constructor Create(const APrimitives: ICryptoPrimitives; AKem: UInt16;
      const APrivateKey: ISecretBuffer; const APublicKey: TBytes);
    function Kem: UInt16;
    function PublicKey: TBytes;
    function SetupOpener(const ASuite: IHpkeSuite;
      const AEnc, AInfo: TBytes): IHpkeOpener;
  end;

  // Extracts the raw KEM scalar from a PKCS#8 private key (RFC 8410 X25519 / RFC 5915 EC), the
  // one HPKE step that is DER, not primitive crypto. A minimal, bounds-checked walker that
  // validates the algorithm (and curve) matches the KEM, so the composition stays self-contained.
  THpkePkcs8 = class sealed(TObject)
  strict private
    class function LeftPad(const A: TBytes; ALen: Int32): TBytes; static;
  public
    class function DecodeScalar(AKem: UInt16; const APkcs8Der: TBytes): ISecretBuffer; static;
  end;

{ THpkeContext }

constructor THpkeContext.Create(const AAead: IAead; const ABaseNonce: TBytes);
begin
  inherited Create;
  FAead := AAead;
  FBaseNonce := ABaseNonce;
  FSeq := 0;
end;

function THpkeContext.ComputeNonce: TBytes;
var
  LNn, LI: Int32;
begin
  LNn := System.Length(FBaseNonce);
  Result := nil;
  SetLength(Result, LNn);
  if LNn > 0 then
    Move(FBaseNonce[0], Result[0], LNn);
  // nonce = base_nonce XOR I2OSP(seq, Nn): seq is big-endian in the low-order 8 bytes
  for LI := 0 to 7 do
    Result[LNn - 1 - LI] := Result[LNn - 1 - LI] xor Byte(FSeq shr (8 * LI));
end;

procedure THpkeContext.AdvanceSequence;
begin
  // Nn is 12 for every HPKE AEAD, so the RFC 9180 limit (2^96-1) is beyond UInt64; guard the
  // UInt64 wrap instead so a run never silently reuses a nonce
  if FSeq = High(UInt64) then
    raise EHpkeOpenTlsLibException.CreateRes(@SHpkeMessageLimit);
  Inc(FSeq);
end;

function THpkeContext.Seal(const AAad, APlaintext: TBytes): TBytes;
begin
  Result := FAead.Seal(ComputeNonce, AAad, APlaintext);
  AdvanceSequence; // advance only after a successful seal
end;

function THpkeContext.Open(const AAad, ACiphertext: TBytes): TBytes;
begin
  // FAead.Open raises on authentication failure without advancing, so a rejected
  // ciphertext never desynchronises the sequence
  try
    Result := FAead.Open(ComputeNonce, AAad, ACiphertext);
  except
    on E: EBaseTlsLibException do
      raise EHpkeOpenTlsLibException.CreateRes(@SHpkeMalformedEnc);
  end;
  AdvanceSequence;
end;

{ THpkeCore }

class function THpkeCore.I2OSP2(AValue: Int32): TBytes;
begin
  Result := TBytes.Create(Byte(AValue shr 8), Byte(AValue));
end;

class function THpkeCore.IsKnownKem(AKem: UInt16): Boolean;
begin
  // X448 (33) is intentionally excluded (no OS backend, no ECH use)
  Result := (AKem = THpkeKem.DHKEM_P256_HKDF_SHA256) or
    (AKem = THpkeKem.DHKEM_P384_HKDF_SHA384) or
    (AKem = THpkeKem.DHKEM_P521_HKDF_SHA512) or
    (AKem = THpkeKem.DHKEM_X25519_HKDF_SHA256);
end;

class function THpkeCore.IsKnownKdf(AKdf: UInt16): Boolean;
begin
  Result := (AKdf = THpkeKdf.HKDF_SHA256) or (AKdf = THpkeKdf.HKDF_SHA384) or
    (AKdf = THpkeKdf.HKDF_SHA512);
end;

class function THpkeCore.IsRealAead(AAead: UInt16): Boolean;
begin
  // every AEAD except export-only (0xFFFF), which cannot seal/open
  Result := (AAead = THpkeAead.AES_128_GCM) or (AAead = THpkeAead.AES_256_GCM) or
    (AAead = THpkeAead.CHACHA20_POLY1305);
end;

class function THpkeCore.KemKeyAgreement(AKem: UInt16): TKeyAgreementAlgorithm;
begin
  case AKem of
    THpkeKem.DHKEM_P256_HKDF_SHA256:
      Result := TKeyAgreementAlgorithm.SECP256R1;
    THpkeKem.DHKEM_P384_HKDF_SHA384:
      Result := TKeyAgreementAlgorithm.SECP384R1;
    THpkeKem.DHKEM_P521_HKDF_SHA512:
      Result := TKeyAgreementAlgorithm.SECP521R1;
    THpkeKem.DHKEM_X25519_HKDF_SHA256:
      Result := TKeyAgreementAlgorithm.X25519;
  else
    raise ENotSupportedTlsLibException.CreateRes(@SHpkeUnsupportedKem);
  end;
end;

class function THpkeCore.KemKdfHash(AKem: UInt16): THashAlgorithm;
begin
  case AKem of
    THpkeKem.DHKEM_P384_HKDF_SHA384:
      Result := THashAlgorithm.SHA_384;
    THpkeKem.DHKEM_P521_HKDF_SHA512:
      Result := THashAlgorithm.SHA_512;
  else
    Result := THashAlgorithm.SHA_256; // P-256 and X25519
  end;
end;

class function THpkeCore.KemNsecret(AKem: UInt16): Int32;
begin
  case AKem of
    THpkeKem.DHKEM_P384_HKDF_SHA384:
      Result := 48;
    THpkeKem.DHKEM_P521_HKDF_SHA512:
      Result := 64;
  else
    Result := 32; // P-256 and X25519
  end;
end;

class function THpkeCore.KemNsk(AKem: UInt16): Int32;
begin
  // the raw private scalar width per curve
  case AKem of
    THpkeKem.DHKEM_P384_HKDF_SHA384:
      Result := 48;
    THpkeKem.DHKEM_P521_HKDF_SHA512:
      Result := 66; // secp521r1 field is 66 bytes
  else
    Result := 32; // P-256 and X25519
  end;
end;

class function THpkeCore.KdfHash(AKdf: UInt16): THashAlgorithm;
begin
  case AKdf of
    THpkeKdf.HKDF_SHA384:
      Result := THashAlgorithm.SHA_384;
    THpkeKdf.HKDF_SHA512:
      Result := THashAlgorithm.SHA_512;
  else
    Result := THashAlgorithm.SHA_256;
  end;
end;

class function THpkeCore.AeadAlgorithm(AAead: UInt16): TAeadAlgorithm;
begin
  case AAead of
    THpkeAead.AES_256_GCM:
      Result := TAeadAlgorithm.AES_256_GCM;
    THpkeAead.CHACHA20_POLY1305:
      Result := TAeadAlgorithm.CHACHA20_POLY1305;
  else
    Result := TAeadAlgorithm.AES_128_GCM;
  end;
end;

class function THpkeCore.KemSuiteId(AKem: UInt16): TBytes;
begin
  Result := TArrayUtilities.Concat(TEncoding.ASCII.GetBytes('KEM'), I2OSP2(AKem));
end;

class function THpkeCore.HpkeSuiteId(AKem, AKdf, AAead: UInt16): TBytes;
begin
  Result := TArrayUtilities.Concat([TEncoding.ASCII.GetBytes('HPKE'), I2OSP2(AKem),
    I2OSP2(AKdf), I2OSP2(AAead)]);
end;

class function THpkeCore.LabeledExtract(const APrimitives: ICryptoPrimitives;
  AHash: THashAlgorithm; const ASuiteId, ASalt: TBytes; const ALabel: string;
  const AIkm: ISecretBuffer): ISecretBuffer;
var
  LPrefix: TBytes;
begin
  LPrefix := TArrayUtilities.Concat([TEncoding.ASCII.GetBytes('HPKE-v1'), ASuiteId,
    TEncoding.ASCII.GetBytes(ALabel)]);
  Result := APrimitives.CreateHkdf(AHash).Extract(ASalt,
    TSecretBuffer.Concat(LPrefix, AIkm));
end;

class function THpkeCore.LabeledExpand(const APrimitives: ICryptoPrimitives;
  AHash: THashAlgorithm; const ASuiteId: TBytes; const APrk: ISecretBuffer;
  const ALabel: string; const AInfo: TBytes; ALen: Int32): ISecretBuffer;
var
  LInfo: TBytes;
begin
  LInfo := TArrayUtilities.Concat([I2OSP2(ALen), TEncoding.ASCII.GetBytes('HPKE-v1'),
    ASuiteId, TEncoding.ASCII.GetBytes(ALabel), AInfo]);
  Result := APrimitives.CreateHkdf(AHash).Expand(APrk, LInfo, ALen);
end;

class function THpkeCore.ExtractAndExpand(const APrimitives: ICryptoPrimitives;
  AKem: UInt16; const ADh: ISecretBuffer; const AKemContext: TBytes): ISecretBuffer;
var
  LHash: THashAlgorithm;
  LSuiteId: TBytes;
  LEaePrk: ISecretBuffer;
begin
  LHash := KemKdfHash(AKem);
  LSuiteId := KemSuiteId(AKem);
  LEaePrk := LabeledExtract(APrimitives, LHash, LSuiteId, nil, 'eae_prk', ADh);
  Result := LabeledExpand(APrimitives, LHash, LSuiteId, LEaePrk, 'shared_secret',
    AKemContext, KemNsecret(AKem));
end;

class procedure THpkeCore.Encap(const APrimitives: ICryptoPrimitives; AKem: UInt16;
  const ARecipientPublicKey: TBytes; out ASharedSecret: ISecretBuffer;
  out AEnc: TBytes);
var
  LKa: IKeyAgreement;
  LSkE, LDh: ISecretBuffer;
begin
  LKa := APrimitives.CreateKeyAgreement(KemKeyAgreement(AKem));
  LKa.GenerateKeyPair(LSkE, AEnc); // AEnc is the serialized ephemeral public key (pkE)
  LDh := LKa.Agree(LSkE, ARecipientPublicKey);
  ASharedSecret := ExtractAndExpand(APrimitives, AKem, LDh,
    TArrayUtilities.Concat(AEnc, ARecipientPublicKey));
end;

class function THpkeCore.Decap(const APrimitives: ICryptoPrimitives; AKem: UInt16;
  const AEnc: TBytes; const APrivateKey: ISecretBuffer;
  const ARecipientPublicKey: TBytes): ISecretBuffer;
var
  LKa: IKeyAgreement;
  LDh: ISecretBuffer;
begin
  LKa := APrimitives.CreateKeyAgreement(KemKeyAgreement(AKem));
  LDh := LKa.Agree(APrivateKey, AEnc);
  Result := ExtractAndExpand(APrimitives, AKem, LDh,
    TArrayUtilities.Concat(AEnc, ARecipientPublicKey));
end;

class function THpkeCore.NewBaseContext(const APrimitives: ICryptoPrimitives;
  AKem, AKdf, AAead: UInt16; const ASharedSecret: ISecretBuffer;
  const AInfo: TBytes): THpkeContext;
var
  LHash: THashAlgorithm;
  LSuiteId, LKsContext, LSharedBytes, LBaseNonce: TBytes;
  LAead: IAead;
  LPskIdHash, LInfoHash, LSecret, LKey: ISecretBuffer;
begin
  LHash := KdfHash(AKdf);
  LSuiteId := HpkeSuiteId(AKem, AKdf, AAead);
  LAead := APrimitives.CreateAead(AeadAlgorithm(AAead));
  // base mode: psk = psk_id = "" ; key_schedule_context = 0x00 || psk_id_hash || info_hash
  LPskIdHash := LabeledExtract(APrimitives, LHash, LSuiteId, nil, 'psk_id_hash',
    TSecretBuffer.From(nil));
  LInfoHash := LabeledExtract(APrimitives, LHash, LSuiteId, nil, 'info_hash',
    TSecretBuffer.From(AInfo));
  LKsContext := TArrayUtilities.Concat([TBytes.Create(0), LPskIdHash.ToBytes,
    LInfoHash.ToBytes]);
  // secret = LabeledExtract(shared_secret, "secret", psk): the shared secret is the salt
  LSharedBytes := ASharedSecret.ToBytes;
  try
    LSecret := LabeledExtract(APrimitives, LHash, LSuiteId, LSharedBytes, 'secret',
      TSecretBuffer.From(nil));
  finally
    TSecureMemory.WipeBytes(LSharedBytes);
  end;
  LKey := LabeledExpand(APrimitives, LHash, LSuiteId, LSecret, 'key', LKsContext,
    LAead.KeySize);
  LBaseNonce := LabeledExpand(APrimitives, LHash, LSuiteId, LSecret, 'base_nonce',
    LKsContext, LAead.NonceSize).ToBytes;
  LAead.Init(LKey);
  Result := THpkeContext.Create(LAead, LBaseNonce);
end;

{ THpkeCompositionSuite }

constructor THpkeCompositionSuite.Create(const APrimitives: ICryptoPrimitives;
  AKem, AKdf, AAead: UInt16);
begin
  inherited Create;
  FPrimitives := APrimitives;
  FKem := AKem;
  FKdf := AKdf;
  FAead := AAead;
end;

function THpkeCompositionSuite.Kem: UInt16;
begin
  Result := FKem;
end;

function THpkeCompositionSuite.Kdf: UInt16;
begin
  Result := FKdf;
end;

function THpkeCompositionSuite.Aead: UInt16;
begin
  Result := FAead;
end;

function THpkeCompositionSuite.AeadTagLength: Int32;
begin
  // every HPKE AEAD uses a 128-bit tag (RFC 9180 sec. 7.3)
  Result := 16;
end;

procedure THpkeCompositionSuite.SetupSealer(const ARecipientPublicKey, AInfo: TBytes;
  out AEnc: TBytes; out ASealer: IHpkeSealer);
var
  LSharedSecret: ISecretBuffer;
begin
  try
    THpkeCore.Encap(FPrimitives, FKem, ARecipientPublicKey, LSharedSecret, AEnc);
  except
    on E: EPeerInputTlsLibException do
      raise EArgumentTlsLibException.CreateRes(@SHpkeMalformedPublicKey);
    on E: EBaseTlsLibException do
      raise;
    on E: Exception do
      raise EArgumentTlsLibException.CreateRes(@SHpkeMalformedPublicKey);
  end;
  ASealer := THpkeCore.NewBaseContext(FPrimitives, FKem, FKdf, FAead, LSharedSecret,
    AInfo) as IHpkeSealer;
end;

{ THpkeCompositionRecipientKey }

constructor THpkeCompositionRecipientKey.Create(const APrimitives: ICryptoPrimitives;
  AKem: UInt16; const APrivateKey: ISecretBuffer; const APublicKey: TBytes);
begin
  inherited Create;
  FPrimitives := APrimitives;
  FKem := AKem;
  FPrivateKey := APrivateKey;
  FPublicKey := APublicKey;
end;

function THpkeCompositionRecipientKey.Kem: UInt16;
begin
  Result := FKem;
end;

function THpkeCompositionRecipientKey.PublicKey: TBytes;
begin
  Result := FPublicKey;
end;

function THpkeCompositionRecipientKey.SetupOpener(const ASuite: IHpkeSuite;
  const AEnc, AInfo: TBytes): IHpkeOpener;
var
  LSharedSecret: ISecretBuffer;
begin
  if ASuite.Kem <> FKem then
    raise EArgumentTlsLibException.CreateRes(@SHpkeRecipientKemMismatch);
  try
    LSharedSecret := THpkeCore.Decap(FPrimitives, FKem, AEnc, FPrivateKey, FPublicKey);
  except
    on E: EPeerInputTlsLibException do
      raise EHpkeOpenTlsLibException.CreateRes(@SHpkeMalformedEnc);
    on E: EBaseTlsLibException do
      raise;
    on E: Exception do
      raise EHpkeOpenTlsLibException.CreateRes(@SHpkeMalformedEnc);
  end;
  Result := THpkeCore.NewBaseContext(FPrimitives, ASuite.Kem, ASuite.Kdf, ASuite.Aead,
    LSharedSecret, AInfo) as IHpkeOpener;
end;

{ THpkePkcs8 }

class function THpkePkcs8.LeftPad(const A: TBytes; ALen: Int32): TBytes;
begin
  if System.Length(A) >= ALen then
    Result := System.Copy(A, System.Length(A) - ALen, ALen)
  else
  begin
    Result := nil;
    SetLength(Result, ALen);
    Move(A[0], Result[ALen - System.Length(A)], System.Length(A));
  end;
end;

class function THpkePkcs8.DecodeScalar(AKem: UInt16;
  const APkcs8Der: TBytes): ISecretBuffer;
const
  OidX25519: array [0 .. 2] of Byte = ($2B, $65, $6E); // 1.3.101.110
  OidEcPublicKey: array [0 .. 6] of Byte =
    ($2A, $86, $48, $CE, $3D, $02, $01);                 // 1.2.840.10045.2.1
  OidP256: array [0 .. 7] of Byte =
    ($2A, $86, $48, $CE, $3D, $03, $01, $07);            // 1.2.840.10045.3.1.7
  OidP384: array [0 .. 4] of Byte = ($2B, $81, $04, $00, $22); // 1.3.132.0.34
  OidP521: array [0 .. 4] of Byte = ($2B, $81, $04, $00, $23); // 1.3.132.0.35
var
  LOfs, LCOfs, LCLen, LNext, LAlgOfs, LAlgLen, LAlgNext, LOidOfs, LOidLen: Int32;
  LScalar: TBytes;
  LX25519, LCurveOk: Boolean;

  procedure Fail;
  begin
    raise EArgumentTlsLibException.CreateRes(@SHpkeMalformedPrivateKey);
  end;

  function Expect(AOffset: Int32; AExpectedTag: Byte;
    out AContentOffset, AContentLen, ANext: Int32): Int32;
  var
    LGotTag: Byte;
  begin
    if (not TDer.ReadTlv(APkcs8Der, AOffset, LGotTag, AContentOffset, AContentLen, ANext)) or
      (LGotTag <> AExpectedTag) then
      Fail;
    Result := AContentOffset;
  end;

begin
  LX25519 := AKem = THpkeKem.DHKEM_X25519_HKDF_SHA256;
  // PrivateKeyInfo ::= SEQUENCE { version, AlgorithmIdentifier, privateKey OCTET STRING }
  Expect(0, $30, LOfs, LCLen, LNext);
  Expect(LOfs, $02, LCOfs, LCLen, LNext); // version
  LOfs := LNext;
  Expect(LOfs, $30, LAlgOfs, LAlgLen, LAlgNext); // AlgorithmIdentifier
  Expect(LAlgOfs, $06, LOidOfs, LOidLen, LNext); // algorithm OID
  if LX25519 then
  begin
    if not TDer.OidMatches(APkcs8Der, LOidOfs, LOidLen, OidX25519) then
      Fail;
  end
  else
  begin
    if not TDer.OidMatches(APkcs8Der, LOidOfs, LOidLen, OidEcPublicKey) then
      Fail;
    Expect(LNext, $06, LOidOfs, LOidLen, LNext); // namedCurve OID
    case AKem of
      THpkeKem.DHKEM_P256_HKDF_SHA256:
        LCurveOk := TDer.OidMatches(APkcs8Der, LOidOfs, LOidLen, OidP256);
      THpkeKem.DHKEM_P384_HKDF_SHA384:
        LCurveOk := TDer.OidMatches(APkcs8Der, LOidOfs, LOidLen, OidP384);
      THpkeKem.DHKEM_P521_HKDF_SHA512:
        LCurveOk := TDer.OidMatches(APkcs8Der, LOidOfs, LOidLen, OidP521);
    else
      LCurveOk := False;
    end;
    if not LCurveOk then
      Fail;
  end;
  LOfs := LAlgNext;
  Expect(LOfs, $04, LCOfs, LCLen, LNext); // privateKey OCTET STRING
  if LX25519 then
  begin
    // CurvePrivateKey ::= OCTET STRING (the 32-byte scalar)
    Expect(LCOfs, $04, LCOfs, LCLen, LNext);
    LScalar := System.Copy(APkcs8Der, LCOfs, LCLen);
  end
  else
  begin
    // ECPrivateKey ::= SEQUENCE { version, privateKey OCTET STRING, ... }
    Expect(LCOfs, $30, LCOfs, LCLen, LNext);
    Expect(LCOfs, $02, LOidOfs, LOidLen, LNext);     // version
    Expect(LNext, $04, LCOfs, LCLen, LNext);         // privateKey OCTET STRING
    // RFC 5915 fixes the scalar at field width; normalise defensively
    LScalar := LeftPad(System.Copy(APkcs8Der, LCOfs, LCLen), THpkeCore.KemNsk(AKem));
  end;
  try
    Result := TSecretBuffer.From(LScalar);
  finally
    TSecureMemory.WipeBytes(LScalar);
  end;
end;

{ THpkeComposition }

constructor THpkeComposition.Create(const APrimitives: ICryptoPrimitives);
begin
  inherited Create;
  FPrimitives := APrimitives;
end;

function THpkeComposition.Suite(AKem, AKdf, AAead: UInt16): IHpkeSuite;
begin
  if THpkeCore.IsKnownKem(AKem) and THpkeCore.IsKnownKdf(AKdf) and
    THpkeCore.IsRealAead(AAead) then
    Result := THpkeCompositionSuite.Create(FPrimitives, AKem, AKdf, AAead) as IHpkeSuite
  else
    Result := nil;
end;

function THpkeComposition.ImportRecipientKey(AKem: UInt16;
  const APrivateKey: ISecretBuffer): IHpkeRecipientKey;
var
  LKa: IKeyAgreement;
  LKey: ISecretBuffer;
  LPub: TBytes;
begin
  if not THpkeCore.IsKnownKem(AKem) then
    raise ENotSupportedTlsLibException.CreateRes(@SHpkeUnsupportedKem);
  LKa := FPrimitives.CreateKeyAgreement(THpkeCore.KemKeyAgreement(AKem));
  try
    // adopt the raw scalar into an agreement key, deriving its public value once
    LKey := LKa.ImportPrivateKey(APrivateKey, LPub);
  except
    on E: Exception do
      raise EArgumentTlsLibException.CreateRes(@SHpkeMalformedPrivateKey);
  end;
  Result := THpkeCompositionRecipientKey.Create(FPrimitives, AKem, LKey, LPub)
    as IHpkeRecipientKey;
end;

procedure THpkeComposition.GenerateKeyPair(AKem: UInt16; out APublicKey: TBytes;
  out APrivateKey: ISecretBuffer);
var
  LKa: IKeyAgreement;
  LKey: ISecretBuffer;
begin
  if not THpkeCore.IsKnownKem(AKem) then
    raise ENotSupportedTlsLibException.CreateRes(@SHpkeUnsupportedKem);
  LKa := FPrimitives.CreateKeyAgreement(THpkeCore.KemKeyAgreement(AKem));
  LKa.GenerateKeyPair(LKey, APublicKey);
  APrivateKey := LKa.ExportPrivateKey(LKey); // the raw scalar, the neutral currency
end;

function THpkeComposition.ImportPrivateKey(AKem: UInt16;
  const APkcs8Der: TBytes): ISecretBuffer;
begin
  if not THpkeCore.IsKnownKem(AKem) then
    raise ENotSupportedTlsLibException.CreateRes(@SHpkeUnsupportedKem);
  Result := THpkePkcs8.DecodeScalar(AKem, APkcs8Der);
end;

function THpkeComposition.SupportedSuites(AKem: UInt16): TArray<THpkeSuiteId>;
const
  CKdfs: array [0 .. 2] of UInt16 = (THpkeKdf.HKDF_SHA256, THpkeKdf.HKDF_SHA384,
    THpkeKdf.HKDF_SHA512);
  CAeads: array [0 .. 2] of UInt16 = (THpkeAead.AES_128_GCM, THpkeAead.AES_256_GCM,
    THpkeAead.CHACHA20_POLY1305);
var
  LI, LJ, LN: Int32;
begin
  Result := nil;
  if not THpkeCore.IsKnownKem(AKem) then
    Exit;
  SetLength(Result, System.Length(CKdfs) * System.Length(CAeads));
  LN := 0;
  for LI := 0 to System.High(CKdfs) do
    for LJ := 0 to System.High(CAeads) do
    begin
      Result[LN] := THpkeSuiteId.Create(AKem, CKdfs[LI], CAeads[LJ]);
      Inc(LN);
    end;
end;

function THpkeComposition.ValidatePublicKey(AKem: UInt16;
  const APublicKey: TBytes): Boolean;
var
  LSharedSecret: ISecretBuffer;
  LEnc: TBytes;
begin
  if not THpkeCore.IsKnownKem(AKem) then
    Exit(False);
  // a trial encapsulation is the KEM's full usability check: it catches a wrong length, an
  // off-curve point, and a small-order X25519 key (a degenerate shared secret Agree rejects)
  try
    THpkeCore.Encap(FPrimitives, AKem, APublicKey, LSharedSecret, LEnc);
    Result := True;
  except
    Result := False;
  end;
end;

function THpkeComposition.RandomEncapsulation(AKem: UInt16): TBytes;
var
  LSharedSecret, LPriv: ISecretBuffer;
  LPub: TBytes;
begin
  Result := nil;
  if not THpkeCore.IsKnownKem(AKem) then
    Exit;
  // encapsulate against a throwaway recipient and hand back the KEM encapsulation
  GenerateKeyPair(AKem, LPub, LPriv);
  THpkeCore.Encap(FPrimitives, AKem, LPub, LSharedSecret, Result);
end;

end.
