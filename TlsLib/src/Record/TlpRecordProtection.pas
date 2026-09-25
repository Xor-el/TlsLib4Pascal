{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpRecordProtection;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpBinaryPrimitives,
  TlpISecretBuffer,
  TlpICryptoProvider,
  TlpCryptoDomainTypes,
  TlpIRecordProtection,
  TlpTlsAlert,
  TlpTlsContentType,
  TlpTlsLibExceptions,
  TlpTlsVersion,
  TlpRecordHeader,
  TlpWireReader,
  TlpSecureMemory;

type
  /// <summary>
  /// Shared state and helpers for the record-protection implementations: the
  /// 64-bit sequence counter, its usage-limit signal, and the small byte / header
  /// utilities. Protect / Unprotect / Overhead are supplied by the descendants.
  /// </summary>
  TRecordProtectionBase = class abstract(TInterfacedObject, IRecordProtection,
    IRecordSequenceControl)
  strict protected
  var
    FSeq: UInt64;
    FRecordLimit: UInt64;
    class function AeadUsageLimit(const AAead: IAead): UInt64; static;
    /// <summary>DeriveNonce into a caller-owned buffer of the IV's length, so the per-record
    /// nonce needs no allocation.</summary>
    class procedure DeriveNonceInto(const AIv: TBytes; ASeq: UInt64;
      const ADest: TBytes); static;
    procedure GuardSequenceNotExhausted;
    procedure GuardUsageLimitNotReached;
  public
    /// <summary>
    /// The per-record nonce: the 8-byte big-endian sequence, right-aligned into a
    /// copy of the write IV and XORed in (RFC 8446 5.3). Pure and non-secret.
    /// </summary>
    class function DeriveNonce(const AIv: TBytes; ASeq: UInt64): TBytes; static;
    function Protect(AContentType: TTlsContentType; const APlaintext: TBytes;
      AOffset, ALength: Int32): TBytes; virtual; abstract;
    function Unprotect(const ARecord: TBytes; AOffset, ALength: Int32;
      out AContentType: TTlsContentType): TBytes; virtual; abstract;
    function Overhead: Int32; virtual; abstract;
    // 0 for TLS 1.2 and the null epoch; TLS 1.3 overrides to 1 (TLSInnerPlaintext type byte)
    function InnerContentTypeLength: Int32; virtual;
    function SequenceNumber: UInt64;
    function NeedsKeyUpdate: Boolean;
    procedure SetSequenceNumber(AValue: UInt64);
  end;

  /// <summary>
  /// The initial plaintext epoch: it only frames and unframes records, with no
  /// AEAD and no sequence. Lets the record layer run before traffic keys exist.
  /// </summary>
  TNullRecordProtection = class sealed(TRecordProtectionBase)
  strict private
  var
    /// <summary>The legacy_record_version for the next record, and whether a one-shot
    /// initial override is pending. A client stamps its initial ClientHello record with
    /// 0x0301 for backward compatibility, then 0x0303 (RFC 8446 5.1).</summary>
    FInitialVersion: TTlsVersion;
    FInitialPending: Boolean;
  public
    constructor Create;
    /// <summary>Makes the next record carry AVersion as its legacy_record_version, reverting
    /// to 0x0303 afterwards (the client's initial-ClientHello 0x0301, RFC 8446 5.1).</summary>
    procedure SetInitialLegacyVersion(const AVersion: TTlsVersion);
    function Protect(AContentType: TTlsContentType; const APlaintext: TBytes;
      AOffset, ALength: Int32): TBytes; override;
    function Unprotect(const ARecord: TBytes; AOffset, ALength: Int32;
      out AContentType: TTlsContentType): TBytes; override;
    function Overhead: Int32; override;
  end;

  /// <summary>
  /// TLS 1.3 record protection (RFC 8446 5.2): nonce = sequence XOR write_iv, the
  /// real content type lives inside the inner plaintext, the outer type is always
  /// application_data, and the AAD is the 5-byte record header.
  /// </summary>
  TTls13RecordProtection = class sealed(TRecordProtectionBase)
  strict private
  var
    FAead: IAead;
    FIv: TBytes;
    // per-record scratch reused across records (the header AAD and the derived nonce), so a
    // record costs one allocation: its own buffer
    FAad: TBytes;
    FNonce: TBytes;
  public
    /// <summary>Installs the epoch: AKey is the AEAD key, AIv the 12-byte write IV.</summary>
    constructor Create(const AKey, AIv: ISecretBuffer; const AAead: IAead);
    destructor Destroy; override;
    function Protect(AContentType: TTlsContentType; const APlaintext: TBytes;
      AOffset, ALength: Int32): TBytes; override;
    function Unprotect(const ARecord: TBytes; AOffset, ALength: Int32;
      out AContentType: TTlsContentType): TBytes; override;
    function Overhead: Int32; override;
    function InnerContentTypeLength: Int32; override;
  end;

  /// <summary>
  /// TLS 1.2 AEAD record protection. Two nonce conventions share the AAD (seq || type
  /// || version || plaintext_length) and the header content type (no inner type):
  /// AES-GCM (RFC 5288) uses a 4-byte implicit salt followed by an 8-byte explicit nonce
  /// carried in each record; ChaCha20-Poly1305 (RFC 7905) uses a 12-byte implicit write
  /// IV XORed with the sequence number, with no explicit nonce on the wire. AEAD-only,
  /// no CBC.
  /// </summary>
  TTls12RecordProtection = class sealed(TRecordProtectionBase)
  strict private
  const
    ExplicitNonceLength = Int32(8);
    // seq(8) || type(1) || version(2) || plaintext_length(2) (RFC 5246 6.2.3.3)
    AadLength = Int32(13);
  var
    FAead: IAead;
    /// <summary>The implicit nonce material from the key_block: a 4-byte salt for AES-GCM,
    /// or the full 12-byte write IV for ChaCha20-Poly1305.</summary>
    FSalt: TBytes;
    /// <summary>True for AES-GCM (RFC 5288 explicit-nonce framing); False for
    /// ChaCha20-Poly1305 (RFC 7905 implicit XOR nonce, no explicit nonce).</summary>
    FUsesExplicitNonce: Boolean;
    // per-record scratch reused across records, see TTls13RecordProtection
    FAad: TBytes;
    FNonce: TBytes;
    procedure BuildAadInto(AContentTypeByte: Byte; AVersionWire: UInt16;
      APlaintextLength: Int32);
  public
    /// <summary>Installs the epoch: AKey is the AEAD key, ASalt the 4-byte implicit nonce.</summary>
    constructor Create(const AKey, ASalt: ISecretBuffer; const AAead: IAead);
    destructor Destroy; override;
    function Protect(AContentType: TTlsContentType; const APlaintext: TBytes;
      AOffset, ALength: Int32): TBytes; override;
    function Unprotect(const ARecord: TBytes; AOffset, ALength: Int32;
      out AContentType: TTlsContentType): TBytes; override;
    function Overhead: Int32; override;
  end;

implementation

const
  // AES-GCM must rekey well before 2^24.5 records (RFC 8446 5.5); ChaCha20-Poly1305
  // is bounded only by the 2^64 sequence, so its limit is the counter itself.
  AesGcmRecordUsageLimit = UInt64(23726566);
  ChaChaRecordUsageLimit = High(UInt64);
  // NeedsKeyUpdate reports the limit reached this many records early, so the KeyUpdate that
  // rekeys the epoch (and a coalesced response and any alert) still seals under the old key
  // before the hard limit refuses to seal at all.
  RekeyLeadRecords = UInt64(16);

resourcestring
  SSequenceExhausted = 'record sequence number exhausted; a key update is required';
  SUsageLimitReached = 'the AEAD record usage limit was reached before a key update could be sent';
  SEmptyInnerPlaintext = 'decrypted record carries no content type';
  SInnerPlaintextTooLong = 'the TLSInnerPlaintext exceeds the 2^14+1 limit';
  SPlaintextTooLong = 'the record plaintext exceeds the 2^14 limit';
  SUnknownContentType = 'record carries an unrecognized content type';
  SRecordTooShort = 'record body is shorter than the AEAD overhead';
  SRecordLengthMismatch = 'record length does not match its header';
  SBadOuterRecordType =
    'a protected TLS 1.3 record must carry the application_data outer type (RFC 8446 5.2)';

{ TRecordProtectionBase }

class function TRecordProtectionBase.AeadUsageLimit(const AAead: IAead): UInt64;
begin
  case AAead.UsageCategory of
    TAeadUsageCategory.AesGcm:
      Result := AesGcmRecordUsageLimit;
  else
    Result := ChaChaRecordUsageLimit;
  end;
end;

class procedure TRecordProtectionBase.DeriveNonceInto(const AIv: TBytes; ASeq: UInt64;
  const ADest: TBytes);
var
  LI, LLast: Int32;
begin
  // right-align the 8-byte big-endian sequence into the write IV and XOR
  Move(AIv[0], ADest[0], System.Length(AIv));
  LLast := System.Length(AIv) - 1;
  for LI := 0 to 7 do
    ADest[LLast - LI] := ADest[LLast - LI] xor Byte(ASeq shr (8 * LI));
end;

class function TRecordProtectionBase.DeriveNonce(const AIv: TBytes; ASeq: UInt64): TBytes;
begin
  Result := nil;
  SetLength(Result, System.Length(AIv));
  DeriveNonceInto(AIv, ASeq, Result);
end;

procedure TRecordProtectionBase.GuardSequenceNotExhausted;
begin
  if FSeq = High(UInt64) then
    raise EInvalidOperationTlsLibException.CreateRes(@SSequenceExhausted);
end;

procedure TRecordProtectionBase.GuardUsageLimitNotReached;
begin
  // the hard bound: refuse to seal once the AEAD usage limit is actually reached, rather than
  // silently exceeding the safety bound. NeedsKeyUpdate flags the soft threshold earlier so a
  // key update is normally sent before this triggers.
  if (FRecordLimit > 0) and (FSeq >= FRecordLimit) then
    raise EInvalidOperationTlsLibException.CreateRes(@SUsageLimitReached);
end;

function TRecordProtectionBase.SequenceNumber: UInt64;
begin
  Result := FSeq;
end;

function TRecordProtectionBase.NeedsKeyUpdate: Boolean;
begin
  // soft threshold: reached a lead margin before the hard limit so a key update can still be
  // sealed under the current epoch (RFC 8446 5.5 advises rekeying before the limit)
  Result := (FRecordLimit > RekeyLeadRecords) and (FSeq >= FRecordLimit - RekeyLeadRecords);
end;

procedure TRecordProtectionBase.SetSequenceNumber(AValue: UInt64);
begin
  FSeq := AValue;
end;

function TRecordProtectionBase.InnerContentTypeLength: Int32;
begin
  Result := 0;
end;

{ TNullRecordProtection }

constructor TNullRecordProtection.Create;
begin
  inherited Create;
  FSeq := 0;
  FRecordLimit := 0;
  FInitialVersion := TTlsVersion.Tls12;
  FInitialPending := False;
end;

procedure TNullRecordProtection.SetInitialLegacyVersion(const AVersion: TTlsVersion);
begin
  FInitialVersion := AVersion;
  FInitialPending := True;
end;

function TNullRecordProtection.Protect(AContentType: TTlsContentType;
  const APlaintext: TBytes; AOffset, ALength: Int32): TBytes;
var
  LHeader: TTlsRecordHeader;
  LVersion: TTlsVersion;
begin
  Result := nil;
  // the initial record (a client's first ClientHello) may carry 0x0301; every record after
  // it carries 0x0303 (RFC 8446 5.1)
  if FInitialPending then
  begin
    LVersion := FInitialVersion;
    FInitialPending := False;
  end
  else
    LVersion := TTlsVersion.Tls12;
  LHeader := TTlsRecordHeader.Create(AContentType, LVersion, ALength);
  SetLength(Result, TRecordLimits.HeaderLength + ALength);
  LHeader.WriteTo(Result, 0);
  if ALength > 0 then
    Move(APlaintext[AOffset], Result[TRecordLimits.HeaderLength], ALength);
end;

function TNullRecordProtection.Unprotect(const ARecord: TBytes;
  AOffset, ALength: Int32; out AContentType: TTlsContentType): TBytes;
var
  LReader: TWireReader;
  LHeader: TTlsRecordHeader;
begin
  Result := nil;
  LReader := TWireReader.Create(ARecord, AOffset, ALength);
  LHeader := TTlsRecordHeader.Parse(LReader, TRecordLimits.MaxPlaintext);
  if ALength <> TRecordLimits.HeaderLength + LHeader.Length then
    raise EDecodeErrorTlsLibException.CreateRes(@SRecordLengthMismatch);
  if not LHeader.TryContentType(AContentType) then
    raise EFatalAlertTlsLibException.CreateRes(TTlsAlertDescription.UnexpectedMessage,
      @SUnknownContentType);
  Result := LReader.ReadBytes(LHeader.Length);
end;

function TNullRecordProtection.Overhead: Int32;
begin
  Result := 0;
end;

{ TTls13RecordProtection }

constructor TTls13RecordProtection.Create(const AKey, AIv: ISecretBuffer;
  const AAead: IAead);
begin
  inherited Create;
  FAead := AAead;
  FAead.Init(AKey);
  FIv := AIv.ToBytes;
  FSeq := 0;
  FRecordLimit := AeadUsageLimit(AAead);
  FAad := nil;
  SetLength(FAad, TRecordLimits.HeaderLength);
  FNonce := nil;
  SetLength(FNonce, System.Length(FIv));
end;

destructor TTls13RecordProtection.Destroy;
begin
  TSecureMemory.WipeBytes(FIv);
  // the nonce is the IV under a public XOR, so it goes with the IV
  TSecureMemory.WipeBytes(FNonce);
  inherited Destroy;
end;

function TTls13RecordProtection.Protect(AContentType: TTlsContentType;
  const APlaintext: TBytes; AOffset, ALength: Int32): TBytes;
var
  LHeader: TTlsRecordHeader;
  LInnerLength: Int32;
begin
  Result := nil;
  GuardSequenceNotExhausted;
  GuardUsageLimitNotReached;
  // the record is built in its own wire buffer: header, then the inner plaintext (content ||
  // real content type, no padding) sealed in place so ciphertext and tag land where they ship
  LInnerLength := ALength + 1;
  // AAD = the record header, opaque_type = application_data, ciphertext length
  LHeader := TTlsRecordHeader.Create(TTlsContentType.ApplicationData,
    TTlsVersion.Tls12, LInnerLength + FAead.TagSize);
  LHeader.WriteTo(FAad, 0);
  SetLength(Result, TRecordLimits.HeaderLength + LInnerLength + FAead.TagSize);
  Move(FAad[0], Result[0], TRecordLimits.HeaderLength);
  if ALength > 0 then
    Move(APlaintext[AOffset], Result[TRecordLimits.HeaderLength], ALength);
  Result[TRecordLimits.HeaderLength + ALength] := AContentType.ToByte;
  DeriveNonceInto(FIv, FSeq, FNonce);
  try
    FAead.Seal(FNonce, FAad, Result, TRecordLimits.HeaderLength, LInnerLength,
      Result, TRecordLimits.HeaderLength);
    Inc(FSeq);
  except
    // until the seal overwrites it, the buffer still holds the plaintext
    TSecureMemory.WipeBytes(Result);
    raise;
  end;
end;

function TTls13RecordProtection.Unprotect(const ARecord: TBytes;
  AOffset, ALength: Int32; out AContentType: TTlsContentType): TBytes;
var
  LReader: TWireReader;
  LHeader: TTlsRecordHeader;
  LInner: TBytes;
  LInnerLength, LI: Int32;
begin
  Result := nil;
  GuardSequenceNotExhausted;
  LReader := TWireReader.Create(ARecord, AOffset, ALength);
  LHeader := TTlsRecordHeader.Parse(LReader, TRecordLimits.MaxCiphertextTls13);
  if ALength <> TRecordLimits.HeaderLength + LHeader.Length then
    raise EDecodeErrorTlsLibException.CreateRes(@SRecordLengthMismatch);
  // AAD is the received 5-byte header exactly as it arrived
  Move(ARecord[AOffset], FAad[0], TRecordLimits.HeaderLength);
  // a body shorter than the tag cannot authenticate; Open surfaces it as bad_record_mac
  LInnerLength := LHeader.Length - FAead.TagSize;
  if LInnerLength < 0 then
    LInnerLength := 0;
  LInner := nil;
  SetLength(LInner, LInnerLength);
  DeriveNonceInto(FIv, FSeq, FNonce);
  // opened straight out of the record body, so the plaintext is materialized once
  FAead.Open(FNonce, FAad, ARecord, AOffset + TRecordLimits.HeaderLength, LHeader.Length,
    LInner, 0);
  try
    // the outer opaque_type check comes AFTER a successful decrypt: a record that fails its
    // AEAD (e.g. a plaintext record arriving where encryption is expected) is a bad_record_mac,
    // and only a validly protected record with the wrong outer type is a framing violation.
    // A protected 1.3 record's outer type is always application_data(23) (RFC 8446 5.2)
    if LHeader.ContentTypeByte <> Byte(Ord(TTlsContentType.ApplicationData)) then
      raise EFatalAlertTlsLibException.CreateRes(TTlsAlertDescription.UnexpectedMessage,
        @SBadOuterRecordType);
    // the full TLSInnerPlaintext (content || type || padding) is capped at 2^14+1
    // (RFC 8446 5.4), independent of how much of it is padding
    if System.Length(LInner) > TRecordLimits.MaxPlaintext + 1 then
      raise EFatalAlertTlsLibException.CreateRes(TTlsAlertDescription.RecordOverflow,
        @SInnerPlaintextTooLong);
    // strip zero padding back to the trailing content-type byte
    LI := System.Length(LInner) - 1;
    while (LI >= 0) and (LInner[LI] = 0) do
      Dec(LI);
    if LI < 0 then
      raise EFatalAlertTlsLibException.CreateRes(TTlsAlertDescription.UnexpectedMessage,
        @SEmptyInnerPlaintext);
    if not TTlsContentType.TryFromByte(LInner[LI], AContentType) then
      raise EFatalAlertTlsLibException.CreateRes(TTlsAlertDescription.UnexpectedMessage,
        @SUnknownContentType);
    // the content is handed up in the buffer it was opened into, trimmed of type and padding
    SetLength(LInner, LI);
    Result := LInner;
    LInner := nil;
    Inc(FSeq);
  finally
    // still held only when a check above failed
    TSecureMemory.WipeBytes(LInner);
  end;
end;

function TTls13RecordProtection.Overhead: Int32;
begin
  // one inner content-type byte plus the AEAD tag
  Result := 1 + FAead.TagSize;
end;

function TTls13RecordProtection.InnerContentTypeLength: Int32;
begin
  Result := 1;
end;

{ TTls12RecordProtection }

constructor TTls12RecordProtection.Create(const AKey, ASalt: ISecretBuffer;
  const AAead: IAead);
begin
  inherited Create;
  FAead := AAead;
  FAead.Init(AKey);
  FSalt := ASalt.ToBytes;
  FSeq := 0;
  FRecordLimit := AeadUsageLimit(AAead);
  // AES-GCM frames an explicit nonce (RFC 5288); ChaCha20-Poly1305 derives the nonce by
  // XORing the sequence number into the write IV, with none on the wire (RFC 7905)
  FUsesExplicitNonce := AAead.UsageCategory = TAeadUsageCategory.AesGcm;
  FAad := nil;
  SetLength(FAad, AadLength);
  FNonce := nil;
  if FUsesExplicitNonce then
    SetLength(FNonce, System.Length(FSalt) + ExplicitNonceLength)
  else
    SetLength(FNonce, System.Length(FSalt));
end;

destructor TTls12RecordProtection.Destroy;
begin
  TSecureMemory.WipeBytes(FSalt);
  // the nonce carries the salt / IV, so it goes with it
  TSecureMemory.WipeBytes(FNonce);
  inherited Destroy;
end;

procedure TTls12RecordProtection.BuildAadInto(AContentTypeByte: Byte;
  AVersionWire: UInt16; APlaintextLength: Int32);
begin
  TBinaryPrimitives.WriteUInt64BigEndian(FAad, 0, FSeq);
  FAad[8] := AContentTypeByte;
  TBinaryPrimitives.WriteUInt16BigEndian(FAad, 9, AVersionWire);
  TBinaryPrimitives.WriteUInt16BigEndian(FAad, 11, UInt16(APlaintextLength));
end;

function TTls12RecordProtection.Protect(AContentType: TTlsContentType;
  const APlaintext: TBytes; AOffset, ALength: Int32): TBytes;
var
  LHeader: TTlsRecordHeader;
  LPrefix, LBodyOffset: Int32;
begin
  Result := nil;
  GuardSequenceNotExhausted;
  GuardUsageLimitNotReached;
  BuildAadInto(AContentType.ToByte, TlsWireVersionTls12, ALength);
  if FUsesExplicitNonce then
  begin
    // AES-GCM (RFC 5288): salt || explicit nonce, the explicit nonce prefixes the record body
    LPrefix := ExplicitNonceLength;
    Move(FSalt[0], FNonce[0], System.Length(FSalt));
    TBinaryPrimitives.WriteUInt64BigEndian(FNonce, System.Length(FSalt), FSeq);
  end
  else
  begin
    // ChaCha20-Poly1305 (RFC 7905): the 12-byte write IV XORed with the sequence number
    LPrefix := 0;
    DeriveNonceInto(FSalt, FSeq, FNonce);
  end;
  // the record is built in its own wire buffer and the plaintext sealed in place
  LHeader := TTlsRecordHeader.Create(AContentType, TTlsVersion.Tls12,
    LPrefix + ALength + FAead.TagSize);
  SetLength(Result, TRecordLimits.HeaderLength + LPrefix + ALength + FAead.TagSize);
  LHeader.WriteTo(Result, 0);
  if LPrefix > 0 then
    TBinaryPrimitives.WriteUInt64BigEndian(Result, TRecordLimits.HeaderLength, FSeq);
  LBodyOffset := TRecordLimits.HeaderLength + LPrefix;
  if ALength > 0 then
    Move(APlaintext[AOffset], Result[LBodyOffset], ALength);
  try
    FAead.Seal(FNonce, FAad, Result, LBodyOffset, ALength, Result, LBodyOffset);
    Inc(FSeq);
  except
    // until the seal overwrites it, the buffer still holds the plaintext
    TSecureMemory.WipeBytes(Result);
    raise;
  end;
end;

function TTls12RecordProtection.Unprotect(const ARecord: TBytes;
  AOffset, ALength: Int32; out AContentType: TTlsContentType): TBytes;
var
  LReader: TWireReader;
  LHeader: TTlsRecordHeader;
  LVersion: TTlsVersion;
  LCipherOffset, LCipherLength, LPlaintextLength: Int32;
begin
  Result := nil;
  GuardSequenceNotExhausted;
  LReader := TWireReader.Create(ARecord, AOffset, ALength);
  LHeader := TTlsRecordHeader.Parse(LReader, TRecordLimits.MaxCiphertextTls12);
  if ALength <> TRecordLimits.HeaderLength + LHeader.Length then
    raise EDecodeErrorTlsLibException.CreateRes(@SRecordLengthMismatch);
  if not LHeader.TryContentType(AContentType) then
    raise EFatalAlertTlsLibException.CreateRes(TTlsAlertDescription.UnexpectedMessage,
      @SUnknownContentType);
  LCipherOffset := AOffset + TRecordLimits.HeaderLength;
  LCipherLength := LHeader.Length;
  if FUsesExplicitNonce then
  begin
    // AES-GCM (RFC 5288): the explicit nonce prefixes the body, salt || explicit is the nonce
    if LHeader.Length < ExplicitNonceLength + FAead.TagSize then
      raise EDecodeErrorTlsLibException.CreateRes(@SRecordTooShort);
    Move(FSalt[0], FNonce[0], System.Length(FSalt));
    Move(ARecord[LCipherOffset], FNonce[System.Length(FSalt)], ExplicitNonceLength);
    Inc(LCipherOffset, ExplicitNonceLength);
    Dec(LCipherLength, ExplicitNonceLength);
  end
  else
  begin
    // ChaCha20-Poly1305 (RFC 7905): no explicit nonce; the whole body is the ciphertext
    if LHeader.Length < FAead.TagSize then
      raise EDecodeErrorTlsLibException.CreateRes(@SRecordTooShort);
    DeriveNonceInto(FSalt, FSeq, FNonce);
  end;
  LPlaintextLength := LCipherLength - FAead.TagSize;
  LVersion := LHeader.Version;
  BuildAadInto(LHeader.ContentTypeByte, LVersion.WireValue, LPlaintextLength);
  SetLength(Result, LPlaintextLength);
  // opened straight out of the record body, so the plaintext is materialized once
  FAead.Open(FNonce, FAad, ARecord, LCipherOffset, LCipherLength, Result, 0);
  // checked after a successful open so a forged oversize record stays a bad_record_mac;
  // the plaintext itself may not exceed 2^14 (RFC 5246 6.2.1)
  if System.Length(Result) > TRecordLimits.MaxPlaintext then
  begin
    TSecureMemory.WipeBytes(Result);
    Result := nil;
    raise EFatalAlertTlsLibException.CreateRes(TTlsAlertDescription.RecordOverflow,
      @SPlaintextTooLong);
  end;
  Inc(FSeq);
end;

function TTls12RecordProtection.Overhead: Int32;
begin
  // AES-GCM adds the explicit nonce plus the tag; ChaCha20-Poly1305 carries no explicit
  // nonce, so only the tag (RFC 5288 / RFC 7905)
  if FUsesExplicitNonce then
    Result := ExplicitNonceLength + FAead.TagSize
  else
    Result := FAead.TagSize;
end;

end.
