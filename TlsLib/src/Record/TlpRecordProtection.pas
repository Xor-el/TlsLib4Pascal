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
  TlpArrayUtilities,
  TlpBinaryPrimitives,
  TlpISecretBuffer,
  TlpICryptoProvider,
  TlpCryptoAlgorithms,
  TlpIRecordProtection,
  TlpTlsAlert,
  TlpTlsContentType,
  TlpTlsLibExceptions,
  TlpTlsVersion,
  TlpRecordHeader,
  TlpWireReader,
  TlpIWireWriter,
  TlpWireWriter,
  TlpSecureMemory;

type
  /// <summary>
  /// Shared state and helpers for the record-protection implementations: the
  /// 64-bit sequence counter, its usage-limit signal, and the small byte / header
  /// utilities. Protect / Unprotect / Overhead are supplied by the descendants.
  /// </summary>
  TRecordProtectionBase = class abstract(TInterfacedObject, IRecordProtection,
    IRecordProtectionTestHook)
  strict protected
  var
    FSeq: UInt64;
    FRecordLimit: UInt64;
    class function AeadUsageLimit(const AAead: IAead): UInt64; static;
    class function UInt64ToBigEndian8(AValue: UInt64): TBytes; static;
    function SerializeHeader(const AHeader: TTlsRecordHeader): TBytes;
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
  public
    /// <summary>Installs the epoch: AKey is the AEAD key, AIv the 12-byte write IV.</summary>
    constructor Create(const AKey, AIv: ISecretBuffer; const AAead: IAead);
    destructor Destroy; override;
    function Protect(AContentType: TTlsContentType; const APlaintext: TBytes;
      AOffset, ALength: Int32): TBytes; override;
    function Unprotect(const ARecord: TBytes; AOffset, ALength: Int32;
      out AContentType: TTlsContentType): TBytes; override;
    function Overhead: Int32; override;
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
  var
    FAead: IAead;
    /// <summary>The implicit nonce material from the key_block: a 4-byte salt for AES-GCM,
    /// or the full 12-byte write IV for ChaCha20-Poly1305.</summary>
    FSalt: TBytes;
    /// <summary>True for AES-GCM (RFC 5288 explicit-nonce framing); False for
    /// ChaCha20-Poly1305 (RFC 7905 implicit XOR nonce, no explicit nonce).</summary>
    FUsesExplicitNonce: Boolean;
    function BuildAad(AContentTypeByte: Byte; const AVersion: TTlsVersion;
      APlaintextLength: Int32): TBytes;
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

resourcestring
  SSequenceExhausted = 'record sequence number exhausted; a key update is required';
  SUsageLimitReached = 'the AEAD record usage limit was reached and no key update is available';
  SEmptyInnerPlaintext = 'decrypted record carries no content type';
  SInnerPlaintextTooLong = 'the TLSInnerPlaintext exceeds the 2^14+1 limit';
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

class function TRecordProtectionBase.UInt64ToBigEndian8(AValue: UInt64): TBytes;
begin
  Result := nil;
  SetLength(Result, 8);
  TBinaryPrimitives.WriteUInt64BigEndian(Result, 0, AValue);
end;

function TRecordProtectionBase.SerializeHeader(const AHeader: TTlsRecordHeader): TBytes;
var
  LWriter: IWireWriter;
begin
  Result := nil;
  LWriter := TWireWriter.Create;
  AHeader.Serialize(LWriter);
  Result := LWriter.ToBytes;
end;

class function TRecordProtectionBase.DeriveNonce(const AIv: TBytes; ASeq: UInt64): TBytes;
var
  LI, LLast: Int32;
begin
  // right-align the 8-byte big-endian sequence into the write IV and XOR
  Result := System.Copy(AIv);
  LLast := System.Length(Result) - 1;
  for LI := 0 to 7 do
    Result[LLast - LI] := Result[LLast - LI] xor Byte(ASeq shr (8 * LI));
end;

procedure TRecordProtectionBase.GuardSequenceNotExhausted;
begin
  if FSeq = High(UInt64) then
    raise EInvalidOperationTlsLibException.CreateRes(@SSequenceExhausted);
end;

procedure TRecordProtectionBase.GuardUsageLimitNotReached;
begin
  // the AEAD usage limit is reached and no key update is wired yet; refuse to seal
  // another record rather than silently exceeding the AEAD safety bound
  if NeedsKeyUpdate then
    raise EInvalidOperationTlsLibException.CreateRes(@SUsageLimitReached);
end;

function TRecordProtectionBase.SequenceNumber: UInt64;
begin
  Result := FSeq;
end;

function TRecordProtectionBase.NeedsKeyUpdate: Boolean;
begin
  Result := (FRecordLimit > 0) and (FSeq >= FRecordLimit);
end;

procedure TRecordProtectionBase.SetSequenceNumber(AValue: UInt64);
begin
  FSeq := AValue;
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
  LWriter: IWireWriter;
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
  LWriter := TWireWriter.Create;
  LHeader.Serialize(LWriter);
  LWriter.WriteBytes(APlaintext, AOffset, ALength);
  Result := LWriter.ToBytes;
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
end;

destructor TTls13RecordProtection.Destroy;
begin
  TSecureMemory.WipeBytes(FIv);
  inherited Destroy;
end;

function TTls13RecordProtection.Protect(AContentType: TTlsContentType;
  const APlaintext: TBytes; AOffset, ALength: Int32): TBytes;
var
  LInner, LNonce, LAad, LCipher: TBytes;
  LHeader: TTlsRecordHeader;
begin
  Result := nil;
  GuardSequenceNotExhausted;
  GuardUsageLimitNotReached;
  // inner plaintext = content || real content type (no padding in this slice)
  LInner := nil;
  SetLength(LInner, ALength + 1);
  if ALength > 0 then
    Move(APlaintext[AOffset], LInner[0], ALength);
  LInner[ALength] := AContentType.ToByte;
  // AAD = the record header, opaque_type = application_data, ciphertext length
  LHeader := TTlsRecordHeader.Create(TTlsContentType.ApplicationData,
    TTlsVersion.Tls12, ALength + 1 + FAead.TagSize);
  LAad := SerializeHeader(LHeader);
  LNonce := DeriveNonce(FIv, FSeq);
  try
    LCipher := FAead.Seal(LNonce, LAad, LInner);
    Result := TArrayUtilities.Concat(LAad, LCipher);
    Inc(FSeq);
  finally
    TSecureMemory.WipeBytes(LInner);
    TSecureMemory.WipeBytes(LNonce);
  end;
end;

function TTls13RecordProtection.Unprotect(const ARecord: TBytes;
  AOffset, ALength: Int32; out AContentType: TTlsContentType): TBytes;
var
  LReader: TWireReader;
  LHeader: TTlsRecordHeader;
  LAad, LNonce, LBody, LInner: TBytes;
  LI: Int32;
begin
  Result := nil;
  GuardSequenceNotExhausted;
  LReader := TWireReader.Create(ARecord, AOffset, ALength);
  LHeader := TTlsRecordHeader.Parse(LReader, TRecordLimits.MaxCiphertextTls13);
  if ALength <> TRecordLimits.HeaderLength + LHeader.Length then
    raise EDecodeErrorTlsLibException.CreateRes(@SRecordLengthMismatch);
  // AAD is the received 5-byte header exactly as it arrived
  LAad := System.Copy(ARecord, AOffset, TRecordLimits.HeaderLength);
  LBody := LReader.ReadBytes(LHeader.Length);
  LNonce := DeriveNonce(FIv, FSeq);
  try
    LInner := FAead.Open(LNonce, LAad, LBody);
  finally
    TSecureMemory.WipeBytes(LNonce);
  end;
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
    Result := System.Copy(LInner, 0, LI);
    Inc(FSeq);
  finally
    TSecureMemory.WipeBytes(LInner);
  end;
end;

function TTls13RecordProtection.Overhead: Int32;
begin
  // one inner content-type byte plus the AEAD tag
  Result := 1 + FAead.TagSize;
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
end;

destructor TTls12RecordProtection.Destroy;
begin
  TSecureMemory.WipeBytes(FSalt);
  inherited Destroy;
end;

function TTls12RecordProtection.BuildAad(AContentTypeByte: Byte;
  const AVersion: TTlsVersion; APlaintextLength: Int32): TBytes;
var
  LWriter: IWireWriter;
begin
  Result := nil;
  LWriter := TWireWriter.Create;
  LWriter.WriteBytes(UInt64ToBigEndian8(FSeq));
  LWriter.WriteUInt8(AContentTypeByte);
  LWriter.WriteUInt16(AVersion.WireValue);
  LWriter.WriteUInt16(UInt16(APlaintextLength));
  Result := LWriter.ToBytes;
end;

function TTls12RecordProtection.Protect(AContentType: TTlsContentType;
  const APlaintext: TBytes; AOffset, ALength: Int32): TBytes;
var
  LExplicitNonce, LNonce, LAad, LCipher, LBody: TBytes;
  LHeader: TTlsRecordHeader;
begin
  Result := nil;
  GuardSequenceNotExhausted;
  GuardUsageLimitNotReached;
  LAad := BuildAad(AContentType.ToByte, TTlsVersion.Tls12, ALength);
  if FUsesExplicitNonce then
  begin
    // AES-GCM (RFC 5288): salt || explicit nonce, the explicit nonce prefixes the record
    LExplicitNonce := UInt64ToBigEndian8(FSeq);
    LNonce := TArrayUtilities.Concat(FSalt, LExplicitNonce);
  end
  else
    // ChaCha20-Poly1305 (RFC 7905): the 12-byte write IV XORed with the sequence number
    LNonce := DeriveNonce(FSalt, FSeq);
  try
    LCipher := FAead.Seal(LNonce, LAad, System.Copy(APlaintext, AOffset, ALength));
  finally
    TSecureMemory.WipeBytes(LNonce);
  end;
  if FUsesExplicitNonce then
    LBody := TArrayUtilities.Concat(LExplicitNonce, LCipher)
  else
    LBody := LCipher;
  LHeader := TTlsRecordHeader.Create(AContentType, TTlsVersion.Tls12,
    System.Length(LBody));
  Result := TArrayUtilities.Concat(SerializeHeader(LHeader), LBody);
  Inc(FSeq);
end;

function TTls12RecordProtection.Unprotect(const ARecord: TBytes;
  AOffset, ALength: Int32; out AContentType: TTlsContentType): TBytes;
var
  LReader: TWireReader;
  LHeader: TTlsRecordHeader;
  LExplicitNonce, LNonce, LAad, LCipher: TBytes;
  LPlaintextLen: Int32;
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
  if FUsesExplicitNonce then
  begin
    // AES-GCM (RFC 5288): read the explicit nonce prefix, salt || explicit is the nonce
    if LHeader.Length < ExplicitNonceLength + FAead.TagSize then
      raise EDecodeErrorTlsLibException.CreateRes(@SRecordTooShort);
    LExplicitNonce := LReader.ReadBytes(ExplicitNonceLength);
    LCipher := LReader.ReadBytes(LHeader.Length - ExplicitNonceLength);
    LNonce := TArrayUtilities.Concat(FSalt, LExplicitNonce);
  end
  else
  begin
    // ChaCha20-Poly1305 (RFC 7905): no explicit nonce; the whole body is the ciphertext
    if LHeader.Length < FAead.TagSize then
      raise EDecodeErrorTlsLibException.CreateRes(@SRecordTooShort);
    LCipher := LReader.ReadBytes(LHeader.Length);
    LNonce := DeriveNonce(FSalt, FSeq);
  end;
  LPlaintextLen := System.Length(LCipher) - FAead.TagSize;
  LAad := BuildAad(LHeader.ContentTypeByte, LHeader.Version, LPlaintextLen);
  try
    Result := FAead.Open(LNonce, LAad, LCipher);
  finally
    TSecureMemory.WipeBytes(LNonce);
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
