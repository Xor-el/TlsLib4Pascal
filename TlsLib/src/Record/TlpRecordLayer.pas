{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpRecordLayer;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  Generics.Collections,
  TlpArrayUtilities,
  TlpIRecordProtection,
  TlpRecordProtection,
  TlpTlsAlert,
  TlpTlsVersion,
  TlpTlsContentType,
  TlpTlsLibExceptions,
  TlpRecordHeader,
  TlpWireReader;

type
  /// <summary>A decrypted, demultiplexed record handed up from the read side.</summary>
  TTlsRecordFragment = record
    ContentType: TTlsContentType;
    Data: TBytes;
  end;

  /// <summary>
  /// The default driver of the record/handshake inversion: it turns a stream of
  /// opaque transport bytes into demultiplexed plaintext fragments and application
  /// writes into protected records. Framing and decryption are split: ProcessInput
  /// only frames (a record may span several feeds or several records may be
  /// coalesced in one), enforcing the reassembly limit, while NextIncoming decrypts
  /// the head framed record lazily under the read epoch installed at pull time and
  /// classifies a legacy change_cipher_spec there. That split lets a
  /// coalesced flight change epoch mid-buffer: the plaintext record installs the
  /// next read epoch before the following record is pulled and decrypted under it.
  /// Outbound it fragments to 2^14 and protects through the write epoch. Sans-IO
  /// and single-threaded (the caller serializes).
  /// </summary>
  TRecordLayer = class sealed(TObject)
  strict private
  var
    FReadProtection: IRecordProtection;
    FWriteProtection: IRecordProtection;
    /// <summary>A read epoch armed to activate on the peer's next change_cipher_spec (TLS 1.2):
    /// the read side stays on the current epoch until that plaintext CCS is consumed, so a peer's
    /// plaintext rejection alert sent before its CCS is read under the right epoch (RFC 5246 7.1).
    /// nil when nothing is armed. TLS 1.3 installs the read epoch immediately instead.</summary>
    FPendingReadProtection: IRecordProtection;
    /// <summary>True until the first read epoch key is installed: an inbound application_data
    /// record decoded while the read side is still plaintext is never valid (0-RTT early data
    /// is encrypted under the early keys, later traffic under the application keys).</summary>
    FReadIsPlaintext: Boolean;
    /// <summary>When set (by the engine for a real handshake), a cleartext application_data
    /// record is rejected as unexpected. Off by default so the record layer stays a plain
    /// framing component for its own unit tests, which feed plaintext application_data.</summary>
    FStrictApplicationData: Boolean;
    /// <summary>Whether the read side is on the accepted-0-RTT early-data epoch, during which an
    /// application_data record legitimately precedes the handshake completion (RFC 8446 4.2.10).
    /// Set when the server installs the early read keys and cleared at EndOfEarlyData; outside
    /// that window an application_data record before the handshake completes is unexpected.</summary>
    FEarlyReadAccepted: Boolean;
    FInbound: TBytes;
    FOutbound: TBytes;
    FFramed: TQueue<TBytes>;
    // running total of the bytes held in FFramed, so the caller can bound the framed backlog
    // (records the peer sent faster than they are pulled) without walking the queue
    FFramedBytes: Int32;
    // the negotiated protocol version once the peer's hello has fixed it; the default
    // (wire value 0) means unknown - no peer hello processed yet
    FNegotiatedVersion: TTlsVersion;
    FMaxCiphertextLength: Int32;
    FMaxInboundBuffer: Int32;
    FMaxFramedBacklog: Int32;
    // raw negotiated record_size_limit values (RFC 8449: the full TLSInnerPlaintext
    // length, incl. content type and padding); 0 = not negotiated (no extra cap)
    FOutboundRecordSizeLimit: Int32;
    FInboundRecordSizeLimit: Int32;
    FMaxConsecutiveEmptyRecords: Int32;
    FConsecutiveEmptyRecords: Int32;
    FMaxChangeCipherSpec: Int32;
    FChangeCipherSpecCount: Int32;
    FHandshakeComplete: Boolean;
    FFailed: Boolean;
    // 0-RTT reject: bytes still allowed to be dropped as undecryptable early data
    FEarlyDataSkipRemaining: Int32;
    procedure GuardUsable;
    class function IsKnownRecordType(AByte: Byte): Boolean; static;
    procedure HandleChangeCipherSpec(const ARecord: TBytes; ABodyOffset,
      ABodyLength: Int32);
    function TryDecodeFramed(const ARecord: TBytes;
      out AFragment: TTlsRecordFragment): Boolean;
    procedure AppendOutgoing(const ARecord: TBytes);
  public
    constructor Create;
    destructor Destroy; override;

    /// <summary>Installs the active read (inbound) epoch. Defaults to plaintext.</summary>
    procedure SetReadProtection(const AProtection: IRecordProtection);
    /// <summary>Arms a read epoch to activate when the peer's next change_cipher_spec is consumed
    /// (TLS 1.2 read-cipher switch, RFC 5246 7.1), rather than immediately. Until then the read
    /// side stays on the current epoch, so a peer's plaintext alert sent before its CCS reads
    /// under the right epoch. Raises if a read epoch is already armed (a double-arm without an
    /// intervening CCS is unreachable and would mask a caller bug).</summary>
    procedure ArmReadProtectionOnChangeCipherSpec(const AProtection: IRecordProtection);
    /// <summary>Installs the active write (outbound) epoch. Defaults to plaintext.</summary>
    procedure SetWriteProtection(const AProtection: IRecordProtection);
    /// <summary>Reverts the write epoch to an unprotected (plaintext) one, abandoning an
    /// installed early-data write protection when a HelloRetryRequest rejects offered 0-RTT
    /// (RFC 8446 4.2.10).</summary>
    procedure RevertWriteToPlaintext;
    /// <summary>A client calls this before its first flight so the initial ClientHello record
    /// carries legacy_record_version 0x0301 (RFC 8446 5.1); later records carry 0x0303.</summary>
    procedure UseClientInitialRecordVersion;

    /// <summary>Feeds transport bytes; frames complete records and queues them raw.</summary>
    procedure ProcessInput(const AWire: TBytes; AOffset, ALength: Int32);
    /// <summary>
    /// Decrypts and dequeues the next framed record under the read epoch installed
    /// at this call; False when none is ready. The caller MUST pull one record at a
    /// time and dispatch it before the next pull, so an epoch installed while
    /// handling one record is active for the record that follows it.
    /// </summary>
    function NextIncoming(out AFragment: TTlsRecordFragment): Boolean;

    /// <summary>
    /// Applies the negotiated record_size_limit (RFC 8449) as raw TLSInnerPlaintext
    /// caps: each value is the full plaintext length including the content-type byte and
    /// padding. Outbound records are fragmented so their TLSInnerPlaintext stays within
    /// AOutboundLimit, and an inbound record whose TLSInnerPlaintext exceeds AInboundLimit
    /// is record_overflow. 0 means the extension was not negotiated (no extra cap beyond
    /// the protocol maximum).
    /// </summary>
    procedure SetRecordSizeLimit(AOutboundLimit, AInboundLimit: Int32);

    /// <summary>Fragments and protects a write to the wire, returning the number of content
    /// bytes actually sealed. For application data, sealing pauses at the write epoch's AEAD
    /// rekey threshold and returns fewer than ALength (0 if already at it), so the caller can
    /// send a KeyUpdate and resume; control records (handshake, alert, change_cipher_spec) are
    /// always sealed in full so the KeyUpdate/alert that resolves the limit is never withheld.</summary>
    function Write(AContentType: TTlsContentType; const AData: TBytes;
      AOffset, ALength: Int32): Int32;
    /// <summary>True when the write epoch has reached its AEAD rekey threshold, so further
    /// application-data writes seal nothing until a KeyUpdate rekeys the write side.</summary>
    function WriteNeedsKeyUpdate: Boolean;
    /// <summary>Forces the write / read epoch's record sequence counter forward (no-op when the
    /// protection exposes no IRecordSequenceControl), so the usage-limit rekey path can be
    /// exercised without sealing 2^24 records. The read side is set in step with the write side to
    /// keep the AEAD nonces synchronized across the two endpoints.</summary>
    procedure SetWriteSequenceNumber(AValue: UInt64);
    procedure SetReadSequenceNumber(AValue: UInt64);
    /// <summary>Removes and returns all pending outbound wire bytes.</summary>
    function TakeOutgoing: TBytes;
    /// <summary>Pending outbound byte count.</summary>
    function PendingOutgoing: Int32;

    /// <summary>Records the negotiated protocol version once the peer's hello fixes it, so an
    /// incoming change_cipher_spec can be classified: middlebox-compat filler to drop under TLS
    /// 1.3, but out of its legal window (fatal) before any hello or under an unarmed TLS 1.2
    /// read epoch (RFC 8446 D.4 / RFC 5246 7.1).</summary>
    procedure SetNegotiatedVersion(const AVersion: TTlsVersion);
    /// <summary>When set, a cleartext application_data record is rejected as unexpected (RFC
    /// 8446 5.1). The engine sets it for a real handshake; off by default for framing tests.</summary>
    property StrictApplicationData: Boolean read FStrictApplicationData
      write FStrictApplicationData;
    /// <summary>The record_overflow ceiling applied to an inbound record's length.</summary>
    property MaxCiphertextLength: Int32 read FMaxCiphertextLength
      write FMaxCiphertextLength;
    /// <summary>The hard cap on buffered partial-record bytes (anti-DoS).</summary>
    property MaxInboundBuffer: Int32 read FMaxInboundBuffer write FMaxInboundBuffer;
    /// <summary>The cap on the total framed-but-not-yet-pulled backlog (complete records the peer
    /// sent faster than the caller pulls them, e.g. while parked or under read backpressure).
    /// InboundBacklogFull reports it; the caller stops feeding rather than growing without bound.</summary>
    property MaxFramedBacklog: Int32 read FMaxFramedBacklog write FMaxFramedBacklog;
    /// <summary>True once the framed backlog (plus any partial residual) has reached
    /// MaxFramedBacklog: the caller must pull/drain before feeding more transport bytes. This is
    /// flow control (a full read buffer), never a protocol error - it raises no alert.</summary>
    function InboundBacklogFull: Boolean;
    /// <summary>Drops all buffered inbound state (framed records and any partial residual). Used
    /// once the connection is closed so post-close bytes are not retained.</summary>
    procedure DiscardInbound;
    /// <summary>The cap on consecutive empty records before it is treated as abuse.</summary>
    property MaxConsecutiveEmptyRecords: Int32 read FMaxConsecutiveEmptyRecords
      write FMaxConsecutiveEmptyRecords;
    /// <summary>The cap on tolerated middlebox change_cipher_spec records (anti-DoS).</summary>
    property MaxChangeCipherSpec: Int32 read FMaxChangeCipherSpec
      write FMaxChangeCipherSpec;

    /// <summary>
    /// Enters the 0-RTT reject skip mode (RFC 8446 4.2.10): NextIncoming drops
    /// undecryptable application_data records (early data the server cannot read), up to
    /// AMaxBytes, until a record decrypts under the installed epoch.
    /// </summary>
    procedure SetEarlyDataSkip(AMaxBytes: Int32);
    /// <summary>Opens (server accepts 0-RTT, on installing the early read keys) or closes (at
    /// EndOfEarlyData) the accepted-early-data read window, during which an application_data
    /// record legitimately precedes the handshake completion (RFC 8446 4.2.10).</summary>
    procedure SetEarlyReadAccepted(AActive: Boolean);

    /// <summary>Marks the handshake complete, after which a change_cipher_spec is no
    /// longer in its legal window and is rejected (RFC 8446 D.4).</summary>
    procedure SetHandshakeComplete;
  end;

implementation

const
  DefaultMaxConsecutiveEmptyRecords = Int32(32);
  // each peer sends at most one middlebox change_cipher_spec; a small margin tolerates
  // an interleaved one without opening a flood vector (RFC 8446 D.4)
  DefaultMaxChangeCipherSpec = Int32(2);
  // a handful of max-size records: comfortably holds a legitimate flight buffered while parked
  // (CertificateVerify + Finished + a few NewSessionTickets) plus a small pull-ahead, while
  // capping a peer that streams faster than the caller drains. Not tied to the (much larger)
  // plaintext app-read buffer, which is a different bound on decrypted data.
  DefaultMaxFramedBacklog = Int32(8) *
    (TRecordLimits.HeaderLength + TRecordLimits.MaxCipherTextTls13);
  OuterApplicationData = Byte(23); // TLSCiphertext outer content type
  OuterChangeCipherSpec = Byte(20); // the legacy change_cipher_spec outer content type
  OuterHandshake = Byte(22); // the handshake outer content type

resourcestring
  SRecordLayerFailed = 'the record layer is in a failed state';
  SReassemblyOverflow = 'buffered partial-record bytes exceed the reassembly cap';
  SBadChangeCipherSpec = 'malformed change_cipher_spec record';
  SUnexpectedContentType = 'unexpected record content type';
  SEmptyRecordFlood = 'too many consecutive empty records';
  STooMuchSkippedEarlyData = 'the peer sent more skipped early data than the bound allows';
  SUnexpectedApplicationData = 'an application_data record arrived before any read epoch keys';
  SRecordSizeLimitExceeded = 'inbound record plaintext exceeds the negotiated record_size_limit';
  SChangeCipherSpecFlood = 'too many change_cipher_spec records';
  SChangeCipherSpecAfterHandshake = 'change_cipher_spec after the handshake completed';
  SChangeCipherSpecOutOfWindow = 'change_cipher_spec outside its legal window';
  SSequenceRewindRejected = 'the record sequence counter may only be advanced, never rewound';
  SProtectedChangeCipherSpec = 'a protected (encrypted) change_cipher_spec record is not allowed';
  SWriteSliceOutOfRange = 'the write offset/length is outside the source buffer';
  SHandshakeBeforeChangeCipherSpec = 'a handshake record arrived before the peer''s change_cipher_spec';
  SReadEpochAlreadyArmed = 'a read epoch is already armed for the next change_cipher_spec';

{ TRecordLayer }

constructor TRecordLayer.Create;
begin
  inherited Create;
  FReadProtection := TNullRecordProtection.Create;
  FWriteProtection := TNullRecordProtection.Create;
  FReadIsPlaintext := True;
  FFramed := TQueue<TBytes>.Create;
  FFramedBytes := 0;
  FMaxCiphertextLength := TRecordLimits.MaxCipherTextTls13;
  FMaxInboundBuffer := TRecordLimits.HeaderLength + TRecordLimits.MaxCipherTextTls13;
  FMaxFramedBacklog := DefaultMaxFramedBacklog;
  FOutboundRecordSizeLimit := 0;
  FInboundRecordSizeLimit := 0;
  FMaxConsecutiveEmptyRecords := DefaultMaxConsecutiveEmptyRecords;
  FConsecutiveEmptyRecords := 0;
  FMaxChangeCipherSpec := DefaultMaxChangeCipherSpec;
  FChangeCipherSpecCount := 0;
  FHandshakeComplete := False;
  FFailed := False;
  FPendingReadProtection := nil;
end;

destructor TRecordLayer.Destroy;
begin
  FFramed.Free;
  inherited Destroy;
end;

procedure TRecordLayer.GuardUsable;
begin
  if FFailed then
    raise EInvalidOperationTlsLibException.CreateRes(@SRecordLayerFailed);
end;

class function TRecordLayer.IsKnownRecordType(AByte: Byte): Boolean;
begin
  // the four outer record content types the layer accepts (RFC 8446 5.1); an
  // unknown or unsupported outer type is rejected at framing, before it is queued
  Result := (AByte = Byte(Ord(TTlsContentType.ChangeCipherSpec))) or
    (AByte = Byte(Ord(TTlsContentType.Alert))) or
    (AByte = Byte(Ord(TTlsContentType.Handshake))) or
    (AByte = Byte(Ord(TTlsContentType.ApplicationData)));
end;

procedure TRecordLayer.SetReadProtection(const AProtection: IRecordProtection);
begin
  FReadProtection := AProtection;
  // a real read epoch (early / handshake / application keys) is now installed
  FReadIsPlaintext := False;
end;

procedure TRecordLayer.ArmReadProtectionOnChangeCipherSpec(
  const AProtection: IRecordProtection);
begin
  // one read install per TLS 1.2 handshake, promoted by the peer's next change_cipher_spec;
  // arming twice without an intervening CCS would mean a caller bug, so refuse it loudly
  if FPendingReadProtection <> nil then
    raise EInvalidOperationTlsLibException.CreateRes(@SReadEpochAlreadyArmed);
  FPendingReadProtection := AProtection;
  // the keys are derived and owned from now, mirroring SetReadProtection; the active read
  // epoch does not change until the change_cipher_spec promotes it (see HandleChangeCipherSpec)
  FReadIsPlaintext := False;
end;

procedure TRecordLayer.SetWriteProtection(const AProtection: IRecordProtection);
begin
  FWriteProtection := AProtection;
end;

procedure TRecordLayer.RevertWriteToPlaintext;
begin
  // drop back to an unprotected write epoch (legacy_record_version 0x0303): a client that
  // offered 0-RTT installed the early-data write keys, but a HelloRetryRequest rejects the
  // early data, so its second ClientHello onward goes out in the clear (RFC 8446 4.2.10)
  FWriteProtection := TNullRecordProtection.Create;
end;

procedure TRecordLayer.UseClientInitialRecordVersion;
var
  LNull: TNullRecordProtection;
begin
  // the write epoch is still plaintext before the first flight; arm the initial 0x0301
  LNull := TNullRecordProtection.Create;
  LNull.SetInitialLegacyVersion(TTlsVersion.LegacyRecordInitial);
  FWriteProtection := LNull;
end;

procedure TRecordLayer.SetRecordSizeLimit(AOutboundLimit, AInboundLimit: Int32);
const
  // the largest a TLSInnerPlaintext may be (RFC 8446 5.4: 2^14 content + 1 type byte)
  MaxInnerPlaintext = TRecordLimits.MaxPlaintext + 1;
begin
  // raw TLSInnerPlaintext caps; ignore a non-positive value and clamp defensively
  if AOutboundLimit > 0 then
  begin
    if AOutboundLimit <= MaxInnerPlaintext then
      FOutboundRecordSizeLimit := AOutboundLimit
    else
      FOutboundRecordSizeLimit := MaxInnerPlaintext;
  end;
  if AInboundLimit > 0 then
  begin
    if AInboundLimit <= MaxInnerPlaintext then
      FInboundRecordSizeLimit := AInboundLimit
    else
      FInboundRecordSizeLimit := MaxInnerPlaintext;
  end;
end;

procedure TRecordLayer.HandleChangeCipherSpec(const ARecord: TBytes;
  ABodyOffset, ABodyLength: Int32);
begin
  // a change_cipher_spec is a single 0x01 byte carried in the clear; reject a malformed one
  if (ABodyLength <> 1) or (ARecord[ABodyOffset] <> 1) then
    raise EFatalAlertTlsLibException.CreateRes(TTlsAlertDescription.UnexpectedMessage,
      @SBadChangeCipherSpec);
  // never legal once the handshake is complete (RFC 8446 D.4)
  if FHandshakeComplete then
    raise EFatalAlertTlsLibException.CreateRes(TTlsAlertDescription.UnexpectedMessage,
      @SChangeCipherSpecAfterHandshake);
  // TLS 1.2 read-cipher switch: a read epoch armed for this change_cipher_spec now becomes the
  // active read epoch, so the record that follows (the peer's encrypted Finished) decrypts under
  // it. This is the only place a TLS 1.2 change_cipher_spec is legal.
  if FPendingReadProtection <> nil then
  begin
    FReadProtection := FPendingReadProtection;
    FPendingReadProtection := nil;
    Exit;
  end;
  // TLS 1.3 middlebox-compatibility filler: dropped, but only a bounded number of times and only
  // once the peer's hello has fixed the version (RFC 8446 D.4 - a change_cipher_spec before the
  // peer's first hello is an unexpected record type).
  if FNegotiatedVersion.Equals(TTlsVersion.Tls13) then
  begin
    Inc(FChangeCipherSpecCount);
    if FChangeCipherSpecCount > FMaxChangeCipherSpec then
      raise EFatalAlertTlsLibException.CreateRes(TTlsAlertDescription.UnexpectedMessage,
        @SChangeCipherSpecFlood);
    Exit;
  end;
  // otherwise out of its legal window: before the peer's first hello (version still unknown), or
  // a TLS 1.2 change_cipher_spec with no read epoch armed (before ClientKeyExchange, or a stray
  // extra one) (RFC 8446 D.4 / RFC 5246 7.1)
  raise EFatalAlertTlsLibException.CreateRes(TTlsAlertDescription.UnexpectedMessage,
    @SChangeCipherSpecOutOfWindow);
end;

procedure TRecordLayer.SetNegotiatedVersion(const AVersion: TTlsVersion);
begin
  FNegotiatedVersion := AVersion;
end;

procedure TRecordLayer.SetHandshakeComplete;
begin
  FHandshakeComplete := True;
end;

function TRecordLayer.InboundBacklogFull: Boolean;
begin
  Result := (FFramedBytes + System.Length(FInbound)) >= FMaxFramedBacklog;
end;

procedure TRecordLayer.DiscardInbound;
begin
  FFramed.Clear;
  FFramedBytes := 0;
  FInbound := nil;
end;

procedure TRecordLayer.SetEarlyDataSkip(AMaxBytes: Int32);
begin
  if AMaxBytes > 0 then
    FEarlyDataSkipRemaining := AMaxBytes
  else
    FEarlyDataSkipRemaining := 0;
end;

procedure TRecordLayer.SetEarlyReadAccepted(AActive: Boolean);
begin
  // a server that accepts 0-RTT reads early data (application_data) before the handshake
  // completes; this marks that window open (on the early read keys) and closed (EndOfEarlyData)
  FEarlyReadAccepted := AActive;
end;

function TRecordLayer.TryDecodeFramed(const ARecord: TBytes;
  out AFragment: TTlsRecordFragment): Boolean;
begin
  // decrypt under the read epoch active at this pull: a coalesced flight may change
  // epoch between records, so the epoch is resolved here, per record, not at framing
  AFragment.Data := FReadProtection.Unprotect(ARecord, 0, System.Length(ARecord),
    AFragment.ContentType);
  // RFC 8449: the record_size_limit caps the whole TLSInnerPlaintext (content + type +
  // padding), so measure it from the wire record - content alone would let padding hide
  // an over-limit record. Only enforced once the extension has been negotiated.
  if (FInboundRecordSizeLimit > 0) and
    ((System.Length(ARecord) - TRecordLimits.HeaderLength - FReadProtection.Overhead +
    FReadProtection.InnerContentTypeLength) > FInboundRecordSizeLimit) then
    raise EFatalAlertTlsLibException.CreateRes(TTlsAlertDescription.RecordOverflow,
      @SRecordSizeLimitExceeded);
  case AFragment.ContentType of
    TTlsContentType.ApplicationData, TTlsContentType.Handshake,
      TTlsContentType.Alert:
      begin
        // an application_data record before the handshake completes is unexpected (RFC 8446 5.1
        // / RFC 5246), whether empty or not: cleartext before any read epoch, or - the case the
        // plaintext flag alone missed - under a real epoch installed mid-handshake (TLS 1.2 keys
        // at the peer ChangeCipherSpec, so before its Finished). The one exception is accepted
        // 0-RTT, where early data legitimately precedes completion under the early-data epoch;
        // the 0-RTT reject skip window drops its own records and is likewise excluded.
        if FStrictApplicationData and
          (AFragment.ContentType = TTlsContentType.ApplicationData) and
          (not FHandshakeComplete) and (not FEarlyReadAccepted) and
          (FEarlyDataSkipRemaining = 0) then
          raise EFatalAlertTlsLibException.CreateRes(
            TTlsAlertDescription.UnexpectedMessage, @SUnexpectedApplicationData);
        if System.Length(AFragment.Data) = 0 then
        begin
          Inc(FConsecutiveEmptyRecords);
          if FConsecutiveEmptyRecords > FMaxConsecutiveEmptyRecords then
            raise EFatalAlertTlsLibException.CreateRes(
              TTlsAlertDescription.UnexpectedMessage, @SEmptyRecordFlood);
          // an empty fragment carries no data to hand up; only its cadence is bounded
          Exit(False);
        end;
        // a warning alert is a non-empty control record but advances neither the handshake
        // nor application data, so it must not clear the empty-record cadence: an empty-record
        // flood stays bounded even when a peer intersperses warning alerts to reset the count.
        // Only a non-empty handshake or application_data record is genuine progress. (A fatal
        // alert terminates the connection, so its effect on this counter is moot.)
        if AFragment.ContentType <> TTlsContentType.Alert then
          FConsecutiveEmptyRecords := 0;
        Result := True;
      end;
    TTlsContentType.ChangeCipherSpec:
      // reaching here is a change_cipher_spec whose content type surfaced from a decrypted
      // record - a PROTECTED change_cipher_spec (a plaintext one is recognized by its outer
      // type and dropped before decryption). A protected change_cipher_spec is never valid and
      // MUST abort with unexpected_message (RFC 8446 5), e.g. a post-handshake CCS a peer sends
      // under the application keys.
      raise EFatalAlertTlsLibException.CreateRes(TTlsAlertDescription.UnexpectedMessage,
        @SProtectedChangeCipherSpec);
  else
    raise EFatalAlertTlsLibException.CreateRes(TTlsAlertDescription.UnexpectedMessage,
      @SUnexpectedContentType);
  end;
end;

procedure TRecordLayer.ProcessInput(const AWire: TBytes; AOffset, ALength: Int32);
var
  LReader: TWireReader;
  LHeader: TTlsRecordHeader;
  LPos, LAvailable, LRecordLength, LResidual: Int32;
begin
  GuardUsable;
  try
    FInbound := TArrayUtilities.Concat(FInbound, System.Copy(AWire, AOffset, ALength));
    LPos := 0;
    while (System.Length(FInbound) - LPos) >= TRecordLimits.HeaderLength do
    begin
      LReader := TWireReader.Create(FInbound, LPos, System.Length(FInbound) - LPos);
      LHeader := TTlsRecordHeader.Parse(LReader, FMaxCiphertextLength);
      LRecordLength := TRecordLimits.HeaderLength + LHeader.Length;
      LAvailable := System.Length(FInbound) - LPos;
      if LAvailable < LRecordLength then
        Break; // the record spans into bytes not yet received
      // structural framing only; decryption is deferred to the pull side
      if not IsKnownRecordType(LHeader.ContentTypeByte) then
        raise EFatalAlertTlsLibException.CreateRes(
          TTlsAlertDescription.UnexpectedMessage, @SUnexpectedContentType);
      // a plaintext change_cipher_spec is queued like any record and judged at pull time, not
      // dropped here: its legality (middlebox-compatibility drop while the handshake runs, but a
      // fatal unexpected_message once complete - RFC 8446 5 / D.4) depends on whether the peer's
      // Finished has been processed, which only happens at the pull side. Dropping it eagerly
      // here would clear a change_cipher_spec coalesced with the peer's final flight before that
      // Finished flips the handshake-complete state.
      FFramed.Enqueue(System.Copy(FInbound, LPos, LRecordLength));
      Inc(FFramedBytes, LRecordLength);
      Inc(LPos, LRecordLength);
    end;
    // keep the trailing partial record; bound how much may sit un-framed
    LResidual := System.Length(FInbound) - LPos;
    FInbound := System.Copy(FInbound, LPos, LResidual);
    if LResidual > FMaxInboundBuffer then
      raise EFatalAlertTlsLibException.CreateRes(TTlsAlertDescription.RecordOverflow,
        @SReassemblyOverflow);
  except
    FFailed := True;
    raise;
  end;
end;

function TRecordLayer.NextIncoming(out AFragment: TTlsRecordFragment): Boolean;
var
  LRecord: TBytes;
begin
  GuardUsable;
  Result := False;
  try
    while FFramed.Count > 0 do
    begin
      LRecord := FFramed.Dequeue;
      Dec(FFramedBytes, System.Length(LRecord));
      // a plaintext change_cipher_spec (never encrypted, so its outer type is authoritative):
      // dropped as middlebox compatibility while the handshake runs, but a fatal
      // unexpected_message once it is complete (RFC 8446 5 / D.4). Judged here at pull time, so a
      // change_cipher_spec coalesced with the peer's final flight is decided after that flight's
      // Finished has been processed (which set the handshake complete), not eagerly at framing.
      if (System.Length(LRecord) > 0) and (LRecord[0] = OuterChangeCipherSpec) then
      begin
        HandleChangeCipherSpec(LRecord, TRecordLimits.HeaderLength,
          System.Length(LRecord) - TRecordLimits.HeaderLength);
        Continue; // classified: promoted (1.2), dropped (1.3), or raised (out of window)
      end;
      // TLS 1.2 read-cipher switch: while a read epoch is armed, the only peer records expected
      // are the plaintext change_cipher_spec that promotes it (handled above) and a plaintext
      // alert (an abort the peer sends before its own CCS). A plaintext handshake record here -
      // a Finished, or a fragment of one, sent before the CCS - is illegal (RFC 5246 7.4.9): the
      // Finished is the first message under the new cipher spec. (application_data while the
      // handshake is incomplete is already rejected by StrictApplicationData.)
      if (FPendingReadProtection <> nil) and (System.Length(LRecord) > 0) and
        (LRecord[0] = OuterHandshake) then
        raise EFatalAlertTlsLibException.CreateRes(TTlsAlertDescription.UnexpectedMessage,
          @SHandshakeBeforeChangeCipherSpec);
      if FEarlyDataSkipRemaining > 0 then
      begin
        // 0-RTT reject / HelloRetryRequest: drop the client's early-data records (bounded),
        // and stop skipping as soon as a genuine handshake record arrives. Early data appears
        // two ways depending on the read epoch active when it is skipped: encrypted under keys
        // the server discarded (a bad_record_mac from the deprotect) after the server flight, or
        // an application_data record decoded under the null/plaintext epoch while waiting for a
        // second ClientHello. Both are dropped; a decoded handshake record ends the skip.
        try
          if TryDecodeFramed(LRecord, AFragment) then
          begin
            if AFragment.ContentType = TTlsContentType.ApplicationData then
            begin
              if System.Length(LRecord) > FEarlyDataSkipRemaining then
                raise EFatalAlertTlsLibException.CreateRes(
                  TTlsAlertDescription.UnexpectedMessage, @STooMuchSkippedEarlyData);
              Dec(FEarlyDataSkipRemaining, System.Length(LRecord));
              Continue; // skip this early-data record
            end;
            FEarlyDataSkipRemaining := 0; // a handshake record: the skip window ends
            Exit(True);
          end;
          FEarlyDataSkipRemaining := 0; // an empty / dropped record: done skipping
        except
          on E: EFatalAlertTlsLibException do
          begin
            if (E.AlertDescription = TTlsAlertDescription.BadRecordMac) and
              (System.Length(LRecord) > 0) and (LRecord[0] = OuterApplicationData) and
              (System.Length(LRecord) <= FEarlyDataSkipRemaining) then
            begin
              Dec(FEarlyDataSkipRemaining, System.Length(LRecord));
              Continue; // skip this early-data record the server cannot read
            end;
            raise;
          end;
        end;
      end
      else if TryDecodeFramed(LRecord, AFragment) then
        Exit(True);
      // a dropped or empty record yields nothing; try the next queued record
    end;
  except
    FFailed := True;
    raise;
  end;
end;

function TRecordLayer.Write(AContentType: TTlsContentType; const AData: TBytes;
  AOffset, ALength: Int32): Int32;
var
  LOffset, LRemaining, LChunk, LPlainCap: Int32;
  LIsAppData: Boolean;
begin
  Result := 0;
  // reject an out-of-range slice at the single chokepoint before Protect
  if (AOffset < 0) or (ALength < 0) or
    (Int64(AOffset) + ALength > System.Length(AData)) then
    raise EArgumentTlsLibException.CreateRes(@SWriteSliceOutOfRange);
  // only application data pauses at the rekey threshold (see the interface doc); a control
  // record always seals so the KeyUpdate/alert that resolves the limit is never withheld, with
  // the hard usage guard in Protect as the backstop.
  LIsAppData := AContentType = TTlsContentType.ApplicationData;
  if LIsAppData and FWriteProtection.NeedsKeyUpdate then
    Exit(0);
  // deliberately not guarded by the read-side failure: the engine must still be
  // able to protect and queue an alert record after an inbound processing error
  LOffset := AOffset;
  LRemaining := ALength;
  // per-record content cap: the 2^14 TLSPlaintext ceiling, further reduced to the
  // negotiated record_size_limit less this epoch's inner content-type byte (RFC 8449)
  LPlainCap := TRecordLimits.MaxPlaintext;
  if (FOutboundRecordSizeLimit > 0) and
    ((FOutboundRecordSizeLimit - FWriteProtection.InnerContentTypeLength) < LPlainCap) then
    LPlainCap := FOutboundRecordSizeLimit - FWriteProtection.InnerContentTypeLength;
  // never a non-positive cap (a pathological tiny limit set through the public setter would
  // otherwise divide by zero / loop forever below); at least one content byte per record
  if LPlainCap < 1 then
    LPlainCap := 1;
  // an empty write emits one empty record (Protect advances the sequence exactly once per record)
  if ALength <= 0 then
  begin
    AppendOutgoing(FWriteProtection.Protect(AContentType, AData, LOffset, 0));
    Exit(0);
  end;
  while LRemaining > 0 do
  begin
    // stop application data at the rekey threshold mid-flight; the caller rekeys and resumes
    if LIsAppData and FWriteProtection.NeedsKeyUpdate then
      Break;
    if LRemaining < LPlainCap then
      LChunk := LRemaining
    else
      LChunk := LPlainCap;
    AppendOutgoing(FWriteProtection.Protect(AContentType, AData, LOffset, LChunk));
    Inc(LOffset, LChunk);
    Dec(LRemaining, LChunk);
    Inc(Result, LChunk);
  end;
end;

procedure TRecordLayer.AppendOutgoing(const ARecord: TBytes);
var
  LBase, LLen: Int32;
begin
  LLen := System.Length(ARecord);
  if LLen <= 0 then
    Exit;
  LBase := System.Length(FOutbound);
  SetLength(FOutbound, LBase + LLen);
  System.Move(ARecord[0], FOutbound[LBase], LLen);
end;

function TRecordLayer.WriteNeedsKeyUpdate: Boolean;
begin
  Result := FWriteProtection.NeedsKeyUpdate;
end;

procedure TRecordLayer.SetWriteSequenceNumber(AValue: UInt64);
var
  LSeq: IRecordSequenceControl;
begin
  // only ever advance the counter: moving it backwards would reuse a nonce
  if AValue < FWriteProtection.SequenceNumber then
    raise EArgumentTlsLibException.CreateRes(@SSequenceRewindRejected);
  if Supports(FWriteProtection, IRecordSequenceControl, LSeq) then
    LSeq.SetSequenceNumber(AValue);
end;

procedure TRecordLayer.SetReadSequenceNumber(AValue: UInt64);
var
  LSeq: IRecordSequenceControl;
begin
  if AValue < FReadProtection.SequenceNumber then
    raise EArgumentTlsLibException.CreateRes(@SSequenceRewindRejected);
  if Supports(FReadProtection, IRecordSequenceControl, LSeq) then
    LSeq.SetSequenceNumber(AValue);
end;

function TRecordLayer.TakeOutgoing: TBytes;
begin
  Result := FOutbound;
  FOutbound := nil;
end;

function TRecordLayer.PendingOutgoing: Int32;
begin
  Result := System.Length(FOutbound);
end;

end.
