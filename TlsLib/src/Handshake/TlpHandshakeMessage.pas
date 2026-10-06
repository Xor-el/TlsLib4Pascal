{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpHandshakeMessage;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpTlsLibExceptions,
  TlpWireReader,
  TlpWireVectorMarker,
  TlpIWireWriter,
  TlpWireWriter;

type
  /// <summary>The handshake message types (RFC 8446 4; RFC 5246 7.4 for the
  /// TLS 1.2-only ServerKeyExchange / ServerHelloDone / ClientKeyExchange).</summary>
  TTlsHandshakeType = (
    HelloRequest = 0,
    ClientHello = 1,
    ServerHello = 2,
    NewSessionTicket = 4,
    EndOfEarlyData = 5,
    EncryptedExtensions = 8,
    Certificate = 11,
    ServerKeyExchange = 12,
    CertificateRequest = 13,
    ServerHelloDone = 14,
    CertificateVerify = 15,
    ClientKeyExchange = 16,
    Finished = 20,
    CertificateStatus = 22,
    KeyUpdate = 24,
    CompressedCertificate = 25,
    MessageHash = 254);

  /// <summary>Wire-byte codec for the handshake message type.</summary>
  TTlsHandshakeTypeHelper = record helper for TTlsHandshakeType
  public
    function ToByte: Byte;
    class function TryFromByte(AValue: Byte;
      out AType: TTlsHandshakeType): Boolean; static;
  end;

  /// <summary>
  /// A reassembled handshake message: the raw type byte, the body (excluding the
  /// 4-byte header), and the full wire bytes (type || uint24 length || body) for
  /// feeding the transcript hash exactly as sent. Framing only - the type is not
  /// interpreted here; the state machine decides whether it is expected.
  /// </summary>
  TTlsHandshakeMessage = record
    TypeByte: Byte;
    Body: TBytes;
    Raw: TBytes;
  end;

  /// <summary>Serializes a handshake message: type(1) || length(uint24) || body.</summary>
  THandshakeFraming = class sealed(TObject)
  public
    class function Frame(AMsgType: TTlsHandshakeType; const ABody: TBytes): TBytes;
      static;
  end;

  /// <summary>
  /// Reassembles handshake messages from the handshake-fragment byte stream the
  /// record layer delivers: a message may span several fragments and several
  /// messages may be coalesced in one. Bounded - a declared body length beyond
  /// MaxMessageLength is a fatal decode_error before any of it is buffered
  /// (RFC 8446, DoS resistance). Single-threaded; the caller serializes.
  /// </summary>
  THandshakeMessageReader = class sealed(TObject)
  strict private
  var
    // un-consumed bytes are [FHead, FTail); keeps small-fragment reassembly linear
    FBuffer: TBytes;
    FHead: Int32;
    FTail: Int32;
    FMaxMessageLength: Int32;
    FMaxCertificateMessageLength: Int32;
    FMaxTotalLength: Int32;
  public
    constructor Create;

    /// <summary>Appends inbound handshake-fragment bytes to the reassembly buffer.</summary>
    procedure Append(const AData: TBytes; AOffset, ALength: Int32);
    /// <summary>
    /// Dequeues the next complete message; False when the buffered bytes do not yet
    /// form one (more fragments are needed).
    /// </summary>
    function NextMessage(out AMessage: TTlsHandshakeMessage): Boolean;
    /// <summary>Whether buffered bytes remain that do not yet complete a message.</summary>
    function HasPartial: Boolean;

    /// <summary>The largest handshake message body accepted (default 2^16).</summary>
    property MaxMessageLength: Int32 read FMaxMessageLength;
    /// <summary>The largest Certificate-message body accepted, so a caller's configured chain
    /// budget bounds the uncompressed Certificate the same way the compressed path is bounded.
    /// Applies only to the Certificate handshake type; every other message keeps MaxMessageLength.
    /// Defaults to MaxMessageLength.</summary>
    property MaxCertificateMessageLength: Int32 read FMaxCertificateMessageLength
      write FMaxCertificateMessageLength;
    /// <summary>The hard cap on un-consumed reassembly bytes (anti-DoS, default 2^17).</summary>
    property MaxTotalLength: Int32 read FMaxTotalLength write FMaxTotalLength;
  end;

const
  HandshakeHeaderLength = Int32(4); // type(1) + length(uint24)
  DefaultMaxHandshakeMessageLength = Int32(1 shl 16);
  DefaultMaxHandshakeReassembly = Int32(1 shl 17);

implementation

const
  ReassemblyMinCapacity = Int32(1024);
  ReassemblyRetainCapacity = Int32(1 shl 16);

resourcestring
  SHandshakeMessageTooLong =
    'handshake message body of %d byte(s) exceeds the %d-byte cap';
  SHandshakeReassemblyOverflow =
    'buffered handshake bytes (%d) exceed the %d-byte reassembly cap';
  SHandshakeSliceOutOfRange = 'handshake input slice is outside the supplied buffer';

{ TTlsHandshakeTypeHelper }

function TTlsHandshakeTypeHelper.ToByte: Byte;
begin
  Result := Byte(Ord(Self));
end;

class function TTlsHandshakeTypeHelper.TryFromByte(AValue: Byte;
  out AType: TTlsHandshakeType): Boolean;
begin
  Result := True;
  case AValue of
    0:
      AType := TTlsHandshakeType.HelloRequest;
    1:
      AType := TTlsHandshakeType.ClientHello;
    2:
      AType := TTlsHandshakeType.ServerHello;
    4:
      AType := TTlsHandshakeType.NewSessionTicket;
    5:
      AType := TTlsHandshakeType.EndOfEarlyData;
    8:
      AType := TTlsHandshakeType.EncryptedExtensions;
    11:
      AType := TTlsHandshakeType.Certificate;
    12:
      AType := TTlsHandshakeType.ServerKeyExchange;
    13:
      AType := TTlsHandshakeType.CertificateRequest;
    14:
      AType := TTlsHandshakeType.ServerHelloDone;
    15:
      AType := TTlsHandshakeType.CertificateVerify;
    16:
      AType := TTlsHandshakeType.ClientKeyExchange;
    20:
      AType := TTlsHandshakeType.Finished;
    22:
      AType := TTlsHandshakeType.CertificateStatus;
    24:
      AType := TTlsHandshakeType.KeyUpdate;
    25:
      AType := TTlsHandshakeType.CompressedCertificate;
    // message_hash (254) is a synthetic transcript-only type (RFC 8446 4.4.1) that must never
    // arrive on the wire, so it is intentionally not decodable here
  else
    Result := False;
  end;
end;

{ THandshakeFraming }

class function THandshakeFraming.Frame(AMsgType: TTlsHandshakeType;
  const ABody: TBytes): TBytes;
var
  LWriter: IWireWriter;
  LMarker: TWireVectorMarker;
begin
  Result := nil;
  LWriter := TWireWriter.Create;
  LWriter.WriteUInt8(AMsgType.ToByte);
  LMarker := LWriter.OpenVector(3);
  LWriter.WriteBytes(ABody);
  LWriter.CloseVector(LMarker);
  Result := LWriter.ToBytes;
end;

{ THandshakeMessageReader }

constructor THandshakeMessageReader.Create;
begin
  inherited Create;
  FBuffer := nil;
  FHead := 0;
  FTail := 0;
  FMaxMessageLength := DefaultMaxHandshakeMessageLength;
  FMaxCertificateMessageLength := DefaultMaxHandshakeMessageLength;
  FMaxTotalLength := DefaultMaxHandshakeReassembly;
end;

procedure THandshakeMessageReader.Append(const AData: TBytes;
  AOffset, ALength: Int32);
var
  LLive, LNeed, LCap: Int32;
begin
  if ALength <= 0 then
    Exit;
  // a caller error, not a peer fault: reject rather than read past the slice
  if (AOffset < 0) or (Int64(AOffset) + ALength > System.Length(AData)) then
    raise EArgumentTlsLibException.CreateRes(@SHandshakeSliceOutOfRange);
  LLive := FTail - FHead;
  // bound un-consumed reassembly so a flood of messages cannot grow it without limit
  if Int64(LLive) + ALength > FMaxTotalLength then
    raise EDecodeErrorTlsLibException.CreateResFmt(@SHandshakeReassemblyOverflow,
      [Int64(LLive) + ALength, FMaxTotalLength]);
  if Int64(FTail) + ALength > System.Length(FBuffer) then
  begin
    // reclaim the consumed prefix before growing
    if FHead > 0 then
    begin
      if LLive > 0 then
        System.Move(FBuffer[FHead], FBuffer[0], LLive);
      FHead := 0;
      FTail := LLive;
    end;
    LNeed := FTail + ALength;
    if LNeed > System.Length(FBuffer) then
    begin
      LCap := System.Length(FBuffer);
      if LCap < ReassemblyMinCapacity then
        LCap := ReassemblyMinCapacity;
      if LCap <= High(Int32) div 2 then
        LCap := LCap * 2;
      if LCap < LNeed then
        LCap := LNeed;
      System.SetLength(FBuffer, LCap);
    end;
  end;
  System.Move(AData[AOffset], FBuffer[FTail], ALength);
  Inc(FTail, ALength);
end;

function THandshakeMessageReader.NextMessage(
  out AMessage: TTlsHandshakeMessage): Boolean;
var
  LReader: TWireReader;
  LTypeByte: Byte;
  LBodyLength, LCap, LTotal: Int32;
begin
  Result := False;
  if FTail - FHead < HandshakeHeaderLength then
    Exit; // not even a header yet
  LReader := TWireReader.Create(FBuffer, FHead, FTail - FHead);
  LTypeByte := LReader.ReadUInt8;
  LBodyLength := Int32(LReader.ReadUInt24);
  // the Certificate message carries the peer chain, so it is bounded by the configured chain
  // budget; every other message keeps the tighter default cap
  if LTypeByte = TTlsHandshakeType.Certificate.ToByte then
    LCap := FMaxCertificateMessageLength
  else
    LCap := FMaxMessageLength;
  if LBodyLength > LCap then
    raise EDecodeErrorTlsLibException.CreateResFmt(@SHandshakeMessageTooLong,
      [LBodyLength, LCap]);
  if LReader.Remaining < LBodyLength then
    Exit; // the body spans fragments not yet received
  AMessage.TypeByte := LTypeByte;
  AMessage.Body := LReader.ReadBytes(LBodyLength);
  LTotal := HandshakeHeaderLength + LBodyLength;
  AMessage.Raw := System.Copy(FBuffer, FHead, LTotal);
  Inc(FHead, LTotal);
  if FHead = FTail then
  begin
    FHead := 0;
    FTail := 0;
    // do not pin a buffer sized for one large message
    if System.Length(FBuffer) > ReassemblyRetainCapacity then
      FBuffer := nil;
  end;
  Result := True;
end;

function THandshakeMessageReader.HasPartial: Boolean;
begin
  Result := FTail > FHead;
end;

end.
