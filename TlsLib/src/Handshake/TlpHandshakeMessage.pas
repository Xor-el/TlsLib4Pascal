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
  TlpArrayUtilities,
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
    FBuffer: TBytes;
    FMaxMessageLength: Int32;
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
    property MaxMessageLength: Int32 read FMaxMessageLength write FMaxMessageLength;
    /// <summary>The hard cap on un-consumed reassembly bytes (anti-DoS, default 2^17).</summary>
    property MaxTotalLength: Int32 read FMaxTotalLength write FMaxTotalLength;
  end;

const
  HandshakeHeaderLength = Int32(4); // type(1) + length(uint24)
  DefaultMaxHandshakeMessageLength = Int32(1 shl 16);
  DefaultMaxHandshakeReassembly = Int32(1 shl 17);

implementation

resourcestring
  SHandshakeMessageTooLong =
    'handshake message body of %d byte(s) exceeds the %d-byte cap';
  SHandshakeReassemblyOverflow =
    'buffered handshake bytes (%d) exceed the %d-byte reassembly cap';

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
    254:
      AType := TTlsHandshakeType.MessageHash;
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
  FMaxMessageLength := DefaultMaxHandshakeMessageLength;
  FMaxTotalLength := DefaultMaxHandshakeReassembly;
end;

procedure THandshakeMessageReader.Append(const AData: TBytes;
  AOffset, ALength: Int32);
begin
  if ALength <= 0 then
    Exit;
  FBuffer := TArrayUtilities.Concat(FBuffer, System.Copy(AData, AOffset, ALength));
  // bound un-consumed reassembly so a flood of messages cannot grow it without limit
  if System.Length(FBuffer) > FMaxTotalLength then
    raise EDecodeErrorTlsLibException.CreateResFmt(@SHandshakeReassemblyOverflow,
      [System.Length(FBuffer), FMaxTotalLength]);
end;

function THandshakeMessageReader.NextMessage(
  out AMessage: TTlsHandshakeMessage): Boolean;
var
  LReader: TWireReader;
  LTypeByte: Byte;
  LBodyLength, LTotal: Int32;
begin
  Result := False;
  if System.Length(FBuffer) < HandshakeHeaderLength then
    Exit; // not even a header yet
  LReader := TWireReader.Create(FBuffer);
  LTypeByte := LReader.ReadUInt8;
  LBodyLength := Int32(LReader.ReadUInt24);
  if LBodyLength > FMaxMessageLength then
    raise EDecodeErrorTlsLibException.CreateResFmt(@SHandshakeMessageTooLong,
      [LBodyLength, FMaxMessageLength]);
  if LReader.Remaining < LBodyLength then
    Exit; // the body spans fragments not yet received
  AMessage.TypeByte := LTypeByte;
  AMessage.Body := LReader.ReadBytes(LBodyLength);
  LTotal := HandshakeHeaderLength + LBodyLength;
  AMessage.Raw := System.Copy(FBuffer, 0, LTotal);
  FBuffer := System.Copy(FBuffer, LTotal, System.Length(FBuffer) - LTotal);
  Result := True;
end;

function THandshakeMessageReader.HasPartial: Boolean;
begin
  Result := System.Length(FBuffer) > 0;
end;

end.
