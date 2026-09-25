{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpHandshakeChannel;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpTlsContentType,
  TlpRecordLayer,
  TlpHandshakeMessage,
  TlpIHandshakeChannel;

type
  /// <summary>
  /// The record-layer handshake channel: sends framed handshake messages (and the
  /// middlebox CCS) out through the record layer, and reassembles the inbound
  /// handshake byte stream the engine feeds in. Owns its reassembler; the record
  /// layer is owned by the engine. Single-threaded.
  /// </summary>
  THandshakeChannel = class sealed(TInterfacedObject, IHandshakeChannel)
  strict private
  var
    FRecordLayer: TRecordLayer;
    FReader: THandshakeMessageReader;
  public
    constructor Create(const ARecordLayer: TRecordLayer); overload;
    /// <summary>As above, bounding the inbound Certificate message to AMaxCertificateMessageLength
    /// (the caller's certificate-chain budget) so the uncompressed Certificate is capped in step
    /// with the compressed path; the reassembly ceiling is raised to fit it.</summary>
    constructor Create(const ARecordLayer: TRecordLayer;
      AMaxCertificateMessageLength: Int32); overload;
    destructor Destroy; override;

    procedure SendHandshake(const AMessage: TBytes);
    procedure SendChangeCipherSpec;
    function ReceiveHandshake(out AMessage: TTlsHandshakeMessage): Boolean;
    function HasPartialInbound: Boolean;

    /// <summary>Feeds inbound handshake-fragment bytes to the reassembler.</summary>
    procedure AppendInbound(const AData: TBytes; AOffset, ALength: Int32);
  end;

implementation

const
  // one max-size TLS plaintext record (16 KiB) plus a following handshake header: the most the
  // reassembler can hold un-consumed once a Certificate completes, since it drains after every append
  MaxCoalescedRecordHeadroom = Int32((1 shl 14) + HandshakeHeaderLength);

{ THandshakeChannel }

constructor THandshakeChannel.Create(const ARecordLayer: TRecordLayer);
begin
  Create(ARecordLayer, DefaultMaxHandshakeMessageLength);
end;

constructor THandshakeChannel.Create(const ARecordLayer: TRecordLayer;
  AMaxCertificateMessageLength: Int32);
begin
  inherited Create;
  FRecordLayer := ARecordLayer;
  FReader := THandshakeMessageReader.Create;
  FReader.MaxCertificateMessageLength := AMaxCertificateMessageLength;
  // the reassembly buffer must hold a full Certificate message before it completes, plus headroom
  // for at most one following coalesced record (drained after every append)
  if FReader.MaxTotalLength <
    AMaxCertificateMessageLength + MaxCoalescedRecordHeadroom then
    FReader.MaxTotalLength :=
      AMaxCertificateMessageLength + MaxCoalescedRecordHeadroom;
end;

destructor THandshakeChannel.Destroy;
begin
  FReader.Free;
  inherited Destroy;
end;

procedure THandshakeChannel.SendHandshake(const AMessage: TBytes);
begin
  FRecordLayer.Write(TTlsContentType.Handshake, AMessage, 0,
    System.Length(AMessage));
end;

procedure THandshakeChannel.SendChangeCipherSpec;
begin
  // the legacy 1-byte 0x01 change_cipher_spec, sent in the clear (RFC 8446 D.4)
  FRecordLayer.Write(TTlsContentType.ChangeCipherSpec, TBytes.Create(1), 0, 1);
end;

function THandshakeChannel.ReceiveHandshake(
  out AMessage: TTlsHandshakeMessage): Boolean;
begin
  Result := FReader.NextMessage(AMessage);
end;

procedure THandshakeChannel.AppendInbound(const AData: TBytes;
  AOffset, ALength: Int32);
begin
  FReader.Append(AData, AOffset, ALength);
end;

function THandshakeChannel.HasPartialInbound: Boolean;
begin
  Result := FReader.HasPartial;
end;

end.
