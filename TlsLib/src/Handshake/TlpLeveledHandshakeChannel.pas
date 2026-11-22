{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpLeveledHandshakeChannel;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  Generics.Collections,
  TlpArrayUtilities,
  TlpIKeySchedule,
  TlpHandshakeMessage,
  TlpIHandshakeChannel,
  TlpIHandshakeMachine,
  TlpTls13HandshakeOutput;

type
  /// <summary>
  /// A TLS 1.3 handshake channel with no record layer under it, for a host that protects records
  /// itself:
  /// each handshake message and each installed traffic secret is queued, in the order the
  /// machine produced it, for the host to pull, and inbound handshake bytes are reassembled into
  /// messages. Handshake bytes ride the level of the latest Handshake or Application write
  /// install (a Plaintext start), and inbound bytes belong to the level of the latest Handshake
  /// or Application read install; an early-data install moves neither, since no handshake
  /// message travels under it. Single-threaded.
  /// </summary>
  TLeveledHandshakeChannel = class sealed(TInterfacedObject, IHandshakeChannel,
    IEpochKeyInstaller)
  strict private
  var
    FReader: THandshakeMessageReader;
    FOutputs: TList<TTls13HandshakeOutput>;
    FReadLevel: TTlsEpoch;
    FWriteLevel: TTlsEpoch;
  public
    constructor Create(AMaxCertificateMessageLength: Int32);
    destructor Destroy; override;

    procedure SendHandshake(const AMessage: TBytes);
    procedure AppendInbound(const AData: TBytes; AOffset, ALength: Int32);
    function ReceiveHandshake(out AMessage: TTlsHandshakeMessage): Boolean;
    function HasPartialInbound: Boolean;

    procedure InstallReadSecret(AEpoch: TTlsEpoch; const ASecret: ITrafficSecret);
    procedure InstallWriteSecret(AEpoch: TTlsEpoch; const ASecret: ITrafficSecret);

    /// <summary>Queues a secret or the end of the handshake after everything queued so far.</summary>
    procedure Enqueue(AKind: TTls13HandshakeOutputKind; ALevel: TTlsEpoch;
      const ASecret: ITrafficSecret);
    /// <summary>Dequeues the oldest queued item; False when none is queued.</summary>
    function TryTake(out AOutput: TTls13HandshakeOutput): Boolean;
    /// <summary>The level inbound handshake bytes must belong to now.</summary>
    property ReadLevel: TTlsEpoch read FReadLevel;
    /// <summary>The level outbound handshake bytes ride now.</summary>
    property WriteLevel: TTlsEpoch read FWriteLevel;
    /// <summary>The queued items, oldest first; the owner may count or clear them.</summary>
    property Queue: TList<TTls13HandshakeOutput> read FOutputs;
  end;

implementation

{ TLeveledHandshakeChannel }

constructor TLeveledHandshakeChannel.Create(AMaxCertificateMessageLength: Int32);
begin
  inherited Create;
  FReader := THandshakeMessageReader.Create(AMaxCertificateMessageLength);
  FOutputs := TList<TTls13HandshakeOutput>.Create;
  FReadLevel := TTlsEpoch.Plaintext;
  FWriteLevel := TTlsEpoch.Plaintext;
end;

destructor TLeveledHandshakeChannel.Destroy;
begin
  FOutputs.Free;
  FReader.Free;
  inherited Destroy;
end;

procedure TLeveledHandshakeChannel.Enqueue(AKind: TTls13HandshakeOutputKind;
  ALevel: TTlsEpoch; const ASecret: ITrafficSecret);
var
  LOutput: TTls13HandshakeOutput;
begin
  LOutput := Default(TTls13HandshakeOutput);
  LOutput.Kind := AKind;
  LOutput.Level := ALevel;
  LOutput.Secret := ASecret;
  FOutputs.Add(LOutput);
end;

procedure TLeveledHandshakeChannel.SendHandshake(const AMessage: TBytes);
var
  LOutput: TTls13HandshakeOutput;
begin
  // consecutive messages of one level reach the host as one run of bytes
  if FOutputs.Count > 0 then
  begin
    LOutput := FOutputs[FOutputs.Count - 1];
    if (LOutput.Kind = TTls13HandshakeOutputKind.HandshakeData) and (LOutput.Level = FWriteLevel) then
    begin
      LOutput.Data := TArrayUtilities.Concat(LOutput.Data, AMessage);
      FOutputs[FOutputs.Count - 1] := LOutput;
      Exit;
    end;
  end;
  LOutput := Default(TTls13HandshakeOutput);
  LOutput.Kind := TTls13HandshakeOutputKind.HandshakeData;
  LOutput.Level := FWriteLevel;
  LOutput.Data := System.Copy(AMessage);
  FOutputs.Add(LOutput);
end;

procedure TLeveledHandshakeChannel.AppendInbound(const AData: TBytes; AOffset,
  ALength: Int32);
begin
  FReader.Append(AData, AOffset, ALength);
end;

function TLeveledHandshakeChannel.ReceiveHandshake(
  out AMessage: TTlsHandshakeMessage): Boolean;
begin
  Result := FReader.NextMessage(AMessage);
end;

function TLeveledHandshakeChannel.HasPartialInbound: Boolean;
begin
  Result := FReader.HasPartial;
end;

procedure TLeveledHandshakeChannel.InstallReadSecret(AEpoch: TTlsEpoch;
  const ASecret: ITrafficSecret);
begin
  if AEpoch in [TTlsEpoch.Handshake, TTlsEpoch.Application] then
    FReadLevel := AEpoch;
  Enqueue(TTls13HandshakeOutputKind.ReadSecret, AEpoch, ASecret);
end;

procedure TLeveledHandshakeChannel.InstallWriteSecret(AEpoch: TTlsEpoch;
  const ASecret: ITrafficSecret);
begin
  if AEpoch in [TTlsEpoch.Handshake, TTlsEpoch.Application] then
    FWriteLevel := AEpoch;
  Enqueue(TTls13HandshakeOutputKind.WriteSecret, AEpoch, ASecret);
end;

function TLeveledHandshakeChannel.TryTake(out AOutput: TTls13HandshakeOutput): Boolean;
begin
  Result := FOutputs.Count > 0;
  if not Result then
    Exit;
  AOutput := FOutputs[0];
  FOutputs.Delete(0);
end;

end.
