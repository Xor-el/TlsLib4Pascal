{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpHandshakeConductor;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpTlsAlert,
  TlpHandshakeMessage,
  TlpIHandshakeChannel,
  TlpIHandshakeMachine,
  TlpHandshakeEffect,
  TlpHandshakeDriver;

type
  /// <summary>
  /// Runs a handshake: it holds the stateful machine, feeds inbound reassembled
  /// messages into it, and applies the effects the machine returns through the
  /// driver. The initiating side (the client) is kicked with Start; a responder
  /// stays idle until its first inbound message. A Fail effect stops delivery.
  /// </summary>
  THandshakeConductor = class sealed(TObject)
  strict private
  var
    FChannel: IHandshakeChannel;
    FDriver: THandshakeDriver;
    FMachine: IHandshakeMachine;
    // set when the machine parks on a peer-certificate verdict (async): further inbound
    // messages are buffered, not processed, until the verdict resolves the park
    FVerdictPending: Boolean;
    // set once the handshake completes; gates the flight-boundary excess-data check off for
    // post-handshake traffic (NewSessionTicket / KeyUpdate legitimately span records)
    FEstablished: Boolean;
    // count of post-handshake messages (KeyUpdate / NewSessionTicket) received with no
    // intervening application data; bounded to refuse a flood, reset by genuine traffic
    FPostHandshakeMessages: Int32;
    class function HasFail(const AEffects: TArray<THandshakeEffect>): Boolean; static;
    class function HasAwaitVerdict(
      const AEffects: TArray<THandshakeEffect>): Boolean; static;
    class function HasEstablished(
      const AEffects: TArray<THandshakeEffect>): Boolean; static;
    /// <summary>Whether the effects begin a new outbound flight or change the read epoch - a
    /// flight boundary at which the peer's prior flight must have ended on a record boundary.</summary>
    class function HasFlightBoundary(
      const AEffects: TArray<THandshakeEffect>): Boolean; static;
    /// <summary>Feeds every whole buffered message into the machine, applying its effects,
    /// until the channel drains, a Fail stops it, or the machine parks for a verdict.</summary>
    procedure DrainInbound;
  public
    constructor Create(const AChannel: IHandshakeChannel;
      const ADriver: THandshakeDriver; const AMachine: IHandshakeMachine);
    destructor Destroy; override;

    /// <summary>Kicks the initiating side's opening flight (a no-op for a responder).</summary>
    procedure Start;
    /// <summary>Feeds one run of decrypted handshake bytes, draining every whole message.</summary>
    procedure DeliverHandshake(const AData: TBytes; AOffset, ALength: Int32);
    /// <summary>Whether the handshake is parked awaiting an async peer-certificate verdict.</summary>
    function AwaitingVerdict: Boolean;
    /// <summary>Resolves a parked peer-certificate verdict: True resumes and drains the
    /// buffered flight (the trust pipeline has already passed); False aborts fail-closed with
    /// AAlert (default bad_certificate). A no-op when nothing is parked.</summary>
    procedure ResolveCertificateVerdict(AAccept: Boolean;
      AAlert: TTlsAlertDescription = TTlsAlertDescription.BadCertificate);
    /// <summary>Applies the machine's post-handshake KeyUpdate effects (RFC 8446 4.6.3).</summary>
    procedure RequestKeyUpdate(ARequestPeerUpdate: Boolean);
    /// <summary>Applies any pending coalesced KeyUpdate response (before an app write).</summary>
    procedure FlushPendingKeyUpdate;
    /// <summary>Notes that application data arrived: genuine traffic resets the consecutive
    /// post-handshake message flood counter (RFC 8446 4.6.3 permits unbounded KeyUpdates over
    /// a connection's life, but not an uninterrupted stream of them).</summary>
    procedure NoteApplicationData;
    /// <summary>Exported keying material from the active machine's secrets (RFC 8446 7.5 /
    /// RFC 5705).</summary>
    function ExportKeyingMaterial(const ALabel: string; const AContext: TBytes;
      AUseContext: Boolean; ALength: Int32): TBytes;
  end;

implementation

const
  // the number of consecutive post-handshake messages tolerated with no intervening application
  // data before the stream is refused as a flood (a peer streaming KeyUpdate is a DoS)
  MaxConsecutivePostHandshakeMessages = Int32(32);

{ THandshakeConductor }

constructor THandshakeConductor.Create(const AChannel: IHandshakeChannel;
  const ADriver: THandshakeDriver; const AMachine: IHandshakeMachine);
begin
  inherited Create;
  FChannel := AChannel;
  FDriver := ADriver;
  FMachine := AMachine;
end;

destructor THandshakeConductor.Destroy;
begin
  FDriver.Free;
  inherited Destroy;
end;

class function THandshakeConductor.HasFail(
  const AEffects: TArray<THandshakeEffect>): Boolean;
var
  LEffect: THandshakeEffect;
begin
  Result := False;
  for LEffect in AEffects do
    if LEffect.Kind = THandshakeEffectKind.Fail then
      Exit(True);
end;

class function THandshakeConductor.HasAwaitVerdict(
  const AEffects: TArray<THandshakeEffect>): Boolean;
var
  LEffect: THandshakeEffect;
begin
  Result := False;
  for LEffect in AEffects do
    if LEffect.Kind = THandshakeEffectKind.AwaitCertificateVerdict then
      Exit(True);
end;

class function THandshakeConductor.HasEstablished(
  const AEffects: TArray<THandshakeEffect>): Boolean;
var
  LEffect: THandshakeEffect;
begin
  Result := False;
  for LEffect in AEffects do
    if LEffect.Kind = THandshakeEffectKind.HandshakeEstablished then
      Exit(True);
end;

class function THandshakeConductor.HasFlightBoundary(
  const AEffects: TArray<THandshakeEffect>): Boolean;
var
  LEffect: THandshakeEffect;
begin
  Result := False;
  for LEffect in AEffects do
    // sending a handshake message means the peer's flight ended and we are responding; a
    // read-epoch install is a key change. Either way the reassembler must be empty (RFC 8446
    // 5.1): a handshake message must not span a key change or a flight boundary.
    if (LEffect.Kind = THandshakeEffectKind.SendHandshake) or
      ((LEffect.Kind = THandshakeEffectKind.InstallKeys) and
      (LEffect.Side = TRecordSide.ReadSide)) then
      Exit(True);
end;

procedure THandshakeConductor.Start;
begin
  FDriver.ApplyAll(FMachine.Start);
end;

procedure THandshakeConductor.RequestKeyUpdate(ARequestPeerUpdate: Boolean);
begin
  FDriver.ApplyAll(FMachine.RequestKeyUpdate(ARequestPeerUpdate));
end;

function THandshakeConductor.ExportKeyingMaterial(const ALabel: string;
  const AContext: TBytes; AUseContext: Boolean; ALength: Int32): TBytes;
begin
  Result := FMachine.ExportKeyingMaterial(ALabel, AContext, AUseContext, ALength);
end;

procedure THandshakeConductor.FlushPendingKeyUpdate;
begin
  FDriver.ApplyAll(FMachine.TakePendingKeyUpdate);
end;

procedure THandshakeConductor.NoteApplicationData;
begin
  FPostHandshakeMessages := 0;
end;

procedure THandshakeConductor.DrainInbound;
var
  LMessage: TTlsHandshakeMessage;
  LEffects: TArray<THandshakeEffect>;
  LEstablished, LFlightBoundary, LWasEstablished: Boolean;
begin
  LEstablished := False;
  LFlightBoundary := False;
  LWasEstablished := FEstablished;
  while FChannel.ReceiveHandshake(LMessage) do
  begin
    // once established, bound a peer flooding post-handshake messages (KeyUpdate /
    // NewSessionTicket) with no intervening application data to reset the count
    if FEstablished then
    begin
      Inc(FPostHandshakeMessages);
      if FPostHandshakeMessages > MaxConsecutivePostHandshakeMessages then
      begin
        FDriver.Apply(THandshakeEffects.Fail(TTlsAlertDescription.UnexpectedMessage));
        Exit;
      end;
    end;
    LEffects := FMachine.ProcessMessage(LMessage);
    FDriver.ApplyAll(LEffects);
    // a Fail makes the connection terminal; do not keep feeding the machine
    if HasFail(LEffects) then
      Exit;
    if HasEstablished(LEffects) then
      LEstablished := True;
    if HasFlightBoundary(LEffects) then
      LFlightBoundary := True;
    // a park for an async peer-certificate verdict suspends processing: the rest of the
    // (possibly coalesced) flight stays buffered until the verdict resumes it
    if HasAwaitVerdict(LEffects) then
    begin
      FVerdictPending := True;
      Break;
    end;
  end;
  if LEstablished then
    FEstablished := True;
  // the peer must not pack the next flight's bytes into the record that ends the current one
  // (RFC 8446 5.1). Once we complete the handshake, or - while still handshaking - respond
  // with a new flight or change the read epoch, any handshake bytes still buffered form a
  // partial message that spans that boundary: excess data. Post-handshake messages
  // (NewSessionTicket / KeyUpdate) may legitimately span records, so the mid-handshake
  // boundary check is gated off once established.
  if FChannel.HasPartialInbound and
    (LEstablished or (LFlightBoundary and not LWasEstablished)) then
    FDriver.Apply(THandshakeEffects.Fail(TTlsAlertDescription.UnexpectedMessage));
end;

procedure THandshakeConductor.DeliverHandshake(const AData: TBytes;
  AOffset, ALength: Int32);
begin
  FChannel.AppendInbound(AData, AOffset, ALength);
  // while parked on a verdict, buffer only; the verdict will drain what is already here
  if FVerdictPending then
    Exit;
  DrainInbound;
end;

function THandshakeConductor.AwaitingVerdict: Boolean;
begin
  Result := FVerdictPending;
end;

procedure THandshakeConductor.ResolveCertificateVerdict(AAccept: Boolean;
  AAlert: TTlsAlertDescription);
var
  LEffects: TArray<THandshakeEffect>;
  LWasEstablished: Boolean;
begin
  if not FVerdictPending then
    Exit;
  FVerdictPending := False;
  if not AAccept then
  begin
    // fail-closed: the host rejected the peer chain (or the deadline expired). The built-in
    // pipeline had already accepted it, so this can only additionally reject - augment-only.
    // AAlert lets a definitive live-revocation reject abort with certificate_revoked
    FDriver.Apply(THandshakeEffects.Fail(AAlert));
    Exit;
  end;
  // accepted. First apply any continuation the machine withheld behind the park: the TLS 1.3
  // reverify-on-resume park sits at ServerFinished, where no peer message remains to drive
  // completion, so the machine emits its closing flight here. The initial-certificate park
  // returns none - its buffered server flight drives it below.
  LWasEstablished := FEstablished;
  LEffects := FMachine.ResumeAfterVerdict;
  FDriver.ApplyAll(LEffects);
  if HasFail(LEffects) then
    Exit;
  if HasEstablished(LEffects) then
    FEstablished := True;
  // the same flight-boundary excess-data guard DrainInbound applies to a batch: the peer's
  // prior flight (the server Finished) must have ended on a record boundary
  if FChannel.HasPartialInbound and
    (HasEstablished(LEffects) or (HasFlightBoundary(LEffects) and not LWasEstablished)) then
  begin
    FDriver.Apply(THandshakeEffects.Fail(TTlsAlertDescription.UnexpectedMessage));
    Exit;
  end;
  // process the buffered remainder: the initial-park server flight (CertificateVerify,
  // Finished), or a NewSessionTicket coalesced behind the resumed server Finished
  DrainInbound;
end;

end.
