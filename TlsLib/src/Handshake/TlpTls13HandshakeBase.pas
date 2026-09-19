{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpTls13HandshakeBase;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpArrayUtilities,
  TlpTlsAlert,
  TlpTlsVersion,
  TlpTlsLibExceptions,
  TlpNegotiationTypes,
  TlpIKeySchedule,
  TlpHandshakeMessage,
  TlpHandshakeEffect,
  TlpITlsEngine,
  TlpHandshakeMachineBase;

type
  /// <summary>
  /// The TLS 1.3 handshake base: the shared version-neutral plumbing plus the 1.3 key
  /// schedule and the post-handshake KeyUpdate machinery (RFC 8446 4.6.3), which both the
  /// client and server share once Connected. A concrete 1.3 machine supplies Start, Route
  /// and its role's read/write directions.
  /// </summary>
  TTls13HandshakeBase = class abstract(THandshakeMachineBase)
  strict protected
    FSchedule: ITls13KeySchedule;
    /// <summary>Whether a peer update_requested is awaiting our single coalesced response,
    /// flushed just before our next application write (RFC 8446 4.6.3): any number of
    /// requests collapses to one response, which also bounds a KeyUpdate flood (18.6).</summary>
    FKeyUpdateResponsePending: Boolean;
    /// <summary>This endpoint's own write (send) traffic direction.</summary>
    function WriteDirection: TTlsDirection; virtual; abstract;
    /// <summary>The peer's write direction, i.e. this endpoint's read direction.</summary>
    function ReadDirection: TTlsDirection; virtual; abstract;
    /// <summary>Advances the application secret for a direction and returns the effect that
    /// installs the fresh keys on the matching record side.</summary>
    function RekeyEffect(ADirection: TTlsDirection;
      ASide: TRecordSide): THandshakeEffect;
    function BuildKeyUpdate(ARequestPeerUpdate: Boolean): TBytes;
    /// <summary>Handles an inbound post-handshake KeyUpdate: rekeys the read epoch, and on
    /// update_requested marks a single response pending (coalescing repeats). Call from the
    /// Connected route.</summary>
    function HandleInboundKeyUpdate(const AMessage: TTlsHandshakeMessage)
      : TArray<THandshakeEffect>;
    /// <summary>Whether the exporter must be withheld even though its secret is derived: False
    /// by default; the client overrides to withhold while its reverify-on-resume verdict is open.
    /// (FPhase/TPhase are strict-private to each concrete machine and differ by role, so this is
    /// a virtual hook rather than a base-level phase check.)</summary>
    function ExportWithheld: Boolean; virtual;
  public
    function RequestKeyUpdate(ARequestPeerUpdate: Boolean)
      : TArray<THandshakeEffect>; override;
    /// <summary>If a response to a peer update_requested is pending, emits it (one
    /// KeyUpdate + a write rekey) and clears the flag; the engine flushes this just before
    /// the next application write, so exactly one response precedes our next data.</summary>
    function TakePendingKeyUpdate: TArray<THandshakeEffect>; override;
    function ExportKeyingMaterial(const ALabel: string; const AContext: TBytes;
      AUseContext: Boolean; ALength: Int32): TBytes; override;
    function CanExportKeyingMaterial: Boolean; override;
  end;

implementation

const
  KeyUpdateNotRequested = Byte(0);
  KeyUpdateRequested = Byte(1);

resourcestring
  SBadKeyUpdate = 'malformed KeyUpdate (request_update must be a single 0 or 1 byte)';

{ TTls13HandshakeBase }

function TTls13HandshakeBase.RekeyEffect(ADirection: TTlsDirection;
  ASide: TRecordSide): THandshakeEffect;
begin
  FSchedule.AdvanceKeyUpdate(ADirection);
  Result := THandshakeEffects.InstallKeys(FSchedule.TrafficKeys(TTlsEpoch.Application,
    ADirection), ASide, FSelectedSuite.Common.Aead, TTlsVersion.Tls13);
end;

function TTls13HandshakeBase.BuildKeyUpdate(ARequestPeerUpdate: Boolean): TBytes;
var
  LFlag: Byte;
begin
  if ARequestPeerUpdate then
    LFlag := KeyUpdateRequested
  else
    LFlag := KeyUpdateNotRequested;
  Result := THandshakeFraming.Frame(TTlsHandshakeType.KeyUpdate, TBytes.Create(LFlag));
end;

function TTls13HandshakeBase.RequestKeyUpdate(
  ARequestPeerUpdate: Boolean): TArray<THandshakeEffect>;
var
  LMessage: TBytes;
begin
  Result := nil;
  // only meaningful once the application epoch exists (the engine also guards on complete)
  if FSchedule = nil then
    Exit;
  // the KeyUpdate goes out under the current write keys; the write epoch rekeys after it
  LMessage := BuildKeyUpdate(ARequestPeerUpdate);
  Result := TArray<THandshakeEffect>.Create(
    THandshakeEffects.SendHandshake(LMessage),
    RekeyEffect(WriteDirection, TRecordSide.WriteSide));
end;

function TTls13HandshakeBase.HandleInboundKeyUpdate(
  const AMessage: TTlsHandshakeMessage): TArray<THandshakeEffect>;
var
  LPeerRequested: Boolean;
begin
  if (System.Length(AMessage.Body) <> 1) or (AMessage.Body[0] > KeyUpdateRequested) then
    raise EFatalAlertTlsLibException.CreateRes(TTlsAlertDescription.DecodeError,
      @SBadKeyUpdate);
  LPeerRequested := AMessage.Body[0] = KeyUpdateRequested;

  // the peer advanced its send keys; rekey our read epoch so later records decrypt
  Result := TArray<THandshakeEffect>.Create(
    RekeyEffect(ReadDirection, TRecordSide.ReadSide));

  // update_requested: mark one response pending (repeats coalesce to a single response,
  // flushed just before our next application write - RFC 8446 4.6.3)
  if LPeerRequested then
    FKeyUpdateResponsePending := True;

  TArrayUtilities.Append<THandshakeEffect>(Result,
    THandshakeEffects.RaiseEvent(TTlsEventKind.KeyUpdateReceived));
end;

function TTls13HandshakeBase.TakePendingKeyUpdate: TArray<THandshakeEffect>;
begin
  Result := nil;
  if not FKeyUpdateResponsePending then
    Exit;
  FKeyUpdateResponsePending := False;
  // the responding KeyUpdate (never update_requested, so no loop) goes out under the
  // current write keys; the write epoch rekeys after it
  Result := TArray<THandshakeEffect>.Create(
    THandshakeEffects.SendHandshake(BuildKeyUpdate(False)),
    RekeyEffect(WriteDirection, TRecordSide.WriteSide));
end;

function TTls13HandshakeBase.ExportWithheld: Boolean;
begin
  Result := False;
end;

function TTls13HandshakeBase.CanExportKeyingMaterial: Boolean;
begin
  // available once the exporter_master_secret is derived - for a server that is half-RTT (after
  // its Finished), before the peer's Finished (RFC 8446 7.5) - unless a role-specific gate
  // withholds it (the client during its reverify-on-resume park)
  Result := (FSchedule <> nil) and FSchedule.HasExporterSecret and not ExportWithheld;
end;

function TTls13HandshakeBase.ExportKeyingMaterial(const ALabel: string;
  const AContext: TBytes; AUseContext: Boolean; ALength: Int32): TBytes;
begin
  // query and operation agree: nothing to export until the secret is available (and not withheld)
  Result := nil;
  if not CanExportKeyingMaterial then
    Exit;
  Result := FSchedule.ExportKeyingMaterial(ALabel, AContext, AUseContext, ALength);
end;

end.
