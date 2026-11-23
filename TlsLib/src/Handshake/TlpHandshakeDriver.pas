{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpHandshakeDriver;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpIKeySchedule,
  TlpITlsEngine,
  TlpTlsAlert,
  TlpTlsError,
  TlpTlsLibExceptions,
  TlpIHandshakeChannel,
  TlpIHandshakeMachine,
  TlpHandshakeEffect;

type
  /// <summary>
  /// Applies the pure state machine's effects to the real world: it frames and
  /// sends handshake messages through the channel, hands an epoch's traffic secret
  /// to the key installer, applies the record-only controls and TLS 1.2 keys when the
  /// installer also offers them (failing closed when it does not), and reports events,
  /// completion, cert verdicts, and failures to the sink. The state machine has already
  /// resolved which traffic secret each install uses; the driver only routes.
  /// </summary>
  THandshakeDriver = class sealed(TObject)
  strict private
  var
    FChannel: IHandshakeChannel;
    FInstaller: IEpochKeyInstaller;
    // resolved once from the installer; nil when the installer owns no record layer
    FRecordControl: IRecordLayerControl;
    FSink: IHandshakeSink;
    // resolved once from the sink; nil when the sink does not track the version
    FVersionSink: IHandshakeVersionSink;
    // resolved once from the sink; nil when the sink does not handle async cert verdicts
    FVerdictSink: IHandshakeVerdictSink;
    // resolved once from the sink; nil when the sink does not track connection info
    FConnectionInfoSink: IHandshakeConnectionInfoSink;
    FEchStatusSink: IEchStatusSink;
    // resolved once from the sink; nil when the sink cannot report a failure without an alert
    FLocalFailureSink: IHandshakeLocalFailureSink;
    // resolved once from the sink; nil when the sink does not report a failure cause
    FFailureCauseSink: IHandshakeFailureCauseSink;
    // set once a record-only effect failed for want of the companion
    FRecordControlMissing: Boolean;
    procedure ApplyInstallKeys(const AEffect: THandshakeEffect);
    procedure ApplyRecordControl(const AEffect: THandshakeEffect);
  public
    constructor Create(const AChannel: IHandshakeChannel;
      const AInstaller: IEpochKeyInstaller; const ASink: IHandshakeSink);

    procedure Apply(const AEffect: THandshakeEffect);
    procedure ApplyAll(const AEffects: TArray<THandshakeEffect>);
  end;

implementation

resourcestring
  SVerdictUndeliverable = 'the handshake parked for a certificate verdict that nothing can deliver';
  SRecordControlMissing = 'the handshake needs a record layer that the installer does not provide';

{ THandshakeDriver }

constructor THandshakeDriver.Create(const AChannel: IHandshakeChannel;
  const AInstaller: IEpochKeyInstaller; const ASink: IHandshakeSink);
begin
  inherited Create;
  FChannel := AChannel;
  FInstaller := AInstaller;
  FSink := ASink;
  if not Supports(AInstaller, IRecordLayerControl, FRecordControl) then
    FRecordControl := nil;
  if not Supports(ASink, IHandshakeVersionSink, FVersionSink) then
    FVersionSink := nil;
  if not Supports(ASink, IHandshakeVerdictSink, FVerdictSink) then
    FVerdictSink := nil;
  if not Supports(ASink, IHandshakeConnectionInfoSink, FConnectionInfoSink) then
    FConnectionInfoSink := nil;
  if not Supports(ASink, IEchStatusSink, FEchStatusSink) then
    FEchStatusSink := nil;
  if not Supports(ASink, IHandshakeLocalFailureSink, FLocalFailureSink) then
    FLocalFailureSink := nil;
  if not Supports(ASink, IHandshakeFailureCauseSink, FFailureCauseSink) then
    FFailureCauseSink := nil;
end;

procedure THandshakeDriver.ApplyRecordControl(const AEffect: THandshakeEffect);
begin
  if FRecordControl = nil then
  begin
    // the installer owns no record layer: fail closed and apply nothing more from this batch
    FSink.OnHandshakeFailed(TTlsAlertDescription.InternalError, SRecordControlMissing);
    FRecordControlMissing := True;
    Exit;
  end;
  case AEffect.Kind of
    THandshakeEffectKind.SendChangeCipherSpec:
      FRecordControl.SendChangeCipherSpec;
    THandshakeEffectKind.SetRecordSizeLimit:
      FRecordControl.SetRecordSizeLimit(AEffect.Outbound, AEffect.Inbound);
    THandshakeEffectKind.SkipEarlyData:
      FRecordControl.SetEarlyDataSkip(AEffect.MaxBytes);
    THandshakeEffectKind.SetEarlyDataLimit:
      FRecordControl.SetEarlyDataLimit(AEffect.MaxBytes);
    THandshakeEffectKind.RevertWriteToPlaintext:
      FRecordControl.RevertWriteToPlaintext;
    THandshakeEffectKind.SetEarlyReadEpoch:
      FRecordControl.SetEarlyReadEpoch(AEffect.Active, AEffect.MaxBytes);
  end;
end;

procedure THandshakeDriver.ApplyInstallKeys(const AEffect: THandshakeEffect);
begin
  // the negotiated version rides every key install; surface it for connection info, except on the
  // early-data install, whose version is not negotiated (the hello effect or handshake install reports it)
  if (FVersionSink <> nil) and (AEffect.Epoch <> TTlsEpoch.EarlyData) then
    FVersionSink.OnVersionNegotiated(AEffect.Version);
  if AEffect.Secret <> nil then
  begin
    if AEffect.Side = TRecordSide.ReadSide then
      FInstaller.InstallReadSecret(AEffect.Epoch, AEffect.Secret)
    else
      FInstaller.InstallWriteSecret(AEffect.Epoch, AEffect.Secret);
  end
  else if FRecordControl = nil then
  begin
    // TLS 1.2 keys install through the record layer: fail closed without it
    FSink.OnHandshakeFailed(TTlsAlertDescription.InternalError, SRecordControlMissing);
    FRecordControlMissing := True;
  end
  else if AEffect.Side = TRecordSide.WriteSide then
    FRecordControl.InstallWriteKeys(AEffect.Epoch, AEffect.Keys, AEffect.Aead)
  else
    // TLS 1.2 switches the read cipher on the peer's change_cipher_spec (RFC 5246 7.1), so the
    // read epoch is armed to activate then rather than immediately
    FRecordControl.ArmReadKeysOnChangeCipherSpec(AEffect.Keys, AEffect.Aead);
end;

procedure THandshakeDriver.Apply(const AEffect: THandshakeEffect);
begin
  case AEffect.Kind of
    THandshakeEffectKind.SendHandshake:
      FChannel.SendHandshake(AEffect.Bytes);
    THandshakeEffectKind.SendChangeCipherSpec, THandshakeEffectKind.SetRecordSizeLimit,
    THandshakeEffectKind.SkipEarlyData, THandshakeEffectKind.SetEarlyDataLimit,
    THandshakeEffectKind.RevertWriteToPlaintext, THandshakeEffectKind.SetEarlyReadEpoch:
      ApplyRecordControl(AEffect);
    THandshakeEffectKind.InstallKeys:
      ApplyInstallKeys(AEffect);
    THandshakeEffectKind.NegotiatedVersion:
      if FVersionSink <> nil then
        FVersionSink.OnVersionNegotiated(AEffect.Version);
    THandshakeEffectKind.SelectAlpn:
      FSink.OnAlpnSelected(AEffect.Bytes);
    THandshakeEffectKind.PeerOcspStaple:
      FSink.OnOcspStapleReceived(AEffect.Bytes);
    THandshakeEffectKind.RaiseEvent:
      FSink.OnHandshakeEvent(AEffect.Event);
    THandshakeEffectKind.AwaitCertificateVerdict:
      // the machine emits this only when async verdicts were enabled through the config; a
      // sink that cannot carry the park would leave the handshake parked with nothing able to
      // resume it, so it fails closed instead of wedging
      if FVerdictSink <> nil then
        FVerdictSink.OnCertificateVerdictNeeded(AEffect.Chain, AEffect.ValidatedPath,
          AEffect.HostName, AEffect.Staple, AEffect.RevocationPosture)
      else
        FSink.OnHandshakeFailed(TTlsAlertDescription.InternalError, SVerdictUndeliverable);
    THandshakeEffectKind.PeerCertificateChain:
      if FConnectionInfoSink <> nil then
        FConnectionInfoSink.OnPeerCertificateChain(AEffect.Chain, AEffect.ValidatedPath);
    THandshakeEffectKind.RequestedCertificateAuthorities:
      if FConnectionInfoSink <> nil then
        FConnectionInfoSink.OnRequestedCertificateAuthorities(AEffect.Authorities,
          AEffect.Schemes);
    THandshakeEffectKind.PskIdentity:
      if FConnectionInfoSink <> nil then
        FConnectionInfoSink.OnPskIdentity(AEffect.Identity);
    THandshakeEffectKind.ConnectionParams:
      if FConnectionInfoSink <> nil then
        FConnectionInfoSink.OnConnectionParams(AEffect.CipherSuite,
          AEffect.NamedGroup, AEffect.Resumed, AEffect.ExtendedMasterSecret,
          AEffect.ServerName, AEffect.Facts);
    THandshakeEffectKind.HandshakeEstablished:
      FSink.OnHandshakeEstablished;
    THandshakeEffectKind.EchAccepted:
      if FEchStatusSink <> nil then
        FEchStatusSink.OnEchAccepted;
    THandshakeEffectKind.EchGreased:
      if FEchStatusSink <> nil then
        FEchStatusSink.OnEchGreased;
    THandshakeEffectKind.EchBackend:
      if FEchStatusSink <> nil then
        FEchStatusSink.OnEchBackend;
    THandshakeEffectKind.EchServerRejected:
      if FEchStatusSink <> nil then
        FEchStatusSink.OnEchServerRejected;
    THandshakeEffectKind.EchRejected:
      if FEchStatusSink <> nil then
        FEchStatusSink.OnEchRejected(AEffect.RetryConfigs, AEffect.IsRetry)
      else
        FSink.OnHandshakeFailed(TTlsAlertDescription.EchRequired, SEchRejected);
    THandshakeEffectKind.Fail:
    begin
      if (FFailureCauseSink <> nil) and (AEffect.Cause <> TTlsErrorCause.Unspecified) then
        FFailureCauseSink.OnHandshakeFailureCause(AEffect.Cause);
      FSink.OnHandshakeFailed(AEffect.Alert, AEffect.Reason);
    end;
    THandshakeEffectKind.FailWithoutAlert:
      if FLocalFailureSink <> nil then
        FLocalFailureSink.OnHandshakeFailedWithoutAlert(AEffect.Reason)
      else
        FSink.OnHandshakeFailed(TTlsAlertDescription.InternalError, AEffect.Reason);
  end;
end;

procedure THandshakeDriver.ApplyAll(const AEffects: TArray<THandshakeEffect>);
var
  LEffect: THandshakeEffect;
begin
  for LEffect in AEffects do
  begin
    Apply(LEffect);
    if FRecordControlMissing then
      Break;
  end;
end;

end.
