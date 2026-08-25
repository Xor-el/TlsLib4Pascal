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
  TlpICryptoProvider,
  TlpIRecordProtection,
  TlpRecordProtectionFactory,
  TlpITlsEngine,
  TlpIHandshakeChannel,
  TlpIHandshakeMachine,
  TlpHandshakeEffect;

type
  /// <summary>
  /// Applies the pure state machine's effects to the real world: it frames and
  /// sends handshake messages (and the middlebox CCS) through the channel, turns
  /// an epoch's derived traffic keys into installed record protection (via the
  /// factory into the P1 record layer), and reports events, completion, cert
  /// verdicts, and failures to the sink. The state machine has already resolved
  /// which traffic secret each install uses; the driver only frames, builds, and
  /// installs.
  /// </summary>
  THandshakeDriver = class sealed(TObject)
  strict private
  var
    FChannel: IHandshakeChannel;
    FInstaller: IRecordEpochInstaller;
    FProvider: ICryptoProvider;
    FSink: IHandshakeSink;
    // resolved once from the sink; nil when the sink does not track the version
    FVersionSink: IHandshakeVersionSink;
    // resolved once from the sink; nil when the sink does not handle async cert verdicts
    FVerdictSink: IHandshakeVerdictSink;
    // resolved once from the sink; nil when the sink does not track connection info
    FConnectionInfoSink: IHandshakeConnectionInfoSink;
    procedure ApplyInstallKeys(const AEffect: THandshakeEffect);
  public
    constructor Create(const AChannel: IHandshakeChannel;
      const AInstaller: IRecordEpochInstaller; const AProvider: ICryptoProvider;
      const ASink: IHandshakeSink);

    procedure Apply(const AEffect: THandshakeEffect);
    procedure ApplyAll(const AEffects: TArray<THandshakeEffect>);
  end;

implementation

{ THandshakeDriver }

constructor THandshakeDriver.Create(const AChannel: IHandshakeChannel;
  const AInstaller: IRecordEpochInstaller; const AProvider: ICryptoProvider;
  const ASink: IHandshakeSink);
begin
  inherited Create;
  FChannel := AChannel;
  FInstaller := AInstaller;
  FProvider := AProvider;
  FSink := ASink;
  if not Supports(ASink, IHandshakeVersionSink, FVersionSink) then
    FVersionSink := nil;
  if not Supports(ASink, IHandshakeVerdictSink, FVerdictSink) then
    FVerdictSink := nil;
  if not Supports(ASink, IHandshakeConnectionInfoSink, FConnectionInfoSink) then
    FConnectionInfoSink := nil;
end;

procedure THandshakeDriver.ApplyInstallKeys(const AEffect: THandshakeEffect);
var
  LProtection: IRecordProtection;
begin
  // the state machine names the negotiated AEAD and version in the effect, so the
  // driver needs no up-front suite (a live client does not know the version or suite
  // until the ServerHello)
  LProtection := TRecordProtectionFactory.Build(AEffect.Version, AEffect.Keys,
    FProvider.Primitives.CreateAead(AEffect.Aead));
  // the negotiated version rides every key install; surface it for connection info
  if FVersionSink <> nil then
    FVersionSink.OnVersionNegotiated(AEffect.Version);
  if AEffect.Side = TRecordSide.ReadSide then
    FInstaller.InstallReadProtection(LProtection)
  else
    FInstaller.InstallWriteProtection(LProtection);
end;

procedure THandshakeDriver.Apply(const AEffect: THandshakeEffect);
begin
  case AEffect.Kind of
    THandshakeEffectKind.SendHandshake:
      FChannel.SendHandshake(AEffect.Bytes);
    THandshakeEffectKind.SendChangeCipherSpec:
      FChannel.SendChangeCipherSpec;
    THandshakeEffectKind.InstallKeys:
      ApplyInstallKeys(AEffect);
    THandshakeEffectKind.SelectAlpn:
      FSink.OnAlpnSelected(AEffect.Text);
    THandshakeEffectKind.PeerOcspStaple:
      FSink.OnOcspStapleReceived(AEffect.Bytes);
    THandshakeEffectKind.SetRecordSizeLimit:
      FInstaller.SetRecordSizeLimit(AEffect.Outbound, AEffect.Inbound);
    THandshakeEffectKind.SkipEarlyData:
      FInstaller.SetEarlyDataSkip(AEffect.Inbound);
    THandshakeEffectKind.SetEarlyDataLimit:
      FInstaller.SetEarlyDataLimit(AEffect.Outbound);
    THandshakeEffectKind.RevertWriteToPlaintext:
      FInstaller.RevertWriteToPlaintext;
    THandshakeEffectKind.SetEarlyReadEpoch:
      FInstaller.SetEarlyReadEpoch(AEffect.Resumed);
    THandshakeEffectKind.RaiseEvent:
      FSink.OnHandshakeEvent(AEffect.Event);
    THandshakeEffectKind.AwaitCertificateVerdict:
      // a sink that does not handle async verdicts never sees this effect, because the
      // machine emits it only when async verdicts were enabled through the config
      if FVerdictSink <> nil then
        FVerdictSink.OnCertificateVerdictNeeded(AEffect.Chain, AEffect.Text);
    THandshakeEffectKind.PeerCertificateChain:
      if FConnectionInfoSink <> nil then
        FConnectionInfoSink.OnPeerCertificateChain(AEffect.Chain);
    THandshakeEffectKind.RequestedCertificateAuthorities:
      if FConnectionInfoSink <> nil then
        FConnectionInfoSink.OnRequestedCertificateAuthorities(AEffect.Chain);
    THandshakeEffectKind.ConnectionParams:
      if FConnectionInfoSink <> nil then
        FConnectionInfoSink.OnConnectionParams(AEffect.CipherSuite,
          AEffect.NamedGroup, AEffect.Resumed, AEffect.ServerName);
    THandshakeEffectKind.HandshakeEstablished:
      FSink.OnHandshakeEstablished;
    THandshakeEffectKind.Fail:
      FSink.OnHandshakeFailed(AEffect.Alert);
  end;
end;

procedure THandshakeDriver.ApplyAll(const AEffects: TArray<THandshakeEffect>);
var
  LEffect: THandshakeEffect;
begin
  for LEffect in AEffects do
    Apply(LEffect);
end;

end.
