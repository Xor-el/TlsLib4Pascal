{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit MockRecordInstaller;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  TlpTlsContentType,
  TlpCryptoDomainTypes,
  TlpISecretBuffer,
  TlpSecretBuffer,
  TlpHkdfLabel,
  TlpICryptoProvider,
  TlpTlsVersion,
  TlpIRecordProtection,
  TlpRecordProtection,
  TlpRecordProtectionFactory,
  TlpIHandshakeMachine,
  TlpIKeySchedule,
  TlpRecordLayer;

type
  /// <summary>Installs the keys it is handed straight onto a record layer (test seam) and offers
  /// no record-only controls, so a driver over it sees an installer without the companion.</summary>
  TRecordLayerKeyInstaller = class(TInterfacedObject, IEpochKeyInstaller)
  strict protected
    FLayer: TRecordLayer;
    FCrypto: ICryptoProvider;
  public
    constructor Create(const ALayer: TRecordLayer; const ACrypto: ICryptoProvider);
    procedure InstallReadSecret(AEpoch: TTlsEpoch; const ASecret: ITrafficSecret);
    procedure InstallWriteSecret(AEpoch: TTlsEpoch; const ASecret: ITrafficSecret);
    procedure InstallWriteKeys(AEpoch: TTlsEpoch; const AKeys: ITrafficKeys;
      AAead: TAeadAlgorithm; const AVersion: TTlsVersion);
  end;

  /// <summary>The key installer plus the record-only controls: a handshake driver over this
  /// drives a real record layer without a full engine.</summary>
  TRecordLayerInstaller = class sealed(TRecordLayerKeyInstaller, IEpochKeyInstaller,
    IRecordLayerControl)
  public
    procedure SendChangeCipherSpec;
    procedure ArmReadKeysOnChangeCipherSpec(const AKeys: ITrafficKeys;
      AAead: TAeadAlgorithm; const AVersion: TTlsVersion);
    procedure RevertWriteToPlaintext;
    procedure SetRecordSizeLimit(AOutboundLimit, AInboundLimit: Int32);
    procedure SetEarlyDataSkip(AMaxBytes: Int32);
    procedure SetEarlyDataLimit(AMaxBytes: Int32);
    procedure SetEarlyReadEpoch(AActive: Boolean; AMaxBytes: Int32);
  end;

  /// <summary>Seals records under a TLS 1.3 client's first application traffic secret from outside
  /// its engine (AES-128-GCM, SHA-256), so a peer can be handed records no engine would send.</summary>
  TTrafficForger = class sealed(TObject)
  strict private
  var
    FCrypto: ICryptoProvider;
    FHkdf: IHkdf;
    FSecret: ISecretBuffer;
  public
    constructor Create(const ACrypto: ICryptoProvider; const ASecret: TBytes);
    /// <summary>One record holding APlaintext, sealed at sequence 0 under the current keys.</summary>
    function Seal(AContentType: TTlsContentType; const APlaintext: TBytes): TBytes;
    /// <summary>Moves to the next generation of keys, as the KeyUpdate just sealed does.</summary>
    procedure Advance;
  end;

implementation

{ TRecordLayerKeyInstaller }

constructor TRecordLayerKeyInstaller.Create(const ALayer: TRecordLayer;
  const ACrypto: ICryptoProvider);
begin
  inherited Create;
  FLayer := ALayer;
  FCrypto := ACrypto;
end;

procedure TRecordLayerKeyInstaller.InstallReadSecret(AEpoch: TTlsEpoch;
  const ASecret: ITrafficSecret);
begin
  FLayer.SetReadProtection(TRecordProtectionFactory.BuildFromSecret(FCrypto, ASecret));
end;

procedure TRecordLayerKeyInstaller.InstallWriteSecret(AEpoch: TTlsEpoch;
  const ASecret: ITrafficSecret);
begin
  // the write epoch is an engine-level write-gate concern; this record-layer seam ignores it
  FLayer.SetWriteProtection(TRecordProtectionFactory.BuildFromSecret(FCrypto, ASecret));
end;

procedure TRecordLayerKeyInstaller.InstallWriteKeys(AEpoch: TTlsEpoch;
  const AKeys: ITrafficKeys; AAead: TAeadAlgorithm; const AVersion: TTlsVersion);
begin
  FLayer.SetWriteProtection(TRecordProtectionFactory.Build(AVersion, AKeys,
    FCrypto.Primitives.CreateAead(AAead)));
end;

{ TRecordLayerInstaller }

procedure TRecordLayerInstaller.SendChangeCipherSpec;
begin
  FLayer.Write(TTlsContentType.ChangeCipherSpec, TBytes.Create(1), 0, 1);
end;

procedure TRecordLayerInstaller.ArmReadKeysOnChangeCipherSpec(const AKeys: ITrafficKeys;
  AAead: TAeadAlgorithm; const AVersion: TTlsVersion);
begin
  FLayer.ArmReadProtectionOnChangeCipherSpec(TRecordProtectionFactory.Build(AVersion, AKeys,
    FCrypto.Primitives.CreateAead(AAead)));
end;

procedure TRecordLayerInstaller.RevertWriteToPlaintext;
begin
  FLayer.RevertWriteToPlaintext;
end;

procedure TRecordLayerInstaller.SetEarlyReadEpoch(AActive: Boolean; AMaxBytes: Int32);
begin
  FLayer.SetEarlyReadAccepted(AActive, AMaxBytes);
end;

procedure TRecordLayerInstaller.SetRecordSizeLimit(AOutboundLimit,
  AInboundLimit: Int32);
begin
  FLayer.SetRecordSizeLimit(AOutboundLimit, AInboundLimit);
end;

procedure TRecordLayerInstaller.SetEarlyDataSkip(AMaxBytes: Int32);
begin
  FLayer.SetEarlyDataSkip(AMaxBytes);
end;

procedure TRecordLayerInstaller.SetEarlyDataLimit(AMaxBytes: Int32);
begin
  // outbound 0-RTT capping is an engine concern; this record-layer seam ignores it
end;

{ TTrafficForger }

constructor TTrafficForger.Create(const ACrypto: ICryptoProvider; const ASecret: TBytes);
begin
  inherited Create;
  FCrypto := ACrypto;
  FHkdf := ACrypto.Primitives.CreateHkdf(THashAlgorithm.SHA_256);
  FSecret := TSecretBuffer.From(ASecret);
end;

function TTrafficForger.Seal(AContentType: TTlsContentType; const APlaintext: TBytes): TBytes;
var
  LProtection: IRecordProtection;
begin
  LProtection := TTls13RecordProtection.Create(
    THkdfLabel.HkdfExpandLabel(FHkdf, FSecret, 'key', nil, 16),
    THkdfLabel.HkdfExpandLabel(FHkdf, FSecret, 'iv', nil, 12),
    FCrypto.Primitives.CreateAead(TAeadAlgorithm.AES_128_GCM));
  Result := LProtection.Protect(AContentType, APlaintext, 0, System.Length(APlaintext));
end;

procedure TTrafficForger.Advance;
begin
  FSecret := THkdfLabel.HkdfExpandLabel(FHkdf, FSecret, 'traffic upd', nil, 32);
end;

end.
