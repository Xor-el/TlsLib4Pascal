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
  TlpIRecordProtection,
  TlpITlsEngine,
  TlpRecordLayer;

type
  /// <summary>Installs record protection straight onto a record layer (test seam): a handshake
  /// driver over this drives a real record layer without a full engine.</summary>
  TRecordLayerInstaller = class(TInterfacedObject, IRecordEpochInstaller)
  strict private
    FLayer: TRecordLayer;
  public
    constructor Create(const ALayer: TRecordLayer);
    procedure InstallReadProtection(const AProtection: IRecordProtection);
    procedure InstallWriteProtection(const AProtection: IRecordProtection);
    procedure ArmReadProtectionOnChangeCipherSpec(const AProtection: IRecordProtection);
    procedure RevertWriteToPlaintext;
    procedure SetRecordSizeLimit(AOutboundLimit, AInboundLimit: Int32);
    procedure SetEarlyDataSkip(AMaxBytes: Int32);
    procedure SetEarlyDataLimit(AMaxBytes: Int32);
    procedure SetEarlyReadEpoch(AActive: Boolean);
  end;

implementation

{ TRecordLayerInstaller }

constructor TRecordLayerInstaller.Create(const ALayer: TRecordLayer);
begin
  inherited Create;
  FLayer := ALayer;
end;

procedure TRecordLayerInstaller.InstallReadProtection(
  const AProtection: IRecordProtection);
begin
  FLayer.SetReadProtection(AProtection);
end;

procedure TRecordLayerInstaller.InstallWriteProtection(
  const AProtection: IRecordProtection);
begin
  FLayer.SetWriteProtection(AProtection);
end;

procedure TRecordLayerInstaller.ArmReadProtectionOnChangeCipherSpec(
  const AProtection: IRecordProtection);
begin
  FLayer.ArmReadProtectionOnChangeCipherSpec(AProtection);
end;

procedure TRecordLayerInstaller.RevertWriteToPlaintext;
begin
  FLayer.RevertWriteToPlaintext;
end;

procedure TRecordLayerInstaller.SetEarlyReadEpoch(AActive: Boolean);
begin
  FLayer.SetEarlyReadAccepted(AActive);
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

end.
