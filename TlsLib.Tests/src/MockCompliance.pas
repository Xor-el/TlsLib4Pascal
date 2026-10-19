{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit MockCompliance;

{$I ..\..\TlsLib\src\Include\TlsLib.inc}

interface

uses
  TlpComplianceTypes,
  TlpIModuleAttestation;

type
  /// <summary>An <see cref="IModuleAttestation" /> that answers a fixed status and identity, so a
  /// test drives the module verdict on any host. Never for production use.</summary>
  TFakeModuleAttestation = class sealed(TInterfacedObject, IModuleAttestation)
  strict private
  var
    FStatus: TModuleStatus;
    FIdentity: TModuleIdentity;
  public
    constructor Create(AStatus: TModuleStatus; const AIdentity: TModuleIdentity);
    function Identity: TModuleIdentity;
    function Status(AStandard: TModuleStandard): TModuleStatus;
    function Describe: string;
  end;

implementation

{ TFakeModuleAttestation }

constructor TFakeModuleAttestation.Create(AStatus: TModuleStatus;
  const AIdentity: TModuleIdentity);
begin
  inherited Create;
  FStatus := AStatus;
  FIdentity := AIdentity;
end;

function TFakeModuleAttestation.Identity: TModuleIdentity;
begin
  Result := FIdentity;
end;

function TFakeModuleAttestation.Status(AStandard: TModuleStandard): TModuleStatus;
begin
  Result := FStatus;
end;

function TFakeModuleAttestation.Describe: string;
begin
  Result := 'fake module attestation';
end;

end.
