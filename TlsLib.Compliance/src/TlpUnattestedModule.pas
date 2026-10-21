{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpUnattestedModule;

{$I ..\..\TlsLib\src\Include\TlsLib.inc}

interface

uses
  TlpICryptoProvider,
  TlpComplianceTypes,
  TlpIModuleAttestation;

type
  /// <summary>The attestation of a platform with no validated-module table: nothing is attested,
  /// so the status is Unknown and no provider is covered.</summary>
  TUnattestedModule = class sealed(TInterfacedObject, IModuleAttestation)
  public
    function Identity: TModuleIdentity;
    function Status(AStandard: TModuleStandard): TModuleStatus;
    function Describe: string;
    function Covers(const ACrypto: ICryptoProvider): Boolean;
    function Disclosures: TArray<string>;
  end;

implementation

resourcestring
  SNoModuleTable = 'no validated-module table ships for this platform';

{ TUnattestedModule }

function TUnattestedModule.Identity: TModuleIdentity;
begin
  Result := Default(TModuleIdentity);
end;

function TUnattestedModule.Status(AStandard: TModuleStandard): TModuleStatus;
begin
  Result := TModuleStatus.Unknown;
end;

function TUnattestedModule.Describe: string;
begin
  Result := SNoModuleTable;
end;

function TUnattestedModule.Covers(const ACrypto: ICryptoProvider): Boolean;
begin
  // nothing is attested, so no provider is covered
  Result := False;
end;

function TUnattestedModule.Disclosures: TArray<string>;
begin
  Result := nil;
end;

end.
