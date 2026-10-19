{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpOSModuleAttestation;

{$I ..\..\TlsLib\src\Include\TlsLib.inc}

interface

uses
  TlpComplianceTypes,
  TlpIModuleAttestation
{$IF DEFINED(TLSLIB_MSWINDOWS)}
  , TlpWindowsModuleAttestation
{$IFEND}
  ;

type
  /// <summary>
  /// The attestation of the platform's cryptographic module. Dispatch is compile-time; a platform
  /// with no shipped validated-module table attests nothing, so its status is Unknown and a
  /// strict policy refuses it.
  /// </summary>
  TOSModuleAttestation = class sealed(TObject)
  public
    /// <summary>The attestation of this platform's module; never nil.</summary>
    class function Current: IModuleAttestation; static;
  end;

implementation

{$IF NOT DEFINED(TLSLIB_MSWINDOWS)}

resourcestring
  SNoModuleTable = 'no validated-module table ships for this platform';

type
  /// <summary>The attestation of a platform with no validated-module table.</summary>
  TUnattestedModule = class sealed(TInterfacedObject, IModuleAttestation)
  public
    function Identity: TModuleIdentity;
    function Status(AStandard: TModuleStandard): TModuleStatus;
    function Describe: string;
  end;

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

{$IFEND}

{ TOSModuleAttestation }

class function TOSModuleAttestation.Current: IModuleAttestation;
begin
{$IF DEFINED(TLSLIB_MSWINDOWS)}
  Result := TWindowsModuleAttestation.Create as IModuleAttestation;
{$ELSE}
  Result := TUnattestedModule.Create as IModuleAttestation;
{$IFEND}
end;

end.
