{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpIModuleAttestation;

{$I ..\..\TlsLib\src\Include\TlsLib.inc}

interface

uses
  TlpComplianceTypes;

type
  /// <summary>What the platform can attest about the cryptographic module in use.</summary>
  IModuleAttestation = interface(IInterface)
    ['{B7B781C5-3E83-4346-826C-452BC38D6741}']
    function Identity: TModuleIdentity;
    function Status(AStandard: TModuleStandard): TModuleStatus;
    function Describe: string;
  end;

implementation

end.
