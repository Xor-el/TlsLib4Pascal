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
  TlpICryptoProvider,
  TlpComplianceTypes;

type
  /// <summary>What the platform can attest about the cryptographic module in use.</summary>
  IModuleAttestation = interface(IInterface)
    ['{859AE40F-D55A-487B-921D-E621A82746EC}']
    function Identity: TModuleIdentity;
    function Status(AStandard: TModuleStandard): TModuleStatus;
    function Describe: string;
    /// <summary>Facts that bound what the attested module covers, which every report of a policy
    /// over this attestation carries as disclosures; none when it has none to give.</summary>
    function Disclosures: TArray<string>;
    /// <summary>Whether ACrypto is the provider this attestation describes, so the attested
    /// module is the one that serves its operations. An attestation that cannot say answers
    /// False.</summary>
    function Covers(const ACrypto: ICryptoProvider): Boolean;
  end;

implementation

end.
