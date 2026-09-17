{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpICryptoBackendReport;

{$I ..\..\TlsLib\src\Include\TlsLib.inc}

interface

uses
  TlpCryptoDomainTypes,
  TlpISigningKey,
  TlpSystemCryptoTypes;

type
  /// <summary>
  /// A provider's backend map: for each algorithm and facet, whether it runs on the OS
  /// module or the portable library. Optional and discovered via <c>Supports</c> - a
  /// provider that does not implement it is wholly portable. It is computed once at
  /// provider construction (the native-vs-fallback decision is made then and never per
  /// operation), so it is immutable and safe to read at any time, including from the
  /// config builder at Build.
  /// </summary>
  ICryptoBackendReport = interface(IInterface)
    ['{B1F7B0C4-8E2A-4D53-9C7E-1A6F2D9B4E80}']
    function RandomBackend: TCryptoBackendEntry;
    function HashBackend(AAlgorithm: THashAlgorithm): TCryptoBackendEntry;
    function HmacBackend(AAlgorithm: THashAlgorithm): TCryptoBackendEntry;
    function HkdfBackend(AAlgorithm: THashAlgorithm): TCryptoBackendEntry;
    function Tls12PrfBackend(AAlgorithm: THashAlgorithm): TCryptoBackendEntry;
    function AeadBackend(AAlgorithm: TAeadAlgorithm): TCryptoBackendEntry;
    function KeyAgreementBackend(AAlgorithm: TKeyAgreementAlgorithm): TCryptoBackendEntry;
    function KemBackend(AAlgorithm: TKemAlgorithm): TCryptoBackendEntry;
    function SigningBackend(AScheme: TSignatureScheme): TCryptoBackendEntry;
    /// <summary>The backend of a specific signing key. SigningBackend answers per scheme, but a
    /// key of a native scheme can still sign portable when its import fell back (unusual key
    /// parameters, PKCS#12); this is the honest per-key answer.</summary>
    function SigningKeyBackend(const AKey: ISigningKey): TCryptoBackendEntry;
    /// <summary>The backend of a whole facet. Certificates/PathValidation/Revocation/Hpke
    /// are whole (Portable when the provider forwards them); Primitives and Signing are mixed,
    /// so use the per-algorithm queries for their detail.</summary>
    function FacetBackend(AFacet: TCryptoFacet): TCryptoBackendEntry;
    /// <summary>A one-line human summary for startup logging (what runs native, what fell back).</summary>
    function Describe: string;
  end;

implementation

end.
