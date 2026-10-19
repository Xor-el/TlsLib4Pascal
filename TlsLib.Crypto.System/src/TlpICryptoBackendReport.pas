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
  TlpICryptoProvider,
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
    ['{C48329E6-48DE-4B8F-97D6-E9E692291DCA}']
    function RandomBackend: TCryptoBackendEntry;
    function HashBackend(AAlgorithm: THashAlgorithm): TCryptoBackendEntry;
    function HmacBackend(AAlgorithm: THashAlgorithm): TCryptoBackendEntry;
    function HkdfBackend(AAlgorithm: THashAlgorithm): TCryptoBackendEntry;
    function Tls12PrfBackend(AAlgorithm: THashAlgorithm): TCryptoBackendEntry;
    function AeadBackend(AAlgorithm: TAeadAlgorithm): TCryptoBackendEntry;
    function KeyAgreementBackend(AAlgorithm: TKeyAgreementAlgorithm): TCryptoBackendEntry;
    function KemBackend(AAlgorithm: TKemAlgorithm): TCryptoBackendEntry;
    /// <summary>Signing is about keys: the backend that signs with a key of this scheme.</summary>
    function SigningBackend(AScheme: TSignatureScheme): TCryptoBackendEntry;
    /// <summary>The backend of a specific signing key. SigningBackend answers per scheme, but a
    /// key of a native scheme can still sign portable when its import fell back (unusual key
    /// parameters, PKCS#12); this is the honest per-key answer.</summary>
    function SigningKeyBackend(const AKey: ISigningKey): TCryptoBackendEntry;
    /// <summary>Verification is about verifiers: the upper bound for this scheme. A verifier of
    /// a native scheme can still run portable when its public key was not importable by the OS
    /// module; VerifierBackend is the honest per-verifier answer.</summary>
    function VerificationBackend(AScheme: TSignatureScheme): TCryptoBackendEntry;
    /// <summary>The backend of a specific verifier, as SigningKeyBackend is for a key.</summary>
    function VerifierBackend(const AVerifier: ISignatureVerifier): TCryptoBackendEntry;
    /// <summary>The backend of a whole facet. Hpke is whole (Portable when the provider forwards
    /// it); Primitives and Signing are mixed, so use the per-algorithm queries for their detail.</summary>
    function FacetBackend(AFacet: TCryptoFacet): TCryptoBackendEntry;
    /// <summary>A one-line human summary for startup logging (what runs native, what fell back).</summary>
    function Describe: string;
  end;

implementation

end.
