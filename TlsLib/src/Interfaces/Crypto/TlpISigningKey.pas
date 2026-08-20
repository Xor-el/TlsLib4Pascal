{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpISigningKey;

{$I ..\..\Include\TlsLib.inc}

interface

uses
  TlpCryptoAlgorithms;

type
  /// <summary>
  /// An opaque handle to an imported signing private key. It is produced by the
  /// provider from any supported encoding and holds the key material internally,
  /// wiped on release. Its only public surface is the set of signature schemes the
  /// key can sign with, in the key owner's preferred order; the actual scheme used
  /// for a CertificateVerify is negotiated per handshake against the peer's offer.
  /// </summary>
  ISigningKey = interface(IInterface)
    ['{4D9ABED9-0071-475E-8AE8-22FEA55468BD}']

    /// <summary>The signature schemes this key can sign with, most preferred first.</summary>
    function CapableSchemes: TArray<TSignatureScheme>;

    /// <summary>A handle over the same key whose CapableSchemes are narrowed and
    /// reordered to ASchemes (intersected with what the key can actually sign, in the
    /// given order). An empty ASchemes returns the key unchanged. Lets a caller pin the
    /// signing preference without a separate config knob.</summary>
    function WithPreferredSchemes(const ASchemes: TArray<TSignatureScheme>): ISigningKey;
  end;

implementation

end.
