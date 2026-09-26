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
  SysUtils,
  TlpCryptoDomainTypes;

type
  /// <summary>
  /// An opaque handle to an imported signing private key. It is produced by the
  /// provider from any supported encoding and holds the private key material internally,
  /// wiped on release: no private material and no backend key object cross this surface.
  /// It reports the signature schemes the key can sign with (in the owner's preferred order;
  /// the scheme used for a CertificateVerify is negotiated per handshake against the peer's
  /// offer) and its public key as a SubjectPublicKeyInfo (public data, so a caller can match
  /// the key to a certificate without a signing operation).
  /// </summary>
  ISigningKey = interface(IInterface)
    ['{2F8C7A16-4D3B-4E5A-9C21-7B0E6F14A8D2}']

    /// <summary>The signature schemes this key can sign with, most preferred first.</summary>
    function CapableSchemes: TArray<TSignatureScheme>;

    /// <summary>The canonical DER SubjectPublicKeyInfo of this key's public half, or nil when
    /// the backend cannot export it. The public key is public data; exposing it lets a caller
    /// confirm the key matches a certificate's public key with no private-key operation, and
    /// seeds a raw-public-key credential (RFC 7250) from the key itself.</summary>
    function PublicKeyInfo: TBytes;

    /// <summary>A handle over the same key whose CapableSchemes are narrowed and
    /// reordered to ASchemes (intersected with what the key can actually sign, in the
    /// given order). An empty ASchemes returns the key unchanged. Lets a caller pin the
    /// signing preference without a separate config knob.</summary>
    function WithPreferredSchemes(const ASchemes: TArray<TSignatureScheme>): ISigningKey;
  end;

implementation

end.
