{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpIKeyExchangePrivateKey;

{$I ..\..\Include\TlsLib.inc}

interface

uses
  TlpCryptoDomainTypes,
  TlpISecretBuffer;

type
  /// <summary>
  /// A key-exchange private key held in a backend's own parsed representation (a scalar, an
  /// EC key parameter, or an opaque OS handle), minted once and reused for every agreement so
  /// the scalar is not re-parsed per operation. Its Usage is fixed at mint - a generated key is
  /// Ephemeral, an adopted (imported) one declares whether it will be reused - so a backend can
  /// select a reuse-hardened scalar-blinding posture for a Static key. Reached only through the
  /// key-agreement / KEM primitives that produced it; a foreign implementation is rejected.
  /// </summary>
  IKeyExchangePrivateKey = interface(IInterface)
    ['{4E8B1D06-9C27-4A5F-B3E1-7D0A6C2F94B8}']
    /// <summary>Whether this key is a fresh single-use scalar (Ephemeral) or a long-lived one
    /// adopted for reuse (Static); fixed when the key is minted.</summary>
    function Usage: TKeyAgreementUsage;
    /// <summary>The raw scalar (the curve's fixed-width serialization) behind this key - the
    /// neutral currency a caller can persist and re-import on either backend. A KEM or hybrid
    /// key has no single raw scalar and raises ENotSupportedTlsLibException.</summary>
    function ExportRaw: ISecretBuffer;
  end;

implementation

end.
