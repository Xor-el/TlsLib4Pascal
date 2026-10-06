{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpCertificateStrengthPolicy;

{$I ..\Include\TlsLib.inc}

interface

uses
  TlpPkixDomainTypes,
  TlpNegotiationTypes;

type
  /// <summary>
  /// The minimum-strength floors a peer certificate chain's keys must meet, applied to the
  /// leaf and intermediates (a configured trust anchor is exempt). MinRsaModulusBits sets the
  /// smallest accepted RSA modulus; MaxRsaModulusBits caps it as a verify-cost defence (0 = no
  /// cap); AllowedEcCurves is the accepted ECDSA named-group codes (empty = any curve the
  /// provider recognises); AllowEdDsa admits Ed25519/Ed448 keys; AllowedDeprecatedHashes admits
  /// signature hashes the library otherwise refuses. The chain-signature algorithm check (peer
  /// chain signed only with an advertised scheme, and the MD5 (MUST) / SHA-1 (RECOMMENDED)
  /// rejection of RFC 8446 4.4.2.4) is always applied; the only part of it this record loosens is
  /// that admission.
  /// </summary>
  TCertificateStrengthPolicy = record
    MinRsaModulusBits: Int32;
    MaxRsaModulusBits: Int32;
    AllowedEcCurves: TArray<UInt16>;
    AllowEdDsa: Boolean;
    /// <summary>Deprecated signature hashes still accepted on the leaf and intermediates of a peer
    /// chain, for a private PKI that has not been re-issued (empty = none). An admitted hash stands
    /// in for an advertised scheme, since no scheme names a SHA-1 certificate signature. A
    /// forbidden hash (MD5) is refused regardless; the key floors, PSS parameter checks, and the
    /// fixed floor on OCSP responses, CRLs and responder certificates are unaffected.</summary>
    AllowedDeprecatedHashes: TCertSignatureHashes;
    /// <summary>The default floors, applied by every preset: RSA 2048..8192, the NIST P-curves,
    /// EdDSA admitted, no deprecated hash.</summary>
    class function Defaults: TCertificateStrengthPolicy; static;
  end;

implementation

{ TCertificateStrengthPolicy }

class function TCertificateStrengthPolicy.Defaults: TCertificateStrengthPolicy;
begin
  Result.MinRsaModulusBits := 2048;
  Result.MaxRsaModulusBits := 8192;
  // secp256r1 / secp384r1 / secp521r1 supported-group codes
  Result.AllowedEcCurves := TArray<UInt16>.Create(TNamedGroupCatalog.Secp256r1,
    TNamedGroupCatalog.Secp384r1, TNamedGroupCatalog.Secp521r1);
  Result.AllowEdDsa := True;
  Result.AllowedDeprecatedHashes := [];
end;

end.
