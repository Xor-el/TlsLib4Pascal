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
  TlpNegotiationTypes;

type
  /// <summary>
  /// The minimum-strength floors a peer certificate chain's keys must meet, applied to the
  /// leaf and intermediates (a configured trust anchor is exempt). MinRsaModulusBits sets the
  /// smallest accepted RSA modulus; MaxRsaModulusBits caps it as a verify-cost defence (0 = no
  /// cap); AllowedEcCurves is the accepted ECDSA named-group codes (empty = any curve the
  /// provider recognises); AllowEdDsa admits Ed25519/Ed448 keys. The chain-signature algorithm
  /// check (peer chain signed only with an advertised scheme, and the MD5/SHA-1 rejection RFC
  /// 8446 4.4.2 mandates) is always applied and is not gated by this record.
  /// </summary>
  TCertificateStrengthPolicy = record
    MinRsaModulusBits: Int32;
    MaxRsaModulusBits: Int32;
    AllowedEcCurves: TArray<UInt16>;
    AllowEdDsa: Boolean;
    /// <summary>The default floors, applied by every preset: RSA 2048..8192, the NIST P-curves,
    /// EdDSA admitted.</summary>
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
end;

end.
