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
  TlpArrayUtilities,
  TlpCryptoDomainTypes,
  TlpPkixDomainTypes,
  TlpNegotiationTypes;

type
  /// <summary>
  /// The minimum-strength floors a peer certificate chain's keys must meet, applied to the
  /// leaf and intermediates (a configured trust anchor is exempt unless AnchorKeyFloors is set,
  /// which holds a trust anchor's key to the same floors). MinRsaModulusBits sets the
  /// smallest accepted RSA modulus; MaxRsaModulusBits caps it as a verify-cost defence (0 = no
  /// cap); AllowedEcCurves is the accepted ECDSA named-group codes (empty = any curve the
  /// provider recognises); AllowEdDsa admits Ed25519/Ed448 keys; AllowedDeprecatedHashes admits
  /// signature hashes the library otherwise refuses. The chain-signature algorithm check (peer
  /// chain signed only with an advertised scheme, and the MD5 (MUST) / SHA-1 (RECOMMENDED)
  /// rejection of RFC 9846 4.5.1.3) is always applied; the only part of it this record loosens is
  /// that admission. AllowedDeprecatedHashes governs the peer's chain only; our own chain is sent
  /// with SHA-1 only when the peer advertised it (RFC 9846 4.5.1.2).
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
    /// <summary>Holds a trust anchor's public key to the same floors as the leaf and
    /// intermediates; the anchor's own self-signature and hash are still not checked (False =
    /// the anchor is exempt). An anchor whose key kind is unknown is refused with
    /// unsupported_certificate; one that does not parse, with bad_certificate. A server's
    /// client-CA anchors are all checked at Build.</summary>
    AnchorKeyFloors: Boolean;
    /// <summary>The default floors, applied by every preset: RSA 2048..8192, the NIST P-curves,
    /// EdDSA admitted, no deprecated hash, trust anchors exempt.</summary>
    class function Defaults: TCertificateStrengthPolicy; static;
    /// <summary>Whether a certificate's subject key is admitted by these floors, the RSA modulus
    /// range, the curve allowlist and the EdDSA flag; an empty AllowedEcCurves admits any curve
    /// the provider recognises (EcNamedGroup 0 = unknown).</summary>
    function AdmitsKey(const AFacts: TCertKeyFacts): Boolean;
    /// <summary>Whether this policy admits nothing AFloor does not: a modulus range inside
    /// AFloor's (a zero cap in AFloor is no cap), a curve list inside AFloor's (an empty list in
    /// AFloor is any curve), EdDSA only where AFloor admits it, anchor key floors wherever AFloor
    /// has them, and deprecated hashes within AFloor's.</summary>
    function IsAtLeastAsStrictAs(const AFloor: TCertificateStrengthPolicy): Boolean;
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
  Result.AnchorKeyFloors := False;
end;

function TCertificateStrengthPolicy.AdmitsKey(const AFacts: TCertKeyFacts): Boolean;
begin
  case AFacts.Kind of
    TSignatureKeyKind.Rsa:
      Result := (AFacts.Bits >= MinRsaModulusBits) and
        ((MaxRsaModulusBits = 0) or (AFacts.Bits <= MaxRsaModulusBits));
    TSignatureKeyKind.Ecdsa:
      if System.Length(AllowedEcCurves) = 0 then
        Result := AFacts.EcNamedGroup <> 0
      else
        Result := TArrayUtilities.Contains<UInt16>(AllowedEcCurves, AFacts.EcNamedGroup);
    TSignatureKeyKind.Ed25519, TSignatureKeyKind.Ed448:
      Result := AllowEdDsa;
  else
    Result := False;
  end;
end;

function TCertificateStrengthPolicy.IsAtLeastAsStrictAs(
  const AFloor: TCertificateStrengthPolicy): Boolean;
var
  LI: Int32;
begin
  Result := (MinRsaModulusBits >= AFloor.MinRsaModulusBits) and
    ((AFloor.MaxRsaModulusBits = 0) or ((MaxRsaModulusBits <> 0) and
    (MaxRsaModulusBits <= AFloor.MaxRsaModulusBits))) and
    (not AllowEdDsa or AFloor.AllowEdDsa) and
    (not AFloor.AnchorKeyFloors or AnchorKeyFloors) and
    (AllowedDeprecatedHashes <= AFloor.AllowedDeprecatedHashes);
  if Result and (System.Length(AFloor.AllowedEcCurves) > 0) then
  begin
    Result := System.Length(AllowedEcCurves) > 0;
    for LI := 0 to System.Length(AllowedEcCurves) - 1 do
      if not (TArrayUtilities.Contains<UInt16>(AFloor.AllowedEcCurves, AllowedEcCurves[LI])) then
        Exit(False);
  end;
end;

end.
