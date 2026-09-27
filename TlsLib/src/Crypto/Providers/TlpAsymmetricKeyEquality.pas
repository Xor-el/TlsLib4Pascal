{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpAsymmetricKeyEquality;

{$I ..\..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  ClpIAsymmetricKeyParameter,
  ClpIRsaParameters,
  ClpIECParameters,
  ClpIEd25519Parameters,
  ClpIEd448Parameters,
  ClpSubjectPublicKeyInfoFactory,
  TlpArrayUtilities;

type
  /// <summary>Value-based public-key equality across the key families TlsLib uses, so the
  /// credential leaf guard and PKCS#12 leaf selection share one comparison. Provider-internal:
  /// it works on parsed key parameters, agnostic to point compression and named-vs-explicit EC
  /// parameters (a byte compare of the encodings would false-mismatch those).</summary>
  TAsymmetricKeyEquality = class sealed(TObject)
  strict private
    // for a family without a value comparator (X25519/X448, DH, DSA, the PQ families) the
    // canonical DER encoding is injective, so a byte match is a true key match - the tail only
    class function CanonicalMatch(const AKeyA, AKeyB: IAsymmetricKeyParameter): Boolean; static;
  public
    /// <summary>Whether two public keys are equal by value. A key outside the other's family is a
    /// definite mismatch. Both must be public-key parameters.</summary>
    class function PublicKeysEqual(const AKeyA, AKeyB: IAsymmetricKeyParameter): Boolean; static;
  end;

implementation

{ TAsymmetricKeyEquality }

class function TAsymmetricKeyEquality.CanonicalMatch(
  const AKeyA, AKeyB: IAsymmetricKeyParameter): Boolean;
var
  LA, LB: TBytes;
begin
  LA := TSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(AKeyA).GetDerEncoded;
  LB := TSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(AKeyB).GetDerEncoded;
  Result := (System.Length(LA) > 0) and TArrayUtilities.AreEqual(LA, LB);
end;

class function TAsymmetricKeyEquality.PublicKeysEqual(
  const AKeyA, AKeyB: IAsymmetricKeyParameter): Boolean;
var
  LRsaA, LRsaB: IRsaKeyParameters;
  LEcA, LEcB: IECPublicKeyParameters;
  LEd25519A, LEd25519B: IEd25519PublicKeyParameters;
  LEd448A, LEd448B: IEd448PublicKeyParameters;
begin
  if (AKeyA = nil) or (AKeyB = nil) then
    Exit(False);
  if Supports(AKeyA, IRsaKeyParameters, LRsaA) then
    Result := Supports(AKeyB, IRsaKeyParameters, LRsaB) and LRsaA.Equals(LRsaB)
  else if Supports(AKeyA, IECPublicKeyParameters, LEcA) then
    Result := Supports(AKeyB, IECPublicKeyParameters, LEcB) and LEcA.Equals(LEcB)
  else if Supports(AKeyA, IEd25519PublicKeyParameters, LEd25519A) then
    Result := Supports(AKeyB, IEd25519PublicKeyParameters, LEd25519B) and
      LEd25519A.Equals(LEd25519B)
  else if Supports(AKeyA, IEd448PublicKeyParameters, LEd448A) then
    Result := Supports(AKeyB, IEd448PublicKeyParameters, LEd448B) and
      LEd448A.Equals(LEd448B)
  else
    Result := CanonicalMatch(AKeyA, AKeyB);
end;

end.
