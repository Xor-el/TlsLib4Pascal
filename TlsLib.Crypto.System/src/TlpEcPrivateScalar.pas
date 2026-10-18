{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpEcPrivateScalar;

{$I ..\..\TlsLib\src\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpCryptoDomainTypes,
  TlpDataEncoding,
  TlpSecureMemory,
  TlpTlsLibExceptions;

type
  /// <summary>The private-key range of the NIST prime curves: a scalar d is a key when
  /// 1 &lt;= d &lt;= n-1 (SEC 1 3.2.1). The range test is constant-time so the secret scalar
  /// does not leak through comparison timing.</summary>
  TEcPrivateScalar = class sealed(TObject)
  public
    /// <summary>The group order n of AAlgorithm, big-endian at the curve's field width (SEC 2
    /// 2.4.2, 2.5.1, 2.6.1). Raises EArgumentTlsLibException for a curve that is not a NIST
    /// prime curve.</summary>
    class function GroupOrder(AAlgorithm: TKeyAgreementAlgorithm): TBytes; static;
    /// <summary>Whether AScalar, big-endian and as wide as AOrder, lies in [1, n-1]; the running
    /// time does not depend on the scalar's value.</summary>
    class function IsInRange(const AScalar, AOrder: TBytes): Boolean; static;
  end;

implementation

resourcestring
  SNotNistCurve = 'key-agreement algorithm %d is not a NIST prime curve';

{ TEcPrivateScalar }

class function TEcPrivateScalar.GroupOrder(AAlgorithm: TKeyAgreementAlgorithm): TBytes;
begin
  case AAlgorithm of
    TKeyAgreementAlgorithm.SECP256R1:
      Result := TDataEncoding.HexDecode(
        'FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551');
    TKeyAgreementAlgorithm.SECP384R1:
      Result := TDataEncoding.HexDecode(
        'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973');
    TKeyAgreementAlgorithm.SECP521R1:
      Result := TDataEncoding.HexDecode(
        '01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409');
  else
    raise EArgumentTlsLibException.CreateResFmt(@SNotNistCurve, [Ord(AAlgorithm)]);
  end;
end;

class function TEcPrivateScalar.IsInRange(const AScalar, AOrder: TBytes): Boolean;
var
  LNonZero, LBelow: Boolean;
begin
  // the width is public; only the value is secret
  if System.Length(AScalar) <> System.Length(AOrder) then
    Exit(False);
  LNonZero := not TSecureMemory.ConstantTimeIsAllZero(AScalar);
  LBelow := TSecureMemory.ConstantTimeCompareLexicographic(AScalar, AOrder) < 0;
  Result := LNonZero and LBelow;
end;

end.
