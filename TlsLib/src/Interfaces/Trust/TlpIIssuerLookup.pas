{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpIIssuerLookup;

{$I ..\..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpTrustTypes;

type
  /// <summary>
  /// Finds the certificates that carry a given subject name, on demand during a verification, so
  /// a trust source too large or too slow to load up front is read only for the issuers a peer's
  /// chain names. It answers with the certificates it offers as trust anchors and, separately,
  /// the ones it offers as chain material only; the verifier decides which of them it trusts. An
  /// implementation never raises: a certificate it cannot read is left out of the answer.
  /// </summary>
  IIssuerLookup = interface(IInterface)
    ['{B22D7182-332D-4C19-813F-63A7F43EC32B}']
    /// <summary>Names the source the lookup answers from: equal for lookups that answer alike, so a
    /// configuration built over it is shared, and different for another source.</summary>
    function Identity: string;
    /// <summary>The certificates whose subject is ASubjectName (a DER Name).</summary>
    function IssuersNamed(const ASubjectName: TBytes): TLookedUpIssuers;
  end;

implementation

end.
