{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpSystemCryptoTypes;

{$I ..\..\TlsLib\src\Include\TlsLib.inc}

interface

type
  /// <summary>
  /// Which implementation actually serves a crypto operation, as reported by
  /// <c>ICryptoBackendReport</c> so a caller can see, at startup, exactly what runs on
  /// the OS module versus the portable library - graceful fallback is never silent.
  /// </summary>
  TCryptoBackend = (
    /// <summary>The portable (CryptoLib-backed) implementation.</summary>
    Portable,
    /// <summary>The OS/system module (e.g. Windows CNG).</summary>
    System,
    /// <summary>Assembled in portable code over system primitives - the secret passes
    /// through the module but the construction is not a module service (e.g. HKDF built
    /// over the module's HMAC).</summary>
    Composed);

  /// <summary>Why an operation is not <c>System</c>-backed (meaningful when the backend
  /// is <c>Portable</c>).</summary>
  TCryptoBackendReason = (
    /// <summary>It is system-backed (or composed) - not a fallback.</summary>
    NotFallback,
    /// <summary>The OS module is absent on this host (e.g. no bcrypt.dll).</summary>
    NoModule,
    /// <summary>The module lacks this algorithm on this host/version.</summary>
    NotPresent,
    /// <summary>The provider has no native implementation for it (a forwarded facet, or a
    /// facet/algorithm not yet natively backed).</summary>
    NoNativeImpl);

  /// <summary>The six provider facets, for whole-facet backend reporting.</summary>
  TCryptoFacet = (Primitives, Signing, Certificates, PathValidation, Revocation, Hpke);

  /// <summary>One backend answer: which implementation serves the operation, and - when
  /// it is a portable fallback - why.</summary>
  TCryptoBackendEntry = record
    Backend: TCryptoBackend;
    Reason: TCryptoBackendReason;
  end;

implementation

end.
