{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpSystemCryptoExceptions;

{$I ..\..\TlsLib\src\Include\TlsLib.inc}

interface

uses
  TlpTlsLibExceptions;

type
  /// <summary>
  /// The system (OS) crypto backend has no implementation for the requested algorithm
  /// on this platform. The composer treats it as a signal to keep the portable facet,
  /// so it never surfaces to an ordinary caller; the portable provider is always the
  /// fallback.
  /// </summary>
  ESystemCryptoUnsupportedTlsLibException = class(EBaseTlsLibException);

  /// <summary>
  /// An OS cryptography API call failed unexpectedly - a backend fault, not a
  /// peer-input error. Fail-closed: it is raised rather than degrading to a weak or
  /// zero result.
  /// </summary>
  ESystemCryptoBackendTlsLibException = class(EBaseTlsLibException);

  /// <summary>
  /// A strict-native requirement failed: one or more algorithms a caller demanded via a
  /// Require assertion are not served by the OS-native backend on this host. Unlike
  /// <see cref="ESystemCryptoUnsupportedTlsLibException" /> (caught by the composer), this
  /// surfaces to the caller as an explicit startup gate.
  /// </summary>
  ESystemCryptoRequirementTlsLibException = class(EBaseTlsLibException);

implementation

end.
