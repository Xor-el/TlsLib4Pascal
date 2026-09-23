{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpSystemTrustExceptions;

{$I ..\..\TlsLib\src\Include\TlsLib.inc}

interface

uses
  TlpTlsLibExceptions;

type
  /// <summary>
  /// The requested system-trust operation cannot be honored on this platform:
  /// harvesting roots where no enumeration API exists (iOS, Android), or delegating to an
  /// OS verifier where none exists (Linux/BSD/Solaris).
  /// Raised when a caller forces a mode the target cannot satisfy.
  /// </summary>
  ESystemTrustUnsupportedTlsLibException = class(EBaseTlsLibException);

  /// <summary>
  /// The OS trust store could not be read or yielded no usable roots. Fail-closed:
  /// never a silent empty-anchor pass and never a silent fallback to bundled data.
  /// </summary>
  ESystemTrustUnavailableTlsLibException = class(EBaseTlsLibException);

implementation

end.
