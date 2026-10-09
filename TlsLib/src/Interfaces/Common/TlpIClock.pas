{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpIClock;

{$I ..\..\Include\TlsLib.inc}

interface

type
  /// <summary>
  /// The engine's source of wall-clock time, in Unix epoch milliseconds. Injectable so the
  /// endpoint's time-dependent decisions - a resumption PSK's obfuscated_ticket_age and
  /// ticket-lifetime expiry (RFC 8446 4.2.11 / 4.6.1), a server's 0-RTT anti-replay window,
  /// certificate validity and OCSP/CRL freshness - can be driven by a deterministic test
  /// clock. The default is the real system clock (<see cref="TSystemClock" />).
  /// </summary>
  ITlsClock = interface(IInterface)
    ['{6C2A9E17-5B48-4D31-9F27-0A3E7C5B8D14}']
    /// <summary>The current time as Unix epoch milliseconds.</summary>
    function NowUnixMillis: UInt64;
  end;

  /// <summary>
  /// A source of elapsed time for deadlines: milliseconds from an arbitrary origin that never
  /// decreases, is never stepped by a wall-clock change and keeps counting through system
  /// suspend. Distinct from <see cref="ITlsClock" /> so a calendar time can never be measured as
  /// elapsed time or the reverse. The default is the real system source
  /// (<see cref="TSystemMonotonicClock" />).
  /// </summary>
  ITlsMonotonicClock = interface(IInterface)
    ['{64CC00A9-7DD7-4D98-BB47-3F3333C093D9}']
    /// <summary>Milliseconds since an arbitrary fixed origin.</summary>
    function NowMonotonicMillis: Int64;
  end;

implementation

end.
