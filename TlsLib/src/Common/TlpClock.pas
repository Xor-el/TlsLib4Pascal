{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpClock;

{$I ..\Include\TlsLib.inc}

interface

uses
  TlpSystemTimeUtilities,
  TlpIClock;

type
  /// <summary>The default <see cref="ITlsClock" />: reads the real system clock.</summary>
  TSystemClock = class sealed(TInterfacedObject, ITlsClock)
  public
    function NowUnixMillis: UInt64;
  end;

  /// <summary>The default <see cref="ITlsMonotonicClock" />: reads the real system source. That is
  /// GetTickCount64 on Windows, CLOCK_BOOTTIME on Linux and Android (CLOCK_MONOTONIC before Linux
  /// 2.6.39) and the OS monotonic clock elsewhere. It counts system suspend on Windows, Linux and
  /// Android from 2.6.39, macOS, iOS and OpenBSD. FreeBSD, DragonFly, NetBSD and Solaris/illumos do
  /// not guarantee it, so a deadline that spans a suspend there can run longer than its nominal
  /// time.</summary>
  TSystemMonotonicClock = class sealed(TInterfacedObject, ITlsMonotonicClock)
  public
    function NowMonotonicMillis: Int64;
  end;

implementation

{ TSystemClock }

function TSystemClock.NowUnixMillis: UInt64;
begin
  Result := UInt64(TSystemTimeUtilities.UtcUnixMs);
end;

{ TSystemMonotonicClock }

function TSystemMonotonicClock.NowMonotonicMillis: Int64;
begin
  Result := TSystemTimeUtilities.MonotonicMs;
end;

end.
