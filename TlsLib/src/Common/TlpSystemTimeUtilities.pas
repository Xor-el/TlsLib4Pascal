{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpSystemTimeUtilities;

{$I ..\Include\TlsLib.inc}

interface

uses
  TlpTlsLibExceptions,
{$IFDEF TLSLIB_MSWINDOWS}
  TlpWindowsSystemTime;
{$ELSE}
  TlpPosixSystemTime;
{$ENDIF}

type
  /// <summary>
  /// The OS's UTC time and elapsed time, read directly from the OS: no time-zone conversion,
  /// and elapsed time that a wall-clock step cannot move. A missing OS source raises rather
  /// than fall back to a weaker one.
  /// </summary>
  TSystemTimeUtilities = class sealed(TObject)
  public
    /// <summary>The current UTC time as Unix epoch milliseconds.</summary>
    class function UtcUnixMs: Int64; static;
    /// <summary>Milliseconds from an arbitrary origin that never decrease and keep counting
    /// through system suspend.</summary>
    class function MonotonicMs: Int64; static;
    /// <summary>The OS primitive behind MonotonicMs; empty when none is available.</summary>
    class function MonotonicSourceName: string; static;
  end;

implementation

type
{$IFDEF TLSLIB_MSWINDOWS}
  TPlatformSystemTime = TWindowsSystemTime;
{$ELSE}
  TPlatformSystemTime = TPosixSystemTime;
{$ENDIF}

resourcestring
  SNoSystemTimeSource = 'the operating system provides no %s clock source';

{ TSystemTimeUtilities }

class function TSystemTimeUtilities.UtcUnixMs: Int64;
begin
  if not TPlatformSystemTime.TryUtcUnixMs(Result) then
    raise EInvalidOperationTlsLibException.CreateResFmt(@SNoSystemTimeSource, ['UTC']);
end;

class function TSystemTimeUtilities.MonotonicMs: Int64;
begin
  if not TPlatformSystemTime.TryMonotonicMs(Result) then
    raise EInvalidOperationTlsLibException.CreateResFmt(@SNoSystemTimeSource, ['monotonic']);
end;

class function TSystemTimeUtilities.MonotonicSourceName: string;
begin
  Result := TPlatformSystemTime.MonotonicSourceName;
end;

end.
