{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpDateTimeUtilities;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  DateUtils,
  TlpTlsLibExceptions;

type
  /// <summary>
  /// Static date/time helpers: conversions between TDateTime and Unix milliseconds
  /// (range-validated), ticks (100 ns) and fixed-precision rounding.
  /// </summary>
  TDateTimeUtilities = class sealed(TObject)
  strict private
    class var
      FUnixEpoch: TDateTime;
      FMaxUnixMs: Int64;
      FMinUnixMs: Int64;
  public
    /// <summary>
    /// Milliseconds since the Unix epoch (1 Jan 1970 UTC). The exact inverse of
    /// <see cref="UnixMsToDateTime" />: ADateTime is taken as a UTC wall-clock value
    /// and measured directly - no local/UTC guessing (TDateTime carries no kind).
    /// </summary>
    /// <exception cref="EArgumentTlsLibException">ADateTime is before the epoch.</exception>
    class function DateTimeToUnixMs(const ADateTime: TDateTime): Int64; static;
    /// <summary>The UTC wall-clock TDateTime AUnixMs milliseconds after the epoch.</summary>
    /// <exception cref="EArgumentTlsLibException">AUnixMs outside MinUnixMs..MaxUnixMs.</exception>
    class function UnixMsToDateTime(const AUnixMs: Int64): TDateTime; static;
    /// <summary>Ticks (100 ns) since 1 Jan 0001 00:00:00.</summary>
    class function DateTimeToTicks(const ADateTime: TDateTime): Int64; static;
    /// <summary>The TDateTime ATicks (100 ns each) after 1 Jan 0001 00:00:00.</summary>
    class function TicksToDateTime(const ATicks: Int64): TDateTime; static;
    /// <summary>Rounds down to 10 ms (centisecond).</summary>
    class function WithPrecisionCentisecond(const ADateTime: TDateTime): TDateTime; static;
    /// <summary>Rounds down to 100 ms (decisecond).</summary>
    class function WithPrecisionDecisecond(const ADateTime: TDateTime): TDateTime; static;
    /// <summary>Rounds to millisecond.</summary>
    class function WithPrecisionMillisecond(const ADateTime: TDateTime): TDateTime; static;
    /// <summary>Rounds down to the second (fraction discarded).</summary>
    class function WithPrecisionSecond(const ADateTime: TDateTime): TDateTime; static;

    /// <summary>1 Jan 1970 00:00:00 UTC.</summary>
    class property UnixEpoch: TDateTime read FUnixEpoch;
    /// <summary>The maximum representable Unix millisecond value.</summary>
    class property MaxUnixMs: Int64 read FMaxUnixMs;
    /// <summary>The minimum Unix millisecond value (0).</summary>
    class property MinUnixMs: Int64 read FMinUnixMs;

    class constructor Create;
  end;

implementation

resourcestring
  SDateTimeValueMayNotBeBefore = 'DateTime value may not be before the epoch';
  SUnixMsValueOutOfRange = 'UnixMs value out of range';

{ TDateTimeUtilities }

class constructor TDateTimeUtilities.Create;
var
  LMaxDateTime: TDateTime;
  LMaxMs, LUnixEpochMs: Int64;
begin
  // Unix epoch: January 1, 1970 00:00:00 UTC
  FUnixEpoch := EncodeDate(1970, 1, 1);
  FMinUnixMs := 0;
  LMaxDateTime := MaxDateTime;
  LUnixEpochMs := MilliSecondsBetween(FUnixEpoch, 0);
  LMaxMs := MilliSecondsBetween(LMaxDateTime, 0);
  FMaxUnixMs := LMaxMs - LUnixEpochMs;
end;

class function TDateTimeUtilities.DateTimeToUnixMs(const ADateTime: TDateTime): Int64;
begin
  // ADateTime is an unambiguous UTC instant (TDateTime has no kind), measured
  // directly - the exact inverse of UnixMsToDateTime, with no local/UTC heuristic
  if ADateTime < UnixEpoch then
    raise EArgumentTlsLibException.CreateRes(@SDateTimeValueMayNotBeBefore);
  Result := MilliSecondsBetween(ADateTime, UnixEpoch);
end;

class function TDateTimeUtilities.UnixMsToDateTime(const AUnixMs: Int64): TDateTime;
begin
  if (AUnixMs < MinUnixMs) or (AUnixMs > MaxUnixMs) then
    raise EArgumentTlsLibException.CreateRes(@SUnixMsValueOutOfRange);
  Result := IncMilliSecond(UnixEpoch, AUnixMs);
end;

class function TDateTimeUtilities.DateTimeToTicks(const ADateTime: TDateTime): Int64;
var
  LEpoch: TDateTime;
  LMsSinceEpoch: Int64;
begin
  // Epoch: January 1, 0001 00:00:00
  LEpoch := EncodeDateTime(1, 1, 1, 0, 0, 0, 0);
  if ADateTime >= LEpoch then
    LMsSinceEpoch := MilliSecondsBetween(ADateTime, LEpoch)
  else
    LMsSinceEpoch := -MilliSecondsBetween(ADateTime, LEpoch);
  // 1 millisecond = 10,000 ticks
  Result := LMsSinceEpoch * Int64(10000);
end;

class function TDateTimeUtilities.TicksToDateTime(const ATicks: Int64): TDateTime;
var
  LEpoch: TDateTime;
  LMsSinceEpoch: Int64;
begin
  LEpoch := EncodeDateTime(1, 1, 1, 0, 0, 0, 0);
  LMsSinceEpoch := ATicks div Int64(10000);
  Result := IncMilliSecond(LEpoch, LMsSinceEpoch);
end;

class function TDateTimeUtilities.WithPrecisionCentisecond(
  const ADateTime: TDateTime): TDateTime;
var
  LMs: Int64;
begin
  LMs := DateTimeToUnixMs(ADateTime);
  LMs := LMs - (LMs mod 10);
  Result := UnixMsToDateTime(LMs);
end;

class function TDateTimeUtilities.WithPrecisionDecisecond(
  const ADateTime: TDateTime): TDateTime;
var
  LMs: Int64;
begin
  LMs := DateTimeToUnixMs(ADateTime);
  LMs := LMs - (LMs mod 100);
  Result := UnixMsToDateTime(LMs);
end;

class function TDateTimeUtilities.WithPrecisionMillisecond(
  const ADateTime: TDateTime): TDateTime;
begin
  Result := UnixMsToDateTime(DateTimeToUnixMs(ADateTime));
end;

class function TDateTimeUtilities.WithPrecisionSecond(
  const ADateTime: TDateTime): TDateTime;
var
  LYear, LMonth, LDay, LHour, LMinute, LSecond, LMillisecond: Word;
begin
  DecodeDateTime(ADateTime, LYear, LMonth, LDay, LHour, LMinute, LSecond,
    LMillisecond);
  Result := EncodeDateTime(LYear, LMonth, LDay, LHour, LMinute, LSecond, 0);
end;

end.
