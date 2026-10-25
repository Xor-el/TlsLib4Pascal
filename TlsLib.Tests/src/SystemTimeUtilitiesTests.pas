{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit SystemTimeUtilitiesTests;

{$I ..\..\TlsLib\src\Include\TlsLib.inc}

interface

uses
  SysUtils,
  DateUtils,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  TlpIClock,
  TlpClock,
  TlpDateTimeUtilities,
  TlpSystemTimeUtilities,
  TlsLibTestBase;

type
  TTestSystemTimeUtilities = class(TTlsLibTestCase)
  published
    procedure TestSourcesResolveAndNameTheExpectedPrimitive;
    procedure TestMonotonicNeverDecreases;
    procedure TestMonotonicAdvancesInStepWithTheWallClock;
    procedure TestUtcMatchesTheRuntimeLibrary;
    procedure TestTheClockWrappersReadTheSameSources;
  end;

implementation

const
  ReadingCount = 10000;
  SpinTargetMs = 200;
  SpinCeilingMs = 3000;
  WallToleranceMs = 100;
  UtcToleranceMs = 2000;
  OriginToleranceMs = 2000;
  // 2001-09-09 in Unix milliseconds: a wall reading is beyond it
  UnixEpochMagnitudeMs = Int64(1000000000000);
{$IF DEFINED(TLSLIB_MSWINDOWS)}
  ExpectedSource = 'GetTickCount64';
{$ELSEIF DEFINED(TLSLIB_LINUX) OR DEFINED(TLSLIB_ANDROID)}
  ExpectedSource = 'CLOCK_BOOTTIME';
{$ELSE}
  ExpectedSource = 'CLOCK_MONOTONIC';
{$IFEND}

procedure TTestSystemTimeUtilities.TestSourcesResolveAndNameTheExpectedPrimitive;
begin
  CheckEquals(ExpectedSource, TSystemTimeUtilities.MonotonicSourceName,
    'the monotonic clock uses the intended OS primitive');
  CheckTrue(TSystemTimeUtilities.MonotonicMs >= 0, 'the monotonic source resolves');
  CheckTrue(TSystemTimeUtilities.UtcUnixMs > UnixEpochMagnitudeMs, 'the UTC source resolves');
end;

procedure TTestSystemTimeUtilities.TestMonotonicNeverDecreases;
var
  LI: Int32;
  LPrevious, LCurrent: Int64;
begin
  LPrevious := TSystemTimeUtilities.MonotonicMs;
  for LI := 1 to ReadingCount do
  begin
    LCurrent := TSystemTimeUtilities.MonotonicMs;
    CheckTrue(LCurrent >= LPrevious, 'reading ' + IntToStr(LI) + ' did not go backwards');
    LPrevious := LCurrent;
  end;
end;

procedure TTestSystemTimeUtilities.TestMonotonicAdvancesInStepWithTheWallClock;
var
  LWallStart, LWallNow, LMonoStart, LMonoDelta, LWallDelta: Int64;
begin
  LWallStart := TSystemTimeUtilities.UtcUnixMs;
  LMonoStart := TSystemTimeUtilities.MonotonicMs;
  // a since-boot reading differs from the wall clock by the time of boot, however long the uptime
  CheckTrue(Abs(LWallStart - LMonoStart) > OriginToleranceMs,
    'the monotonic origin is not the Unix epoch');
  // a bounded spin on the wall clock, so no Sleep is needed
  repeat
    LMonoDelta := TSystemTimeUtilities.MonotonicMs - LMonoStart;
    LWallNow := TSystemTimeUtilities.UtcUnixMs;
  until (LMonoDelta >= SpinTargetMs) or (LWallNow - LWallStart >= SpinCeilingMs);
  LWallDelta := LWallNow - LWallStart;
  CheckTrue(LMonoDelta >= SpinTargetMs, 'the monotonic clock advanced');
  CheckTrue(Abs(LWallDelta - LMonoDelta) <= WallToleranceMs,
    'the monotonic and wall clocks advance by the same amount');
end;

procedure TTestSystemTimeUtilities.TestUtcMatchesTheRuntimeLibrary;
var
  LLocalNow, LFromUtc: TDateTime;
begin
  // UTC to local has one answer in every zone, unlike local to UTC in a repeated DST hour
  LLocalNow := Now;
  LFromUtc := TDateTimeUtilities.UnixMsToDateTime(TSystemTimeUtilities.UtcUnixMs);
{$IFDEF FPC}
  LFromUtc := UniversalTimeToLocal(LFromUtc);
{$ELSE}
  LFromUtc := TTimeZone.Local.ToLocalTime(LFromUtc);
{$ENDIF}
  CheckTrue(MilliSecondsBetween(LFromUtc, LLocalNow) <= UtcToleranceMs,
    'the OS UTC reading, converted to local time, agrees with the runtime library local clock');
end;

procedure TTestSystemTimeUtilities.TestTheClockWrappersReadTheSameSources;
var
  LWall: ITlsClock;
  LMonotonic: ITlsMonotonicClock;
  LBefore, LAfter: Int64;
begin
  LWall := TSystemClock.Create as ITlsClock;
  LMonotonic := TSystemMonotonicClock.Create as ITlsMonotonicClock;
  LBefore := TSystemTimeUtilities.UtcUnixMs;
  CheckTrue((Int64(LWall.NowUnixMillis) >= LBefore) and
    (Int64(LWall.NowUnixMillis) - LBefore <= UtcToleranceMs), 'the wall wrapper reads UtcUnixMs');
  LBefore := TSystemTimeUtilities.MonotonicMs;
  LAfter := LMonotonic.NowMonotonicMillis;
  CheckTrue(LAfter >= LBefore, 'the monotonic wrapper reads MonotonicMs');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestSystemTimeUtilities);
{$ELSE}
  RegisterTest(TTestSystemTimeUtilities.Suite);
{$ENDIF FPC}

end.
