{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpPosixSystemTime;

{$I ..\Include\TlsLib.inc}

interface

{$IF DEFINED(TLSLIB_UNIXLIKE)}

uses
{$IFDEF FPC}
  UnixType,
{$ELSE}
  Posix.Time,
{$ENDIF}
  TlpDynamicLibrary;

type
  /// <summary>The libc clock_gettime time sources, resolved once at unit initialization.</summary>
  TPosixSystemTime = class sealed(TObject)
  strict private
  type
    TClockGetTimeFunc = function(AClockId: Int32; var ATime: timespec): Int32; cdecl;
  class var
    FClockGetTime: TClockGetTimeFunc;
    FMonotonicIndex: Int32;
    class function TryRead(AClockId: Int32; out AMs: Int64): Boolean; static;
  private
    class procedure ResolveDynamicImports; static;
  public
    class function TryUtcUnixMs(out AMs: Int64): Boolean; static;
    class function TryMonotonicMs(out AMs: Int64): Boolean; static;
    class function MonotonicSourceName: string; static;
  end;

{$IFEND}

implementation

{$IF DEFINED(TLSLIB_UNIXLIKE)}

type
  TClockChoice = record
    Id: Int32;
    Name: string;
  end;

const
  // clock ids are kernel ABI, from each OS's <time.h>; the monotonic candidates are tried in
  // order and the first the kernel accepts is kept (CLOCK_BOOTTIME counts suspend, but a
  // pre-2.6.39 Linux kernel refuses it); only CLOCK_BOOTTIME and the Darwin and OpenBSD
  // CLOCK_MONOTONIC are known to count suspend
{$IFDEF TLSLIB_SOLARIS}
  ClockRealtime = 3;
{$ELSE}
  ClockRealtime = 0;
{$ENDIF}
{$IF DEFINED(TLSLIB_MACOS) OR DEFINED(TLSLIB_IOS)}
  MonotonicClocks: array [0 .. 0] of TClockChoice = ((Id: 6; Name: 'CLOCK_MONOTONIC'));
{$ELSEIF DEFINED(TLSLIB_NETBSD) OR DEFINED(TLSLIB_OPENBSD)}
  MonotonicClocks: array [0 .. 0] of TClockChoice = ((Id: 3; Name: 'CLOCK_MONOTONIC'));
{$ELSEIF DEFINED(TLSLIB_FREEBSD) OR DEFINED(TLSLIB_DRAGONFLY) OR DEFINED(TLSLIB_SOLARIS)}
  MonotonicClocks: array [0 .. 0] of TClockChoice = ((Id: 4; Name: 'CLOCK_MONOTONIC'));
{$ELSE}
  MonotonicClocks: array [0 .. 1] of TClockChoice = ((Id: 7; Name: 'CLOCK_BOOTTIME'),
    (Id: 1; Name: 'CLOCK_MONOTONIC'));
{$IFEND}
{$IF DEFINED(TLSLIB_NETBSD) AND DEFINED(CPU64)}
  // the plain name is the 32-bit time_t entry point; a 64-bit CPU uses the current ABI
  ClockGetTimeSymbol = '__clock_gettime50';
{$ELSE}
  ClockGetTimeSymbol = 'clock_gettime';
{$IFEND}

{ TPosixSystemTime }

class procedure TPosixSystemTime.ResolveDynamicImports;
var
  LI: Int32;
  LMs: Int64;
begin
  // the global namespace handle stays open for the process lifetime
  FClockGetTime := TClockGetTimeFunc(TDynamicLibrary.Resolve(TDynamicLibrary.Open(''),
    ClockGetTimeSymbol));
  FMonotonicIndex := -1;
  for LI := Low(MonotonicClocks) to High(MonotonicClocks) do
    if TryRead(MonotonicClocks[LI].Id, LMs) then
    begin
      FMonotonicIndex := LI;
      Exit;
    end;
end;

class function TPosixSystemTime.TryRead(AClockId: Int32; out AMs: Int64): Boolean;
var
  LTime: timespec;
begin
  AMs := 0;
  Result := Assigned(FClockGetTime) and (FClockGetTime(AClockId, LTime) = 0);
  if Result then
    AMs := Int64(LTime.tv_sec) * 1000 + Int64(LTime.tv_nsec) div 1000000;
end;

class function TPosixSystemTime.TryUtcUnixMs(out AMs: Int64): Boolean;
begin
  Result := TryRead(ClockRealtime, AMs);
end;

class function TPosixSystemTime.TryMonotonicMs(out AMs: Int64): Boolean;
begin
  AMs := 0;
  Result := (FMonotonicIndex >= 0) and TryRead(MonotonicClocks[FMonotonicIndex].Id, AMs);
end;

class function TPosixSystemTime.MonotonicSourceName: string;
begin
  if FMonotonicIndex >= 0 then
    Result := MonotonicClocks[FMonotonicIndex].Name
  else
    Result := '';
end;

initialization
  TPosixSystemTime.ResolveDynamicImports;

{$IFEND}

end.
