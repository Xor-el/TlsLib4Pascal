{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpWindowsSystemTime;

{$I ..\Include\TlsLib.inc}

interface

{$IFDEF TLSLIB_MSWINDOWS}

uses
  Windows,
  TlpDynamicLibrary;

type
  /// <summary>The kernel32 time sources, resolved once at unit initialization.</summary>
  TWindowsSystemTime = class sealed(TObject)
  strict private
  type
    TGetTickCount64Func = function: UInt64; stdcall;
    TGetSystemTimeAsFileTimeProc = procedure(out AFileTime: TFileTime); stdcall;
  class var
    FGetTickCount64: TGetTickCount64Func;
    FGetSystemTimeAsFileTime: TGetSystemTimeAsFileTimeProc;
  private
    class procedure ResolveDynamicImports; static;
  public
    class function TryUtcUnixMs(out AMs: Int64): Boolean; static;
    /// <summary>GetTickCount64 counts sleep and hibernation and is never stepped.</summary>
    class function TryMonotonicMs(out AMs: Int64): Boolean; static;
    class function MonotonicSourceName: string; static;
  end;

{$ENDIF}

implementation

{$IFDEF TLSLIB_MSWINDOWS}

const
  KERNEL32_DLL = 'kernel32.dll';
  // FILETIME counts 100 ns ticks from 1601-01-01
  FileTimeTicksPerMs = Int64(10000);
  // 1970-01-01 as milliseconds since 1601-01-01
  UnixEpochFileTimeMs = Int64(11644473600000);

{ TWindowsSystemTime }

class procedure TWindowsSystemTime.ResolveDynamicImports;
var
  LKernel32: NativeUInt;
begin
  // kernel32 is mapped into every process and never unloads, so the handle is not closed
  LKernel32 := TDynamicLibrary.Open(KERNEL32_DLL);
  FGetTickCount64 := TGetTickCount64Func(TDynamicLibrary.Resolve(LKernel32, 'GetTickCount64'));
  FGetSystemTimeAsFileTime := TGetSystemTimeAsFileTimeProc(
    TDynamicLibrary.Resolve(LKernel32, 'GetSystemTimeAsFileTime'));
end;

class function TWindowsSystemTime.TryUtcUnixMs(out AMs: Int64): Boolean;
var
  LFileTime: TFileTime;
begin
  AMs := 0;
  Result := Assigned(FGetSystemTimeAsFileTime);
  if not Result then
    Exit;
  FGetSystemTimeAsFileTime(LFileTime);
  AMs := ((Int64(LFileTime.dwHighDateTime) shl 32) or Int64(LFileTime.dwLowDateTime)) div
    FileTimeTicksPerMs - UnixEpochFileTimeMs;
end;

class function TWindowsSystemTime.TryMonotonicMs(out AMs: Int64): Boolean;
begin
  AMs := 0;
  Result := Assigned(FGetTickCount64);
  if Result then
    AMs := Int64(FGetTickCount64());
end;

class function TWindowsSystemTime.MonotonicSourceName: string;
begin
  if Assigned(FGetTickCount64) then
    Result := 'GetTickCount64'
  else
    Result := '';
end;

initialization
  TWindowsSystemTime.ResolveDynamicImports;

{$ENDIF}

end.
