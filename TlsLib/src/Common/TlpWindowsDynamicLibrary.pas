{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpWindowsDynamicLibrary;

{$I ..\Include\TlsLib.inc}

interface

{$IFDEF TLSLIB_MSWINDOWS}

uses
  Windows;

type
  /// <summary>Runtime resolution of Windows system libraries.</summary>
  TWindowsDynamicLibrary = class sealed(TObject)
  public
    /// <summary>Opens a system library by name; never searches the executable's directory.
    /// Returns 0 on failure.</summary>
    class function Open(const AName: string): NativeUInt; static;
    class function Resolve(AHandle: NativeUInt; const ASymbol: string): Pointer; static;
    class procedure Close(AHandle: NativeUInt); static;
  end;

{$ENDIF}

implementation

{$IFDEF TLSLIB_MSWINDOWS}

const
  LOAD_LIBRARY_SEARCH_SYSTEM32 = $00000800;
  LOAD_WITH_ALTERED_SEARCH_PATH = $00000008;

{ TWindowsDynamicLibrary }

class function TWindowsDynamicLibrary.Open(const AName: string): NativeUInt;
var
  LMode: UINT;
  LDir: string;
  LLen: UINT;
{$IF DEFINED(TLSLIB_I386) OR DEFINED(TLSLIB_X86_64)}
  LX87, LMxcsr: Cardinal;
{$IFEND}
begin
  // a bare-name load would search the executable's directory first, where a planted library
  // could stand in for the OS trust or crypto API
  LMode := SetErrorMode(SEM_FAILCRITICALERRORS);
{$IF DEFINED(TLSLIB_I386) OR DEFINED(TLSLIB_X86_64)}
  // a library's initialisation can change the floating-point state; keep the caller's
  LX87 := Get8087CW;
  LMxcsr := GetMXCSR;
{$IFEND}
  try
    Result := NativeUInt(LoadLibraryEx(PChar(AName), 0, LOAD_LIBRARY_SEARCH_SYSTEM32));
    // a system without the search-flag update rejects the flag: load by full system path
    // instead, with the dependency search starting in that directory
    if (Result = 0) and (GetLastError = ERROR_INVALID_PARAMETER) then
    begin
      LDir := '';
      SetLength(LDir, MAX_PATH);
      LLen := GetSystemDirectory(PChar(LDir), MAX_PATH);
      if (LLen > 0) and (LLen < MAX_PATH) then
      begin
        SetLength(LDir, LLen);
        Result := NativeUInt(LoadLibraryEx(PChar(LDir + '\' + AName), 0,
          LOAD_WITH_ALTERED_SEARCH_PATH));
      end;
    end;
  finally
{$IF DEFINED(TLSLIB_I386) OR DEFINED(TLSLIB_X86_64)}
    Set8087CW(LX87);
    SetMXCSR(LMxcsr);
{$IFEND}
    SetErrorMode(LMode);
  end;
end;

class function TWindowsDynamicLibrary.Resolve(AHandle: NativeUInt;
  const ASymbol: string): Pointer;
var
  LAnsi: AnsiString;
begin
  if AHandle = 0 then
    Exit(nil);
  LAnsi := AnsiString(ASymbol);
  Result := GetProcAddress(HMODULE(AHandle), PAnsiChar(LAnsi));
end;

class procedure TWindowsDynamicLibrary.Close(AHandle: NativeUInt);
begin
  if AHandle = 0 then
    Exit;
  FreeLibrary(HMODULE(AHandle));
end;

{$ENDIF}

end.
