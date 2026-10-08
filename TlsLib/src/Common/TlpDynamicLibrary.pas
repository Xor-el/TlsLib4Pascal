{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpDynamicLibrary;

{$I ..\Include\TlsLib.inc}

interface

uses
{$IFDEF TLSLIB_MSWINDOWS}
  Windows,
  SysUtils;
{$ELSE}
{$IFDEF FPC}
  dl;
{$ELSE}
  Posix.Dlfcn;
{$ENDIF}
{$ENDIF}

type
  /// <summary>Resolves platform entry points at runtime instead of linking them statically.</summary>
  TDynamicLibrary = class sealed(TObject)
  public
    /// <summary>Opens the named library. Returns 0 on failure. On POSIX an empty name opens the
    /// global symbol namespace - the libraries already linked.</summary>
    class function Open(const AName: string): NativeUInt; static;
    /// <summary>The address of a symbol in an open library; nil when the handle or the symbol
    /// is absent.</summary>
    class function Resolve(AHandle: NativeUInt; const ASymbol: string): Pointer; static;
    /// <summary>Closes an open library; a 0 handle is a no-op.</summary>
    class procedure Close(AHandle: NativeUInt); static;
  end;

implementation

{ TDynamicLibrary }

class function TDynamicLibrary.Open(const AName: string): NativeUInt;
var
  LAnsi: AnsiString;
begin
{$IFDEF TLSLIB_MSWINDOWS}
  Result := NativeUInt(SafeLoadLibrary(AName, SEM_FAILCRITICALERRORS));
{$ELSE}
  // an empty name opens the global namespace (dlopen(nil))
  if AName = '' then
    Exit(NativeUInt(dlopen(nil, RTLD_NOW)));
  LAnsi := AnsiString(AName);
  Result := NativeUInt(dlopen(PAnsiChar(LAnsi), RTLD_NOW));
{$ENDIF}
end;

class function TDynamicLibrary.Resolve(AHandle: NativeUInt;
  const ASymbol: string): Pointer;
var
  LAnsi: AnsiString;
begin
  if AHandle = 0 then
    Exit(nil);
  LAnsi := AnsiString(ASymbol);
{$IFDEF TLSLIB_MSWINDOWS}
  Result := GetProcAddress(HMODULE(AHandle), PAnsiChar(LAnsi));
{$ELSE}
  Result := dlsym(AHandle, PAnsiChar(LAnsi));
{$ENDIF}
end;

class procedure TDynamicLibrary.Close(AHandle: NativeUInt);
begin
  if AHandle = 0 then
    Exit;
{$IFDEF TLSLIB_MSWINDOWS}
  FreeLibrary(HMODULE(AHandle));
{$ELSE}
  dlclose(AHandle);
{$ENDIF}
end;

end.
