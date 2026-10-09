{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpPosixDynamicLibrary;

{$I ..\Include\TlsLib.inc}

interface

{$IF DEFINED(TLSLIB_UNIXLIKE)}

uses
{$IFDEF FPC}
  dl;
{$ELSE}
  Posix.Dlfcn;
{$ENDIF}

type
  /// <summary>Runtime resolution of POSIX shared libraries through dlopen.</summary>
  TPosixDynamicLibrary = class sealed(TObject)
  public
    /// <summary>Opens the named library; an empty name opens the global symbol namespace - the
    /// libraries already linked. Returns 0 on failure.</summary>
    class function Open(const AName: string): NativeUInt; static;
    class function Resolve(AHandle: NativeUInt; const ASymbol: string): Pointer; static;
    class procedure Close(AHandle: NativeUInt); static;
  end;

{$IFEND}

implementation

{$IF DEFINED(TLSLIB_UNIXLIKE)}

{ TPosixDynamicLibrary }

class function TPosixDynamicLibrary.Open(const AName: string): NativeUInt;
var
  LAnsi: AnsiString;
begin
  // an empty name opens the global namespace (dlopen(nil))
  if AName = '' then
    Exit(NativeUInt(dlopen(nil, RTLD_NOW)));
  LAnsi := AnsiString(AName);
  Result := NativeUInt(dlopen(PAnsiChar(LAnsi), RTLD_NOW));
end;

class function TPosixDynamicLibrary.Resolve(AHandle: NativeUInt;
  const ASymbol: string): Pointer;
var
  LAnsi: AnsiString;
begin
  if AHandle = 0 then
    Exit(nil);
  LAnsi := AnsiString(ASymbol);
  Result := dlsym(AHandle, PAnsiChar(LAnsi));
end;

class procedure TPosixDynamicLibrary.Close(AHandle: NativeUInt);
begin
  if AHandle = 0 then
    Exit;
  dlclose(AHandle);
end;

{$IFEND}

end.
