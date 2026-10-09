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
  TlpWindowsDynamicLibrary;
{$ELSE}
  TlpPosixDynamicLibrary;
{$ENDIF}

type
  /// <summary>Resolves platform entry points at runtime instead of linking them statically.</summary>
  TDynamicLibrary = class sealed(TObject)
  public
    /// <summary>Opens the named library. Returns 0 on failure. On Windows it resolves system
    /// libraries only (never the executable's directory). On POSIX an empty name opens the
    /// global symbol namespace - the libraries already linked.</summary>
    class function Open(const AName: string): NativeUInt; static;
    /// <summary>The address of a symbol in an open library; nil when the handle or the symbol
    /// is absent.</summary>
    class function Resolve(AHandle: NativeUInt; const ASymbol: string): Pointer; static;
    /// <summary>Closes an open library; a 0 handle is a no-op.</summary>
    class procedure Close(AHandle: NativeUInt); static;
  end;

implementation

type
{$IFDEF TLSLIB_MSWINDOWS}
  TPlatformDynamicLibrary = TWindowsDynamicLibrary;
{$ELSE}
  TPlatformDynamicLibrary = TPosixDynamicLibrary;
{$ENDIF}

{ TDynamicLibrary }

class function TDynamicLibrary.Open(const AName: string): NativeUInt;
begin
  Result := TPlatformDynamicLibrary.Open(AName);
end;

class function TDynamicLibrary.Resolve(AHandle: NativeUInt;
  const ASymbol: string): Pointer;
begin
  Result := TPlatformDynamicLibrary.Resolve(AHandle, ASymbol);
end;

class procedure TDynamicLibrary.Close(AHandle: NativeUInt);
begin
  TPlatformDynamicLibrary.Close(AHandle);
end;

end.
