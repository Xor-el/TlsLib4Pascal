{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit DynamicLibraryTests;

{$I ..\..\TlsLib\src\Include\TlsLib.inc}

interface

uses
  SysUtils,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  TlpDynamicLibrary,
  TlsLibTestBase;

type
  TTestDynamicLibrary = class(TTlsLibTestCase)
  published
    procedure TestKnownLibraryOpensAndItsSymbolResolves;
    procedure TestMissingSymbolResolvesToNil;
    procedure TestMissingLibraryOpensToZero;
    procedure TestResolveOnAZeroHandleIsNil;
    procedure TestCloseOfAZeroHandleDoesNotRaise;
    procedure TestRepeatedOpenAndCloseIsSafe;
  end;

implementation

const
{$IFDEF TLSLIB_MSWINDOWS}
  KnownLibrary = 'kernel32.dll';
  KnownSymbol = 'GetCurrentProcessId';
  MissingLibrary = 'tlslib-no-such-library.dll';
{$ELSE}
  // an empty name is the global namespace, where libc is already linked
  KnownLibrary = '';
  KnownSymbol = 'getpid';
  MissingLibrary = 'libtlslib-no-such-library.so.0';
{$ENDIF}
  MissingSymbol = 'TlsLibNoSuchSymbol';

procedure TTestDynamicLibrary.TestKnownLibraryOpensAndItsSymbolResolves;
var
  LHandle: NativeUInt;
begin
  LHandle := TDynamicLibrary.Open(KnownLibrary);
  try
    CheckTrue(LHandle <> 0, 'the known library opens');
    CheckTrue(TDynamicLibrary.Resolve(LHandle, KnownSymbol) <> nil, 'its symbol resolves');
  finally
    TDynamicLibrary.Close(LHandle);
  end;
end;

procedure TTestDynamicLibrary.TestMissingSymbolResolvesToNil;
var
  LHandle: NativeUInt;
begin
  LHandle := TDynamicLibrary.Open(KnownLibrary);
  try
    CheckTrue(TDynamicLibrary.Resolve(LHandle, MissingSymbol) = nil,
      'a symbol the library does not export is nil');
  finally
    TDynamicLibrary.Close(LHandle);
  end;
end;

procedure TTestDynamicLibrary.TestMissingLibraryOpensToZero;
begin
  CheckEquals(0, Int64(TDynamicLibrary.Open(MissingLibrary)),
    'a library that does not exist opens to 0');
end;

procedure TTestDynamicLibrary.TestResolveOnAZeroHandleIsNil;
begin
  CheckTrue(TDynamicLibrary.Resolve(0, KnownSymbol) = nil,
    'a 0 handle resolves nothing, even a symbol the loader knows');
end;

procedure TTestDynamicLibrary.TestCloseOfAZeroHandleDoesNotRaise;
var
  LHandle: NativeUInt;
begin
  TDynamicLibrary.Close(0);
  LHandle := TDynamicLibrary.Open(KnownLibrary);
  try
    CheckTrue(LHandle <> 0, 'the loader still opens libraries afterwards');
  finally
    TDynamicLibrary.Close(LHandle);
  end;
end;

procedure TTestDynamicLibrary.TestRepeatedOpenAndCloseIsSafe;
var
  LI: Int32;
  LHandle: NativeUInt;
begin
  for LI := 1 to 3 do
  begin
    LHandle := TDynamicLibrary.Open(KnownLibrary);
    CheckTrue(LHandle <> 0, 'open succeeds on pass ' + IntToStr(LI));
    CheckTrue(TDynamicLibrary.Resolve(LHandle, KnownSymbol) <> nil,
      'the symbol resolves on pass ' + IntToStr(LI));
    TDynamicLibrary.Close(LHandle);
  end;
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestDynamicLibrary);
{$ELSE}
  RegisterTest(TTestDynamicLibrary.Suite);
{$ENDIF FPC}

end.
