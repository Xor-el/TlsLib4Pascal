{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

{$IF FPC_FULLVERSION < 30202}
  {$MESSAGE ERROR 'This Library requires FreePascal 3.2.2 or higher.'}
{$IFEND}

{============================ FPC Version Features ============================}

// Generics.Defaults IEqualityComparer<T> / IComparer<T> used constref through
// FPC 3.2.2; 3.2.3+ switched to const (Delphi compatibility).
{$IF FPC_FULLVERSION < 30203}
  {$DEFINE TLSLIB_FPC_HAS_CONSTREF_GENERIC_COMPARER}
{$IFEND}

{============================== CPU Architecture ==============================}

{$IFDEF FPC_LITTLE_ENDIAN}
  {$DEFINE TLSLIB_LITTLE_ENDIAN}
{$ENDIF}

{$IFDEF FPC_REQUIRES_PROPER_ALIGNMENT}
  {$DEFINE TLSLIB_REQUIRES_PROPER_ALIGNMENT}
{$ENDIF}

{$IFDEF CPU386}
  {$DEFINE TLSLIB_I386}
{$ENDIF}

{$IFDEF CPUX64}
  {$DEFINE TLSLIB_X86_64}
{$ENDIF}

{$IFDEF CPUARM}
  {$DEFINE TLSLIB_ARM32}
{$ENDIF}

{$IFDEF CPUAARCH64}
  {$DEFINE TLSLIB_AARCH64}
{$ENDIF}

{================================= Target OS ==================================}

{$IFDEF MSWINDOWS}
  {$DEFINE TLSLIB_MSWINDOWS}
{$ENDIF}

{$IFDEF UNIX}
  {$DEFINE TLSLIB_UNIX}
{$ENDIF}

{$IFDEF ANDROID}
  {$DEFINE TLSLIB_ANDROID}
  {$UNDEF TLSLIB_UNIX}
{$ENDIF}

{$IFDEF IOS}
  {$DEFINE TLSLIB_IOS}
  {$UNDEF TLSLIB_UNIX}
{$ENDIF}

{$IF DEFINED(DARWIN) AND NOT DEFINED(TLSLIB_IOS)}
  {$DEFINE TLSLIB_MACOS}
  {$UNDEF TLSLIB_UNIX}
{$IFEND}

{$IFDEF FREEBSD}
  {$DEFINE TLSLIB_FREEBSD}
{$ENDIF}

{$IFDEF NETBSD}
  {$DEFINE TLSLIB_NETBSD}
{$ENDIF}

{$IFDEF OPENBSD}
  {$DEFINE TLSLIB_OPENBSD}
{$ENDIF}

{$IFDEF DRAGONFLY}
  {$DEFINE TLSLIB_DRAGONFLY}
{$ENDIF}

{$IF DEFINED(TLSLIB_FREEBSD)
   OR DEFINED(TLSLIB_NETBSD)
   OR DEFINED(TLSLIB_OPENBSD)
   OR DEFINED(TLSLIB_DRAGONFLY)}
  {$DEFINE TLSLIB_BSD}
  {$UNDEF TLSLIB_UNIX}
{$IFEND}

{$IFDEF LINUX}
  {$DEFINE TLSLIB_LINUX}
  {$UNDEF TLSLIB_UNIX}
{$ENDIF}

{$IFDEF SOLARIS}
  {$DEFINE TLSLIB_SOLARIS}
  {$UNDEF TLSLIB_UNIX}
{$ENDIF}

{$IF DEFINED(TLSLIB_ANDROID)
   OR DEFINED(TLSLIB_LINUX)
   OR DEFINED(TLSLIB_IOS)
   OR DEFINED(TLSLIB_MACOS)
   OR DEFINED(TLSLIB_BSD)
   OR DEFINED(TLSLIB_SOLARIS)
   OR DEFINED(TLSLIB_UNIX)}
  {$DEFINE TLSLIB_UNIXLIKE}
{$IFEND}

{$IF NOT DEFINED(TLSLIB_MSWINDOWS)
   AND NOT DEFINED(TLSLIB_ANDROID)
   AND NOT DEFINED(TLSLIB_IOS)
   AND NOT DEFINED(TLSLIB_MACOS)
   AND NOT DEFINED(TLSLIB_BSD)
   AND NOT DEFINED(TLSLIB_LINUX)
   AND NOT DEFINED(TLSLIB_SOLARIS)
   AND NOT DEFINED(TLSLIB_UNIX)}
  {$MESSAGE ERROR 'UNSUPPORTED TARGET.'}
{$IFEND}

{======================= Compiler Mode & Optimizations ========================}

{$MODE DELPHI}
{$MACRO ON}
{$NOTES OFF}
