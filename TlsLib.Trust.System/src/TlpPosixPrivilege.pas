{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpPosixPrivilege;

{$I ..\..\TlsLib\src\Include\TlsLib.inc}

interface

{$IF DEFINED(TLSLIB_LINUX) OR DEFINED(TLSLIB_BSD) OR DEFINED(TLSLIB_SOLARIS)}

uses
  TlpPosixDynLib;

type
  // uid_t / gid_t are 32-bit unsigned on every supported target; getauxval takes and returns
  // a machine word, so it must be NativeUInt (not UInt32) to stay correct on LP64.
  TPosixIdFunc = function: UInt32; cdecl;
  TPosixFlagFunc = function: Integer; cdecl;
  TPosixAuxvalFunc = function(AType: NativeUInt): NativeUInt; cdecl;

  /// <summary>
  /// Whether the current process runs with elevated privileges - setuid/setgid, file
  /// capabilities, or the kernel's secure-execution flag - so a caller can decline to
  /// honour an attacker-controllable environment override in that case.
  /// </summary>
  TPosixPrivilege = class sealed(TObject)
  public
    /// <summary>True when the process is privilege-elevated, and - fail-closed - when its
    /// identity cannot be established. Resolves the libc identity entry points at runtime.</summary>
    class function IsElevated: Boolean; static;
  end;

{$IFEND}

implementation

{$IF DEFINED(TLSLIB_LINUX) OR DEFINED(TLSLIB_BSD) OR DEFINED(TLSLIB_SOLARIS)}

{ TPosixPrivilege }

class function TPosixPrivilege.IsElevated: Boolean;
const
  // getauxval selector for the secure-execution flag: the kernel sets it on any privileged
  // exec (setuid/setgid or a binary carrying file capabilities), which a bare euid/uid
  // comparison misses. Fixed at 23 across the Linux/Android ABIs (linux/auxvec.h).
  AT_SECURE = NativeUInt(23);
var
  LHandle: NativeUInt;
  LIssetugid: TPosixFlagFunc;
  LGetauxval: TPosixAuxvalFunc;
  LGeteuid, LGetuid, LGetegid, LGetgid: TPosixIdFunc;
begin
  Result := True;
  LHandle := TPosixDynLib.Open('');
  if LHandle = 0 then
    Exit;
  try
    // strongest signal first: issetugid (BSD/Solaris) stays set across a later privilege drop;
    // then the kernel secure-execution flag; then the euid/egid comparison
    LIssetugid := TPosixFlagFunc(TPosixDynLib.Resolve(LHandle, 'issetugid'));
    if Assigned(LIssetugid) then
    begin
      Result := LIssetugid() <> 0;
      Exit;
    end;
    LGetauxval := TPosixAuxvalFunc(TPosixDynLib.Resolve(LHandle, 'getauxval'));
    if Assigned(LGetauxval) then
    begin
      Result := LGetauxval(AT_SECURE) <> 0;
      Exit;
    end;
    LGeteuid := TPosixIdFunc(TPosixDynLib.Resolve(LHandle, 'geteuid'));
    LGetuid := TPosixIdFunc(TPosixDynLib.Resolve(LHandle, 'getuid'));
    LGetegid := TPosixIdFunc(TPosixDynLib.Resolve(LHandle, 'getegid'));
    LGetgid := TPosixIdFunc(TPosixDynLib.Resolve(LHandle, 'getgid'));
    if Assigned(LGeteuid) and Assigned(LGetuid) and Assigned(LGetegid) and
      Assigned(LGetgid) then
      Result := (LGeteuid() <> LGetuid()) or (LGetegid() <> LGetgid());
  finally
    TPosixDynLib.Close(LHandle);
  end;
end;

{$IFEND}

end.
