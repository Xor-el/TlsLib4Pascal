program SystemTrustDemo;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

{$APPTYPE CONSOLE}

uses
  {$IFDEF UNIX}cthreads,{$ENDIF}
  SysUtils,
  SystemTrustExample in 'src\SystemTrustExample.pas';

begin
  if ParamStr(1) = 'os-and-host-roots' then
    Halt(TSystemTrustExample.RunOsAndHostRoots)
  else
    Halt(TSystemTrustExample.Run);
end.
