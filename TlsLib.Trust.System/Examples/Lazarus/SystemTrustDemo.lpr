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
  if ParamStr(1) = 'host-roots' then
    Halt(TSystemTrustExample.RunHostRoots)
  else
    Halt(TSystemTrustExample.Run);
end.
