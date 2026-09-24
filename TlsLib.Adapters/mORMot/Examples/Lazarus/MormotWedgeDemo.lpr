program MormotWedgeDemo;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

{$APPTYPE CONSOLE}

uses
  {$IFDEF UNIX}cthreads,{$ENDIF}
  SysUtils,
  MormotWedgeDemoExample in '..\src\MormotWedgeDemoExample.pas';

begin
  Halt(TMormotWedgeDemoExample.Run);
end.
