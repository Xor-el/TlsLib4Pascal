program MormotResumptionScope;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

{$APPTYPE CONSOLE}

uses
  {$IFDEF UNIX}cthreads,{$ENDIF}
  SysUtils,
  MormotResumptionScopeExample in '..\src\MormotResumptionScopeExample.pas';

begin
  Halt(TMormotResumptionScopeExample.Run);
end.
