program MormotAdvancedConfig;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

{$APPTYPE CONSOLE}

uses
  {$IFDEF UNIX}cthreads,{$ENDIF}
  SysUtils,
  MormotAdvancedConfigExample in '..\src\MormotAdvancedConfigExample.pas';

begin
  Halt(TMormotAdvancedConfigExample.Run);
end.
