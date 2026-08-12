program FclNetAdvancedConfig;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

{$APPTYPE CONSOLE}

uses
  {$IFDEF UNIX}cthreads,{$ENDIF}
  SysUtils,
  FclNetAdvancedConfigExample in '..\src\FclNetAdvancedConfigExample.pas';

begin
  Halt(TFclNetAdvancedConfigExample.Run);
end.
