program IndyAdvancedConfig;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

{$APPTYPE CONSOLE}

uses
  {$IFDEF UNIX}cthreads,{$ENDIF}
  SysUtils,
  IndyAdvancedConfigExample in '..\src\IndyAdvancedConfigExample.pas';

begin
  Halt(TIndyAdvancedConfigExample.Run);
end.
