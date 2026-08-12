program SynapseAdvancedConfig;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

{$APPTYPE CONSOLE}

uses
  {$IFDEF UNIX}cthreads,{$ENDIF}
  SysUtils,
  SynapseAdvancedConfigExample in '..\src\SynapseAdvancedConfigExample.pas';

begin
  Halt(TSynapseAdvancedConfigExample.Run);
end.
