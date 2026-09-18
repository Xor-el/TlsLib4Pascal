program SynapseResumptionScope;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

{$APPTYPE CONSOLE}

uses
  {$IFDEF UNIX}cthreads,{$ENDIF}
  SysUtils,
  SynapseResumptionScopeExample in '..\src\SynapseResumptionScopeExample.pas';

begin
  Halt(TSynapseResumptionScopeExample.Run);
end.
