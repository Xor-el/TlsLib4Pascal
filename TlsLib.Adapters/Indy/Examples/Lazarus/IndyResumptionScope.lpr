program IndyResumptionScope;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

{$APPTYPE CONSOLE}

uses
  {$IFDEF UNIX}cthreads,{$ENDIF}
  SysUtils,
  IndyResumptionScopeExample in '..\src\IndyResumptionScopeExample.pas';

begin
  Halt(TIndyResumptionScopeExample.Run);
end.
