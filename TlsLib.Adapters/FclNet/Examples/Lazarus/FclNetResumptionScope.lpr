program FclNetResumptionScope;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

{$APPTYPE CONSOLE}

uses
  {$IFDEF UNIX}cthreads,{$ENDIF}
  SysUtils,
  FclNetResumptionScopeExample in '..\src\FclNetResumptionScopeExample.pas';

begin
  Halt(TFclNetResumptionScopeExample.Run);
end.
