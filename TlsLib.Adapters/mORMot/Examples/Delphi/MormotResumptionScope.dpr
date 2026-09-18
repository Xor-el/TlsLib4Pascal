program MormotResumptionScope;

{$APPTYPE CONSOLE}
{$R *.res}

uses
  SysUtils,
  MormotResumptionScopeExample in '..\src\MormotResumptionScopeExample.pas';

begin
  Halt(TMormotResumptionScopeExample.Run);
end.
