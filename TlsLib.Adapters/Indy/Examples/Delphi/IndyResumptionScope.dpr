program IndyResumptionScope;

{$APPTYPE CONSOLE}
{$R *.res}

uses
  SysUtils,
  IndyResumptionScopeExample in '..\src\IndyResumptionScopeExample.pas';

begin
  Halt(TIndyResumptionScopeExample.Run);
end.
