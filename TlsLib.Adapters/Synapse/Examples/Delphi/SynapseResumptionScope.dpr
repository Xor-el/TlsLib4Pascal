program SynapseResumptionScope;

{$APPTYPE CONSOLE}
{$R *.res}

uses
  SysUtils,
  SynapseResumptionScopeExample in '..\src\SynapseResumptionScopeExample.pas';

begin
  Halt(TSynapseResumptionScopeExample.Run);
end.
