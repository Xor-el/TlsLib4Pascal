program SynapseWedgeDemo;

{$APPTYPE CONSOLE}
{$R *.res}

uses
  SysUtils,
  SynapseWedgeDemoExample in '..\src\SynapseWedgeDemoExample.pas';

begin
  Halt(TSynapseWedgeDemoExample.Run);
end.
