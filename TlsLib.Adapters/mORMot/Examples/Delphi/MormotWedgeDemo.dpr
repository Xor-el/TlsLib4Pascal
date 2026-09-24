program MormotWedgeDemo;

{$APPTYPE CONSOLE}
{$R *.res}

uses
  SysUtils,
  MormotWedgeDemoExample in '..\src\MormotWedgeDemoExample.pas';

begin
  Halt(TMormotWedgeDemoExample.Run);
end.
