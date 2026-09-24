program IndyWedgeDemo;

{$APPTYPE CONSOLE}
{$R *.res}

uses
  SysUtils,
  IndyWedgeDemoExample in '..\src\IndyWedgeDemoExample.pas';

begin
  Halt(TIndyWedgeDemoExample.Run);
end.
