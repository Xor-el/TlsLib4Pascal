program IndyCustomization;

{$APPTYPE CONSOLE}
{$R *.res}

uses
  SysUtils,
  IndyCustomizationExample in '..\src\IndyCustomizationExample.pas';

begin
  Halt(TIndyCustomizationExample.Run);
end.
