program MormotAdvancedConfig;

{$APPTYPE CONSOLE}
{$R *.res}

uses
  SysUtils,
  MormotAdvancedConfigExample in '..\src\MormotAdvancedConfigExample.pas';

begin
  Halt(TMormotAdvancedConfigExample.Run);
end.
