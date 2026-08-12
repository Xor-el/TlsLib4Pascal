program IndyAdvancedConfig;

{$APPTYPE CONSOLE}
{$R *.res}

uses
  SysUtils,
  IndyAdvancedConfigExample in '..\src\IndyAdvancedConfigExample.pas';

begin
  Halt(TIndyAdvancedConfigExample.Run);
end.
