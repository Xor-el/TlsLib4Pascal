program SynapseAdvancedConfig;

{$APPTYPE CONSOLE}
{$R *.res}

uses
  SysUtils,
  SynapseAdvancedConfigExample in '..\src\SynapseAdvancedConfigExample.pas';

begin
  Halt(TSynapseAdvancedConfigExample.Run);
end.
