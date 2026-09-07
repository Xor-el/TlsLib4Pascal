program SynapseEchLoopback;

{$APPTYPE CONSOLE}
{$R *.res}

uses
  SysUtils,
  SynapseEchLoopbackExample in '..\src\SynapseEchLoopbackExample.pas';

begin
  Halt(TSynapseEchLoopbackExample.Run);
end.
