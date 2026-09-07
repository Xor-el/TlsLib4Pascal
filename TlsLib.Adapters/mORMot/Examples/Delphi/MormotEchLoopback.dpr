program MormotEchLoopback;

{$APPTYPE CONSOLE}
{$R *.res}

uses
  SysUtils,
  MormotEchLoopbackExample in '..\src\MormotEchLoopbackExample.pas';

begin
  Halt(TMormotEchLoopbackExample.Run);
end.
