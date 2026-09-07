program IndyEchLoopback;

{$APPTYPE CONSOLE}
{$R *.res}

uses
  SysUtils,
  IndyEchLoopbackExample in '..\src\IndyEchLoopbackExample.pas';

begin
  Halt(TIndyEchLoopbackExample.Run);
end.
