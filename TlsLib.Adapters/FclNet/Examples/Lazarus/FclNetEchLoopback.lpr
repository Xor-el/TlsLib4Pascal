program FclNetEchLoopback;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

{$APPTYPE CONSOLE}

uses
  {$IFDEF UNIX}cthreads,{$ENDIF}
  SysUtils,
  FclNetEchLoopbackExample in '..\src\FclNetEchLoopbackExample.pas';

begin
  Halt(TFclNetEchLoopbackExample.Run);
end.
