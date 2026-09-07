program MormotEchLoopback;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

{$APPTYPE CONSOLE}

uses
  {$IFDEF UNIX}cthreads,{$ENDIF}
  SysUtils,
  MormotEchLoopbackExample in '..\src\MormotEchLoopbackExample.pas';

begin
  Halt(TMormotEchLoopbackExample.Run);
end.
