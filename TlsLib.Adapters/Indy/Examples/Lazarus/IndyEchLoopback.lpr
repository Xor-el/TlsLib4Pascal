program IndyEchLoopback;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

{$APPTYPE CONSOLE}

uses
  {$IFDEF UNIX}cthreads,{$ENDIF}
  SysUtils,
  IndyEchLoopbackExample in '..\src\IndyEchLoopbackExample.pas';

begin
  Halt(TIndyEchLoopbackExample.Run);
end.
