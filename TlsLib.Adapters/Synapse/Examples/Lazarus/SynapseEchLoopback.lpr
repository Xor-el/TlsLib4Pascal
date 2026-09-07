program SynapseEchLoopback;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

{$APPTYPE CONSOLE}

uses
  {$IFDEF UNIX}cthreads,{$ENDIF}
  SysUtils,
  SynapseEchLoopbackExample in '..\src\SynapseEchLoopbackExample.pas';

begin
  Halt(TSynapseEchLoopbackExample.Run);
end.
