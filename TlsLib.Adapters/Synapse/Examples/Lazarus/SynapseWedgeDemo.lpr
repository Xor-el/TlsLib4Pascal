program SynapseWedgeDemo;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

{$APPTYPE CONSOLE}

uses
  {$IFDEF UNIX}cthreads,{$ENDIF}
  SysUtils,
  SynapseWedgeDemoExample in '..\src\SynapseWedgeDemoExample.pas';

begin
  Halt(TSynapseWedgeDemoExample.Run);
end.
