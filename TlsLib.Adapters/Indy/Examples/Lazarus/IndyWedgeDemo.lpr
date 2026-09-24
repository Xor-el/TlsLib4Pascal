program IndyWedgeDemo;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

{$APPTYPE CONSOLE}

uses
  {$IFDEF UNIX}cthreads,{$ENDIF}
  SysUtils,
  IndyWedgeDemoExample in '..\src\IndyWedgeDemoExample.pas';

begin
  Halt(TIndyWedgeDemoExample.Run);
end.
