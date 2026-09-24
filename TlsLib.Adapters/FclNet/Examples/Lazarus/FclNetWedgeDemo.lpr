program FclNetWedgeDemo;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

{$APPTYPE CONSOLE}

uses
  {$IFDEF UNIX}cthreads,{$ENDIF}
  SysUtils,
  FclNetWedgeDemoExample in '..\src\FclNetWedgeDemoExample.pas';

begin
  Halt(TFclNetWedgeDemoExample.Run);
end.
