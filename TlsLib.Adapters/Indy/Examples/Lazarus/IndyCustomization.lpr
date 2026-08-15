program IndyCustomization;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

{$APPTYPE CONSOLE}

uses
  {$IFDEF UNIX}cthreads,{$ENDIF}
  SysUtils,
  IndyCustomizationExample in '..\src\IndyCustomizationExample.pas';

begin
  Halt(TIndyCustomizationExample.Run);
end.
