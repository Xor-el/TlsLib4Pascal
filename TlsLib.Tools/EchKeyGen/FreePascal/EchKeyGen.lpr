program EchKeyGen;

{$IFDEF FPC}
{$MODE DELPHI}
{$H+}
{$ENDIF}

{$APPTYPE CONSOLE}

uses
  SysUtils,
  TlpEchKeyGen;

begin
  try
    ExitCode := TEchKeyGenerator.RunConsole;
  except
    on E: Exception do
    begin
      WriteLn('error: ', E.Message);
      ExitCode := 4;
    end;
  end;
end.
