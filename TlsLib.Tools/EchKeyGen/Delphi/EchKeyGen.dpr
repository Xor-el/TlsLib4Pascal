program EchKeyGen;

{$APPTYPE CONSOLE}

uses
  SysUtils,
  TlpEchKeyGen in '..\src\TlpEchKeyGen.pas';

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
