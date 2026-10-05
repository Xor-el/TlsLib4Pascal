program TlsLib.BenchmarkConsole;

{$MODE DELPHI}
{$APPTYPE CONSOLE}

// Console runner for the TlsLib benchmarks. Aggregates the TLS-layer benchmarks (the
// handshake-throughput and record-throughput comparisons against OpenSSL) and prints each
// as an ASCII table over the TlsLib benchmark harness (BenchmarkCommon) for timing/format.
// An optional first argument selects one section: "handshake", "throughput" or "trust" (default:
// handshake and throughput; "trust" times the trust-anchor share of certificate verification).

uses
  SysUtils,
  BenchmarkCommon,
  OpenSslBenchSupport,
  TlsHandshakeBenchmark,
  TlsRecordThroughputBenchmark,
  TlsTrustAnchorBenchmark;

procedure ConsoleLog(const AMessage: String);
begin
  WriteLn(AMessage);
end;

var
  LSection: String;

begin
  try
    LSection := LowerCase(ParamStr(1));
    if (LSection <> '') and (LSection <> 'handshake') and (LSection <> 'throughput') and
      (LSection <> 'trust') then
    begin
      WriteLn('usage: TlsLib.BenchmarkConsole [handshake|throughput|trust]');
      ExitCode := 2;
      Exit;
    end;
    if LSection = 'trust' then
    begin
      TTlsTrustAnchorBenchmark.Run(ConsoleLog);
      Exit;
    end;
    // record which OpenSSL produced the reference figures (empty when it did not load)
    if TOpenSslBench.Available then
      ConsoleLog(TOpenSslBench.VersionString);
    ConsoleLog('');
    if LSection <> 'throughput' then
    begin
      TTlsHandshakeBenchmark.Run(ConsoleLog);
      ConsoleLog('');
    end;
    if LSection <> 'handshake' then
    begin
      TTlsRecordThroughputBenchmark.Run(ConsoleLog);
      ConsoleLog('');
    end;
    TBenchmarkReport.WriteRunSummary(ConsoleLog);
  except
    on E: Exception do
    begin
      WriteLn('Benchmark error: ', E.ClassName, ': ', E.Message);
      ExitCode := 1;
    end;
  end;
end.
