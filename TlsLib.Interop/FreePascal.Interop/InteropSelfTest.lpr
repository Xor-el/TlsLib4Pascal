program InteropSelfTest;

{$MODE DELPHI}{$H+}

// A no-external-deps smoke that drives real TLS handshakes between our own client and server
// engines over a loopback TCP socket (TLS 1.3, hardened 1.2, mutual TLS), then the
// revocation-over-the-wire cells, then the fuzz-watchdog self-test. It proves the socket
// transport + pump + engine composition end to end (the same glue the BoGo shim uses), so CI
// can gate it on every leg without Go or openssl. All logic lives in InteropSelfTestRunner.

uses
  {$IFDEF UNIX}cthreads,{$ENDIF}
  SysUtils,
  InteropSelfTestRunner;

begin
  ExitCode := TInteropSelfTestRunner.Run;
end.
