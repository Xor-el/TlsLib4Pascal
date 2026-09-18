program TrustDelegateInterop;

{$MODE DELPHI}{$H+}

// One native-trust cell over a loopback: our server presents a supplied certificate chain
// (optionally stapled) and our client verifies it through the portable PKIX verifier or the
// OS trust delegate against the real machine store. The CI runner drives the cells and, for
// the delegate accept path, brackets a machine-store root install. All logic lives in
// TrustDelegateInteropRunner.

uses
  {$IFDEF UNIX}cthreads,{$ENDIF}
  SysUtils,
  TrustDelegateInteropRunner;

begin
  ExitCode := TTrustDelegateInteropRunner.Run;
end.
