program SystemTrustDemo;

{ FMX host proving TlsLib4Pascal delegates certificate verification to the Android
  platform trust engine over JNI. Source-links the core, the opt-in Trust.System
  package and the Indy adapter so a stale installed .dcp is never in play.
  This is a live-device / network-gated demo, not part of any automated gate. }

uses
  System.StartUpCopy,
  FMX.Forms,
  SystemTrustDemoRunner in 'SystemTrustDemoRunner.pas',
  SystemTrustDemoFormUnit in 'SystemTrustDemoFormUnit.pas' {SystemTrustDemoForm};

{$R *.res}

begin
  Application.Initialize;
  Application.CreateForm(TSystemTrustDemoForm, SystemTrustDemoForm);
  Application.Run;
end.
