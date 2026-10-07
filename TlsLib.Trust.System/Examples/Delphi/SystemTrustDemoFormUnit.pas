{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

/// <summary>
/// The form of the system-trust demo: a URL box, a button and a log, delegating the work to
/// SystemTrustDemoRunner. The demo proves TlsLib4Pascal verifies a server chain against the host
/// OS trust store with no manual trust config (a live GET with SSLOptions.UseSystemTrust - no
/// pinned root, no anchors) and checks the OS delegate on the device. The OS renders the verdict
/// on every platform (Windows crypt32, macOS/iOS SecTrust, Android X509TrustManager, Unix
/// bundle); nothing platform-specific is wired in this form, so it doubles as the seed of a
/// single cross-platform system-trust demo.
/// </summary>
unit SystemTrustDemoFormUnit;

interface

uses
  System.SysUtils,
  System.Classes,
  System.Threading,
  FMX.Types,
  FMX.Controls,
  FMX.Forms,
  FMX.StdCtrls,
  FMX.Controls.Presentation,
  FMX.Edit,
  FMX.Memo.Types,
  FMX.ScrollBox,
  FMX.Memo;

type
  TSystemTrustDemoForm = class(TForm)
    lblUrl: TLabel;
    edtUrl: TEdit;
    btnRun: TButton;
    memLog: TMemo;
    procedure FormCreate(Sender: TObject);
    procedure btnRunClick(Sender: TObject);
  private
    procedure AppendLog(const ALine: string);
    procedure SetBusy(ABusy: Boolean);
    /// <summary>Runs the demo off the UI thread (mobile platforms forbid network on it) and hands
    /// its lines to ShowResults on it.</summary>
    procedure RunDemo(const AUrl: string);
    procedure ShowResults(const ALines: TArray<string>);
  public
  end;

var
  SystemTrustDemoForm: TSystemTrustDemoForm;

implementation

{$R *.fmx}

uses
  SystemTrustDemoRunner;

const
  DefaultUrl = 'https://postman-echo.com/get';

procedure TSystemTrustDemoForm.AppendLog(const ALine: string);
begin
  memLog.Lines.Add(ALine);
  memLog.GoToTextEnd;
end;

procedure TSystemTrustDemoForm.SetBusy(ABusy: Boolean);
begin
  btnRun.Enabled := not ABusy;
end;

procedure TSystemTrustDemoForm.FormCreate(Sender: TObject);
begin
  edtUrl.Text := DefaultUrl;
  // No per-platform trust setup here - the OS system trust store decides. (On Android
  // the JVM is resolved on the first verification; FPC/Android builds would call
  // TlsLibAndroidInitTrust once at startup, which is the only platform that needs it.)
  AppendLog('Enter an https:// URL and tap Verify - the OS system trust store decides.');
end;

procedure TSystemTrustDemoForm.RunDemo(const AUrl: string);
var
  LLines: TArray<string>;
begin
  try
    LLines := TSystemTrustDemoRunner.Run(AUrl);
  except
    // a raise must still release the busy button, so it is reported as a line
    on E: Exception do
      LLines := TArray<string>.Create(Format('FAIL: %s: %s', [E.ClassName, E.Message]));
  end;
  TThread.Queue(nil,
    procedure
    begin
      ShowResults(LLines);
    end);
end;

procedure TSystemTrustDemoForm.ShowResults(const ALines: TArray<string>);
var
  LLine: string;
begin
  for LLine in ALines do
    AppendLog(LLine);
  SetBusy(False);
end;

procedure TSystemTrustDemoForm.btnRunClick(Sender: TObject);
var
  LUrl: string;
begin
  LUrl := Trim(edtUrl.Text);
  if LUrl = '' then
    Exit;
  SetBusy(True);
  AppendLog('GET ' + LUrl + ' (UseSystemTrust) ...');
  // Network off the UI thread; report back on it.
  TTask.Run(
    procedure
    begin
      RunDemo(LUrl);
    end);
end;

end.
