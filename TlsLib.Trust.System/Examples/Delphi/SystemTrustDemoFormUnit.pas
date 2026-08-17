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
/// A live proof that TlsLib4Pascal verifies a server chain against the host OS trust
/// store with no manual trust config: an unmodified Indy TIdHTTP does a live HTTPS GET
/// with SSLOptions.UseSystemTrust - no pinned root, no anchors. The OS renders the
/// verdict on every platform (Windows crypt32, macOS/iOS SecTrust, Android
/// X509TrustManager, Unix bundle); nothing platform-specific is wired in this form, so
/// it doubles as the seed of a single cross-platform system-trust demo.
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
    /// <summary>One live GET over the OS system trust store. Returns a human line;
    /// runs off the UI thread (mobile platforms forbid network on the UI thread).</summary>
    function RunSystemTrustGet(const AUrl: string): string;
  public
  end;

var
  SystemTrustDemoForm: TSystemTrustDemoForm;

implementation

{$R *.fmx}

uses
  IdHTTP,
  IdStack,
  TlpTlsStreamPump,
  TlpIndyTls;

const
  TimeoutMs = 15000;
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

function TSystemTrustDemoForm.RunSystemTrustGet(const AUrl: string): string;
var
  LHttp: TIdHTTP;
  LIO: TTlsLibIOHandlerSocket;
  LBody: string;
begin
  LHttp := TIdHTTP.Create(nil);
  try
    LIO := TTlsLibIOHandlerSocket.Create(LHttp);
    // Trust the OS store only - no RootCertFile, no CustomTrustStore. The platform
    // X509TrustManager renders the verdict over JNI.
    LIO.SSLOptions.UseSystemTrust := True;
    LHttp.IOHandler := LIO;
    LHttp.HandleRedirects := True;
    LHttp.ConnectTimeout := TimeoutMs;
    LHttp.ReadTimeout := TimeoutMs;
    LHttp.Request.UserAgent := 'TlsLib4Pascal-SystemTrust';
    try
      LBody := LHttp.Get(AUrl);
      Result := Format('PASS: %d bytes over OS-verified TLS (status %d)',
        [Length(LBody), LHttp.ResponseCode]);
    except
      on E: EIdSocketError do
        Result := 'SKIP: network unreachable (' + E.Message + ')';
      on E: ETlsStreamError do
        if E.HasAlert then
          Result := Format('FAIL: TLS alert %d - %s', [Ord(E.Alert), E.Message])
        else
          Result := 'FAIL: ' + E.Message;
      on E: Exception do
        Result := Format('FAIL: %s: %s', [E.ClassName, E.Message]);
    end;
  finally
    LHttp.Free;
  end;
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
    var
      LResult: string;
    begin
      LResult := RunSystemTrustGet(LUrl);
      TThread.Queue(nil,
        procedure
        begin
          AppendLog(LResult);
          SetBusy(False);
        end);
    end);
end;

end.
