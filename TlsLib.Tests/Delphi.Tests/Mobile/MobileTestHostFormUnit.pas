{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit MobileTestHostFormUnit;

interface

uses
  System.SysUtils, System.Types, System.UITypes, System.Classes, System.Variants,
  System.IOUtils,
  FMX.Types, FMX.Controls, FMX.Forms, FMX.Graphics, FMX.Dialogs, FMX.StdCtrls,
  FMX.Controls.Presentation, FMX.Edit, FMX.Memo.Types, FMX.ScrollBox, FMX.Memo,
  TlsLibTestResourceLoader, MobileTestRunner;

type
  TMobileTestHostForm = class(TForm)
    lblBaseUrl: TLabel;
    edtBaseUrl: TEdit;
    btnSaveUrl: TButton;
    lblConnection: TLabel;
    btnRunTests: TButton;
    memLog: TMemo;
    procedure FormShow(Sender: TObject);
    procedure FormActivate(Sender: TObject);
    procedure edtBaseUrlChange(Sender: TObject);
    procedure btnSaveUrlClick(Sender: TObject);
    procedure btnRunTestsClick(Sender: TObject);
  private
    procedure RefreshDataRootSection;
    procedure AppendLog(const ALine: string);
    procedure UpdateConnectionLabel;
    procedure UpdateActionButtons;
  public
  end;

var
  MobileTestHostForm: TMobileTestHostForm;

implementation

{$R *.fmx}

procedure TMobileTestHostForm.AppendLog(const ALine: string);
begin
  if ALine <> '' then
    memLog.Lines.Add(ALine);
end;

procedure TMobileTestHostForm.UpdateConnectionLabel;
var
  LUrl: string;
begin
  LUrl := Trim(edtBaseUrl.Text);
  if not ProbeTestInsightServer(LUrl) then
    lblConnection.Text := 'IDE: enter TestInsight BaseUrl'
  else
    lblConnection.Text := 'IDE: URL set (open TestInsight Explorer)';
end;

procedure TMobileTestHostForm.UpdateActionButtons;
var
  LUrlOk: Boolean;
begin
  LUrlOk := ProbeTestInsightServer(edtBaseUrl.Text);
  btnSaveUrl.Enabled := LUrlOk;
  btnRunTests.Enabled := LUrlOk and not MobileTestsRunning;
end;

procedure TMobileTestHostForm.edtBaseUrlChange(Sender: TObject);
begin
  UpdateConnectionLabel;
  UpdateActionButtons;
end;

procedure TMobileTestHostForm.RefreshDataRootSection;
begin
  memLog.Lines.BeginUpdate;
  try
    memLog.Lines.Clear;
    memLog.Lines.Add('=== Test data ===');
    try
      memLog.Lines.Add('Data root: ' + TTlsLibTestResourceLoader.DataRoot);
      memLog.Lines.Add('file count: ' + IntToStr(Length(TDirectory.GetFiles(
        TTlsLibTestResourceLoader.DataRoot, '*', TSearchOption.soAllDirectories))));
    except
      // a missing data root must not stop the host from starting; the tests report it
      on E: Exception do
        memLog.Lines.Add('Data root not found: ' + E.Message);
    end;
    memLog.Lines.Add('');
    memLog.Lines.Add('=== Test log ===');
  finally
    memLog.Lines.EndUpdate;
  end;
end;

procedure TMobileTestHostForm.FormShow(Sender: TObject);
begin
  edtBaseUrl.Text := LoadTestInsightBaseUrl;
  UpdateConnectionLabel;
  UpdateActionButtons;
  RefreshDataRootSection;
end;

procedure TMobileTestHostForm.FormActivate(Sender: TObject);
begin
  RefreshDataRootSection;
end;

procedure TMobileTestHostForm.btnSaveUrlClick(Sender: TObject);
begin
  SaveTestInsightBaseUrl(edtBaseUrl.Text);
  UpdateConnectionLabel;
  AppendLog('Saved TestInsight BaseUrl.');
end;

procedure TMobileTestHostForm.btnRunTestsClick(Sender: TObject);
begin
  if MobileTestsRunning then
    Exit;

  SaveTestInsightBaseUrl(edtBaseUrl.Text);
  UpdateConnectionLabel;
  AppendLog('Running tests (TestInsight remote)...');

  RunMobileTestsAsync(edtBaseUrl.Text,
    procedure(const AMessage: string)
    begin
      AppendLog(AMessage);
    end,
    procedure
    begin
      UpdateActionButtons;
      AppendLog('Tests finished.');
    end);
  UpdateActionButtons;
end;

end.
