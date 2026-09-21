{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit MockSink;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  TlpTlsAlert,
  TlpITlsEngine,
  TlpIHandshakeMachine;

type
  /// <summary>A handshake sink double that records what the driver reports: event count and the
  /// last event, whether the handshake was established, and any failure or warning alert. It also
  /// implements the optional IWarningAlertSink. A test that does not care about the recordings
  /// simply ignores them (it doubles as a silent sink).</summary>
  TMockHandshakeSink = class(TInterfacedObject, IHandshakeSink, IWarningAlertSink)
  strict private
  var
    FEventCount: Int32;
    FLastEvent: TTlsEventKind;
    FEstablished: Boolean;
    FFailed: Boolean;
    FFailedAlert: TTlsAlertDescription;
    FWarned: Boolean;
    FWarnedAlert: TTlsAlertDescription;
  public
    procedure OnHandshakeEvent(AEvent: TTlsEventKind);
    procedure OnAlpnSelected(const AProtocol: string);
    procedure OnOcspStapleReceived(const AStaple: TBytes);
    procedure OnHandshakeEstablished;
    procedure OnHandshakeFailed(AAlert: TTlsAlertDescription);
    procedure OnWarningAlert(AAlert: TTlsAlertDescription);
    property EventCount: Int32 read FEventCount;
    property LastEvent: TTlsEventKind read FLastEvent;
    property Established: Boolean read FEstablished;
    property Failed: Boolean read FFailed;
    property FailedAlert: TTlsAlertDescription read FFailedAlert;
    property Warned: Boolean read FWarned;
    property WarnedAlert: TTlsAlertDescription read FWarnedAlert;
  end;

implementation

{ TMockHandshakeSink }

procedure TMockHandshakeSink.OnHandshakeEvent(AEvent: TTlsEventKind);
begin
  Inc(FEventCount);
  FLastEvent := AEvent;
end;

procedure TMockHandshakeSink.OnAlpnSelected(const AProtocol: string);
begin
end;

procedure TMockHandshakeSink.OnOcspStapleReceived(const AStaple: TBytes);
begin
end;

procedure TMockHandshakeSink.OnHandshakeEstablished;
begin
  FEstablished := True;
end;

procedure TMockHandshakeSink.OnHandshakeFailed(AAlert: TTlsAlertDescription);
begin
  FFailed := True;
  FFailedAlert := AAlert;
end;

procedure TMockHandshakeSink.OnWarningAlert(AAlert: TTlsAlertDescription);
begin
  FWarned := True;
  FWarnedAlert := AAlert;
end;

end.
