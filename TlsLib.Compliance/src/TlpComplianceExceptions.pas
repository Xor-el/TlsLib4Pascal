{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpComplianceExceptions;

{$I ..\..\TlsLib\src\Include\TlsLib.inc}

interface

uses
  TlpTlsLibExceptions,
  TlpTlsAlert,
  TlpComplianceTypes;

type
  /// <summary>The platform or configuration falls short of the rules; carries every
  /// finding.</summary>
  EComplianceUnmetTlsLibException = class(EBaseTlsLibException)
  strict private
    FFindings: TArray<TComplianceFinding>;
    function GetFindings: TArray<TComplianceFinding>;
  public
    constructor Create(const AFindings: TArray<TComplianceFinding>);
    /// <summary>A copy of the findings, so the exception stays unchanged.</summary>
    property Findings: TArray<TComplianceFinding> read GetFindings;
  end;

  /// <summary>A refusing provider declined an operation outside the rules or the module; the
  /// handshake ends with internal_error (RFC 9846 6.2).</summary>
  EComplianceRefusedTlsLibException = class(EFatalAlertTlsLibException)
  public
    constructor CreateRes(AResStringRec: PResStringRec); reintroduce; overload;
    constructor CreateResFmt(AResStringRec: PResStringRec;
      const AArgs: array of const); reintroduce; overload;
  end;

implementation

resourcestring
  SComplianceUnmet = 'compliance requirements are not met: %s';

{ EComplianceUnmetTlsLibException }

constructor EComplianceUnmetTlsLibException.Create(
  const AFindings: TArray<TComplianceFinding>);
var
  LI: Int32;
  LText: string;
begin
  LText := '';
  for LI := 0 to System.Length(AFindings) - 1 do
  begin
    if LI > 0 then
      LText := LText + '; ';
    LText := LText + AFindings[LI].Describe;
  end;
  inherited CreateResFmt(@SComplianceUnmet, [LText]);
  FFindings := System.Copy(AFindings);
end;

function EComplianceUnmetTlsLibException.GetFindings: TArray<TComplianceFinding>;
begin
  Result := System.Copy(FFindings);
end;

{ EComplianceRefusedTlsLibException }

constructor EComplianceRefusedTlsLibException.CreateRes(AResStringRec: PResStringRec);
begin
  inherited CreateRes(TTlsAlertDescription.InternalError, AResStringRec);
end;

constructor EComplianceRefusedTlsLibException.CreateResFmt(AResStringRec: PResStringRec;
  const AArgs: array of const);
begin
  inherited CreateResFmt(TTlsAlertDescription.InternalError, AResStringRec, AArgs);
end;

end.
