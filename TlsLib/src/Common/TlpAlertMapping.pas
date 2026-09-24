{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpAlertMapping;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpTlsAlert,
  TlpTlsError,
  TlpTlsLibExceptions;

type
  /// <summary>
  /// The single table that turns a raised exception into the alert to send and the
  /// public error to surface. It lives at the engine boundary, not in the alert wire
  /// codec, so the codec never depends on the exception hierarchy. A fatal-alert
  /// exception carries its own description; a peer-input failure is illegal_parameter;
  /// any other failure becomes internal_error, and no message from an unrecognized
  /// exception is passed through (no internal-state leakage).
  /// </summary>
  TAlertMapping = class sealed(TObject)
  public
    /// <summary>The alert to send for a raised exception.</summary>
    class function AlertFor(const AException: Exception): TTlsAlert; static;
    /// <summary>The structured, leak-free error for a raised exception.</summary>
    class function ErrorFor(const AException: Exception): TTlsError; static;
  end;

implementation

resourcestring
  SInternalError = 'internal error';

{ TAlertMapping }

class function TAlertMapping.AlertFor(const AException: Exception): TTlsAlert;
begin
  // a peer-supplied value that failed validation is an illegal_parameter
  if AException is EPeerInputTlsLibException then
    Result := TTlsAlert.CreateFatal(TTlsAlertDescription.IllegalParameter)
  // EDecodeErrorTlsLibException is itself a fatal-alert exception (pinned to
  // decode_error), so this one branch covers decode_error, record_overflow,
  // bad_record_mac, unexpected_message, ... - each carries its own description.
  else if AException is EFatalAlertTlsLibException then
    Result := TTlsAlert.CreateFatal((AException as EFatalAlertTlsLibException).AlertDescription)
  else
    Result := TTlsAlert.CreateFatal(TTlsAlertDescription.InternalError);
end;

class function TAlertMapping.ErrorFor(const AException: Exception): TTlsError;
begin
  // our own exceptions carry a resourcestring message (no secret material); an
  // unrecognized exception is reduced to a generic message so nothing leaks
  if AException is EBaseTlsLibException then
    Result := TTlsError.Create(AlertFor(AException), AException.Message,
      TTlsErrorOrigin.Local)
  else
    Result := TTlsError.Create(AlertFor(AException), SInternalError,
      TTlsErrorOrigin.Local);
end;

end.
