{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpTlsError;

{$I ..\Include\TlsLib.inc}

interface

uses
  TlpTlsAlert;

type
  /// <summary>Whether the error is one this side produced (its alert was sent) or one the peer
  /// sent (its alert was received). Unknown is the zero value: no failure recorded yet.</summary>
  TTlsErrorOrigin = (Unknown, Local, Peer);

  /// <summary>
  /// The structured, public-facing error surfaced to callers: the alert that
  /// was (or would be) sent and a human-readable message that must not leak
  /// internal state.
  /// </summary>
  TTlsError = record
  strict private
    FAlert: TTlsAlert;
    FMessage: string;
    FOrigin: TTlsErrorOrigin;
  public
    class function Create(const AAlert: TTlsAlert; const AMessage: string;
      AOrigin: TTlsErrorOrigin = TTlsErrorOrigin.Unknown): TTlsError; static;
    /// <summary>A fatal error carrying the given alert description and message.</summary>
    class function CreateFatal(ADescription: TTlsAlertDescription;
      const AMessage: string;
      AOrigin: TTlsErrorOrigin = TTlsErrorOrigin.Unknown): TTlsError; static;
    property Alert: TTlsAlert read FAlert;
    property Message: string read FMessage;
    property Origin: TTlsErrorOrigin read FOrigin;
  end;

implementation

{ TTlsError }

class function TTlsError.Create(const AAlert: TTlsAlert; const AMessage: string;
  AOrigin: TTlsErrorOrigin): TTlsError;
begin
  Result.FAlert := AAlert;
  Result.FMessage := AMessage;
  Result.FOrigin := AOrigin;
end;

class function TTlsError.CreateFatal(ADescription: TTlsAlertDescription;
  const AMessage: string; AOrigin: TTlsErrorOrigin): TTlsError;
begin
  Result := TTlsError.Create(TTlsAlert.CreateFatal(ADescription), AMessage, AOrigin);
end;

end.
