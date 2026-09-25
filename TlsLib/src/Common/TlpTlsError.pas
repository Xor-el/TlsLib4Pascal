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
    FAlertByte: Byte;
  public
    class function Create(const AAlert: TTlsAlert; const AMessage: string;
      AOrigin: TTlsErrorOrigin = TTlsErrorOrigin.Unknown): TTlsError; static;
    /// <summary>A fatal error carrying the given alert description and message.</summary>
    class function CreateFatal(ADescription: TTlsAlertDescription;
      const AMessage: string;
      AOrigin: TTlsErrorOrigin = TTlsErrorOrigin.Unknown): TTlsError; static;
    /// <summary>A fatal error for a peer-sent alert, carrying the RAW wire description byte so the
    /// diagnostic stays honest even for a code this library does not map (e.g. no_certificate or a
    /// future code): Alert maps the byte when known, else it is a placeholder internal_error, but
    /// AlertByte is always the byte the peer actually sent.</summary>
    class function CreatePeerFatal(ADescriptionByte: Byte;
      const AMessage: string): TTlsError; static;
    property Alert: TTlsAlert read FAlert;
    property Message: string read FMessage;
    property Origin: TTlsErrorOrigin read FOrigin;
    /// <summary>The on-wire alert description byte: for a peer alert the code the peer sent (even
    /// when unmapped); otherwise the byte of Alert.Description.</summary>
    property AlertByte: Byte read FAlertByte;
  end;

implementation

{ TTlsError }

class function TTlsError.Create(const AAlert: TTlsAlert; const AMessage: string;
  AOrigin: TTlsErrorOrigin): TTlsError;
begin
  Result.FAlert := AAlert;
  Result.FMessage := AMessage;
  Result.FOrigin := AOrigin;
  Result.FAlertByte := AAlert.Description.ToByte;
end;

class function TTlsError.CreateFatal(ADescription: TTlsAlertDescription;
  const AMessage: string; AOrigin: TTlsErrorOrigin): TTlsError;
begin
  Result := TTlsError.Create(TTlsAlert.CreateFatal(ADescription), AMessage, AOrigin);
end;

class function TTlsError.CreatePeerFatal(ADescriptionByte: Byte;
  const AMessage: string): TTlsError;
var
  LDescription: TTlsAlertDescription;
begin
  // map the byte when we know it (so Alert.Description stays meaningful), else a placeholder;
  // AlertByte carries the peer's actual code either way, so an unmapped alert is not misreported
  // as our own internal_error
  if not TTlsAlertDescription.TryFromByte(ADescriptionByte, LDescription) then
    LDescription := TTlsAlertDescription.InternalError;
  Result := TTlsError.Create(TTlsAlert.CreateFatal(LDescription), AMessage,
    TTlsErrorOrigin.Peer);
  Result.FAlertByte := ADescriptionByte;
end;

end.
