{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpTlsLibExceptions;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpTlsAlert,
  TlpTlsError;

type
  /// <summary>Root of the TlsLib exception hierarchy.</summary>
  EBaseTlsLibException = class(Exception);

  /// <summary>An argument supplied to a public API was invalid.</summary>
  EArgumentTlsLibException = class(EBaseTlsLibException);

  /// <summary>A peer-supplied value (key share, ciphertext, public point) was
  /// invalid; the engine boundary turns it into an illegal_parameter alert.</summary>
  EPeerInputTlsLibException = class(EArgumentTlsLibException);

  /// <summary>An operation was attempted while in an invalid state.</summary>
  EInvalidOperationTlsLibException = class(EBaseTlsLibException);

  /// <summary>A requested capability is not supported.</summary>
  ENotSupportedTlsLibException = class(EBaseTlsLibException);

  /// <summary>
  /// Carries a <see cref="TTlsAlertDescription" /> so the engine boundary can
  /// turn a raised alert into a fatal outcome with a queued alert. The field is
  /// protected so specialized descendants can pin a fixed description.
  /// </summary>
  EFatalAlertTlsLibException = class(EBaseTlsLibException)
  protected
  var
    FAlertDescription: TTlsAlertDescription;
  public
    constructor CreateRes(ADescription: TTlsAlertDescription;
      AResStringRec: PResStringRec); overload;
    constructor CreateResFmt(ADescription: TTlsAlertDescription;
      AResStringRec: PResStringRec; const AArgs: array of const); overload;
    property AlertDescription: TTlsAlertDescription read FAlertDescription;
  end;

  /// <summary>
  /// A wire-parsing failure; always maps to the decode_error alert. Raised by
  /// the bounds-checked codec on any malformed input.
  /// </summary>
  EDecodeErrorTlsLibException = class(EFatalAlertTlsLibException)
  public
    constructor CreateRes(AResStringRec: PResStringRec); reintroduce; overload;
    constructor CreateResFmt(AResStringRec: PResStringRec;
      const AArgs: array of const); reintroduce; overload;
  end;

  /// <summary>
  /// A fatal TLS error raised out of the blocking stream pump: it carries the
  /// structured alert and message the engine (or the peer) produced, so a host
  /// adapter can map it onto its own error convention.
  /// </summary>
  ETlsStreamError = class(EBaseTlsLibException)
  strict private
    FAlert: TTlsAlertDescription;
    FHasAlert: Boolean;
  public
    constructor Create(const AError: TTlsError); overload;
    constructor Create(ADescription: TTlsAlertDescription;
      const AMessage: string); overload;
    /// <summary>Constructs a stream error that carries no TLS alert: the transport died
    /// (EOF or a read timeout) with no alert exchanged, so HasAlert is False and Alert is
    /// meaningless. Used for truncation and timeout, which are transport events, not TLS
    /// alerts - stamping a placeholder alert here misreports them as an on-the-wire alert.</summary>
    constructor Create(const AMessage: string); overload;
    /// <summary>The alert that was (or would be) sent; valid only when HasAlert.</summary>
    property Alert: TTlsAlertDescription read FAlert;
    property HasAlert: Boolean read FHasAlert;
  end;

  /// <summary>
  /// The peer closed the transport (EOF) with the exchange unfinished and without a
  /// close_notify - a possible truncation attack (RFC 8446 6.1). Distinct from a clean
  /// close_notify shutdown, which the stream surfaces as an ordinary EOF. On a server this
  /// is usually benign - a client that walked away mid-handshake - and belongs at info level.
  /// </summary>
  ETlsTransportTruncated = class(ETlsStreamError);

  /// <summary>
  /// The adapter's handshake read timeout elapsed with the peer sending nothing - a silent
  /// or dead connection reaped. Distinct from ETlsTransportTruncated (a peer close): this is
  /// "we timed out", that is "the client closed". Also benign on a server.
  /// </summary>
  ETlsHandshakeTimeout = class(ETlsStreamError);

implementation

{ EFatalAlertTlsLibException }

constructor EFatalAlertTlsLibException.CreateRes(ADescription: TTlsAlertDescription;
  AResStringRec: PResStringRec);
begin
  inherited CreateRes(AResStringRec);
  FAlertDescription := ADescription;
end;

constructor EFatalAlertTlsLibException.CreateResFmt(ADescription: TTlsAlertDescription;
  AResStringRec: PResStringRec; const AArgs: array of const);
begin
  inherited CreateResFmt(AResStringRec, AArgs);
  FAlertDescription := ADescription;
end;

{ EDecodeErrorTlsLibException }

constructor EDecodeErrorTlsLibException.CreateRes(AResStringRec: PResStringRec);
begin
  inherited CreateRes(TTlsAlertDescription.DecodeError, AResStringRec);
end;

constructor EDecodeErrorTlsLibException.CreateResFmt(AResStringRec: PResStringRec;
  const AArgs: array of const);
begin
  inherited CreateResFmt(TTlsAlertDescription.DecodeError, AResStringRec, AArgs);
end;

{ ETlsStreamError }

constructor ETlsStreamError.Create(const AError: TTlsError);
begin
  inherited Create(AError.Message);
  FAlert := AError.Alert.Description;
  FHasAlert := True;
end;

constructor ETlsStreamError.Create(ADescription: TTlsAlertDescription;
  const AMessage: string);
begin
  inherited Create(AMessage);
  FAlert := ADescription;
  FHasAlert := True;
end;

constructor ETlsStreamError.Create(const AMessage: string);
begin
  inherited Create(AMessage);
  FHasAlert := False;
end;

end.
