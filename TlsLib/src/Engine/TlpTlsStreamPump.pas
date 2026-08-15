{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpTlsStreamPump;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpTlsAlert,
  TlpTlsAlertProtocol,
  TlpTlsError,
  TlpTlsLibExceptions,
  TlpITlsEngine,
  TlpITlsTransport;

type
  /// <summary>
  /// A fatal TLS error raised out of the blocking stream pump: it carries the
  /// structured alert and message the engine (or the peer) produced, so a host
  /// adapter can map it onto its own error convention.
  /// </summary>
  ETlsStreamError = class(Exception)
  strict private
    FAlert: TTlsAlertDescription;
    FHasAlert: Boolean;
  public
    constructor Create(const AError: TTlsError); overload;
    constructor Create(ADescription: TTlsAlertDescription;
      const AMessage: string); overload;
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

  /// <summary>
  /// Decides a parked peer-certificate verdict out-of-band (RFC 8446 deferred-verdict seam):
  /// AChain is the peer chain (leaf first, DER) the built-in pipeline already accepted, and
  /// AHostName the expected host (empty on the server side). Return True to continue the
  /// handshake, False to abort it. On a False return, ARejectAlert selects the abort alert
  /// (default bad_certificate; a definitive live-revocation reject sets certificate_revoked) -
  /// leave it untouched to keep the default. The resolver owns any deadline: a blocking check
  /// that cannot decide in time must return False (fail-closed). Only reached when async
  /// certificate verdicts are enabled on the config.
  /// </summary>
  TTlsVerdictResolver = function(const AChain: TArray<TBytes>;
    const AHostName: string;
    out ARejectAlert: TTlsAlertDescription): Boolean of object;

  /// <summary>How a single application read cycle ended.</summary>
  TTlsReadStatus = (
    Data,        // plaintext was produced (the returned count is > 0)
    CleanEof,    // the peer sent close_notify: an orderly end of stream
    Truncated);  // the transport closed without close_notify: a possible truncation

  /// <summary>
  /// Drives a sans-IO ITlsEngine over a blocking ITlsTransport: flush outbound,
  /// read inbound, repeat. It is the loopback-test pump with an ITlsTransport in place
  /// of the peer engine; the deferred certificate verdict resolves inline here (the
  /// engine's trust pipeline runs synchronously while ProcessInput drives the handshake).
  /// A fatal outcome raises ETlsStreamError; a transport EOF mid-handshake raises
  /// ETlsTransportTruncated.
  /// </summary>
  TTlsStreamPump = class sealed(TObject)
  strict private
  const
    // one TLS record's plaintext never exceeds 2^14; a 16 KiB transport read comfortably
    // holds a framed record and lets the record layer reassemble across reads
    TransportChunk = Int32(16384);
  strict private
    class procedure RaiseIfFatal(const AEngine: ITlsEngine); static;
    /// <summary>Reports a terminal event (peer alert / close_notify) as an out flag and
    /// captures any CertificateReceived event (async verdict); returns True when the peer
    /// closed cleanly, raising on a peer fatal alert.</summary>
    class function DrainEvents(const AEngine: ITlsEngine; out APeerClosed: Boolean;
      out ACertEvent: ICertificateReceivedEvent): Boolean; static;
    /// <summary>Resolves a parked peer-certificate verdict via the resolver (or fail-closed
    /// when none is supplied), then flushes and re-checks for a fatal outcome.</summary>
    class procedure ResolveVerdict(const AEngine: ITlsEngine;
      const ATransport: ITlsTransport;
      const ACertEvent: ICertificateReceivedEvent;
      const AResolveVerdict: TTlsVerdictResolver); static;
  public
    /// <summary>Sends every pending outbound byte to the transport.</summary>
    class procedure Flush(const AEngine: ITlsEngine;
      const ATransport: ITlsTransport); static;
    /// <summary>Runs the handshake to completion. A client sends its opening flight first
    /// (StartHandshake); a server waits for the ClientHello. Raises on failure. When async
    /// certificate verdicts are enabled, the parked verdict resolves inline via the built-in
    /// trust pipeline (the deferred verdict is never awaited); use the resolver overload to
    /// decide it out-of-band.</summary>
    class procedure DriveHandshake(const AEngine: ITlsEngine;
      const ATransport: ITlsTransport; AIsClient: Boolean); overload; static;
    /// <summary>Runs the handshake to completion, resolving any parked peer-certificate
    /// verdict through AResolveVerdict (a nil resolver fails such a park closed). With async
    /// verdicts disabled the handshake never parks and this behaves exactly like the plain
    /// overload.</summary>
    class procedure DriveHandshake(const AEngine: ITlsEngine;
      const ATransport: ITlsTransport; AIsClient: Boolean;
      const AResolveVerdict: TTlsVerdictResolver); overload; static;
    /// <summary>One application read cycle: drains engine-buffered plaintext (which may have
    /// arrived coalesced with the final handshake flight) before blocking on the transport.
    /// Returns the count copied into ADest and, via AStatus, whether more may follow, the
    /// peer closed cleanly, or the transport was truncated.</summary>
    class function ReadApp(const AEngine: ITlsEngine;
      const ATransport: ITlsTransport; var ADest: TBytes; AMaxLength: Int32;
      out AStatus: TTlsReadStatus): Int32; static;
    /// <summary>Encrypts and sends application data.</summary>
    class procedure WriteApp(const AEngine: ITlsEngine;
      const ATransport: ITlsTransport; const AData: TBytes;
      AOffset, ALength: Int32); static;
    /// <summary>Sends close_notify and flushes it.</summary>
    class procedure Close(const AEngine: ITlsEngine;
      const ATransport: ITlsTransport); static;
  end;

implementation

resourcestring
  SPeerFatalAlert = 'the peer sent a fatal alert';
  STruncatedHandshake = 'the transport closed during the handshake without close_notify';
  SWriteAfterClose = 'a write was attempted after the connection was closed';

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

{ TTlsStreamPump }

class procedure TTlsStreamPump.RaiseIfFatal(const AEngine: ITlsEngine);
begin
  if AEngine.IsTerminal then
    raise ETlsStreamError.Create(AEngine.LastError);
end;

class procedure TTlsStreamPump.Flush(const AEngine: ITlsEngine;
  const ATransport: ITlsTransport);
var
  LBuf: TBytes;
  LGot: Int32;
begin
  LBuf := nil;
  SetLength(LBuf, TransportChunk);
  repeat
    LGot := AEngine.TakeOutgoing(LBuf, 0);
    if LGot > 0 then
      ATransport.Write(LBuf, 0, LGot);
  until LGot = 0;
end;

class function TTlsStreamPump.DrainEvents(const AEngine: ITlsEngine;
  out APeerClosed: Boolean; out ACertEvent: ICertificateReceivedEvent): Boolean;
var
  LEvent: ITlsEvent;
  LAlertEvent: IPeerAlertEvent;
  LCertEvent: ICertificateReceivedEvent;
begin
  Result := False;
  APeerClosed := False;
  ACertEvent := nil;
  while AEngine.NextEvent(LEvent) do
    case LEvent.Kind of
      TTlsEventKind.PeerAlert:
        if Supports(LEvent, IPeerAlertEvent, LAlertEvent) then
        begin
          if LAlertEvent.Alert.HasKnownDescription then
            raise ETlsStreamError.Create(LAlertEvent.Alert.Description,
              SPeerFatalAlert)
          else
            raise ETlsStreamError.Create(TTlsAlertDescription.InternalError,
              SPeerFatalAlert);
        end;
      TTlsEventKind.Closed:
        begin
          APeerClosed := True;
          Result := True;
        end;
      TTlsEventKind.CertificateReceived:
        // capture the parked peer chain so a resolver can decide the verdict
        if Supports(LEvent, ICertificateReceivedEvent, LCertEvent) then
          ACertEvent := LCertEvent;
    end;
end;

class procedure TTlsStreamPump.ResolveVerdict(const AEngine: ITlsEngine;
  const ATransport: ITlsTransport;
  const ACertEvent: ICertificateReceivedEvent;
  const AResolveVerdict: TTlsVerdictResolver);
var
  LAccept: Boolean;
  LAlert: TTlsAlertDescription;
begin
  // fail-closed: with no resolver (or no captured chain) the parked handshake is rejected
  // with certificate_unknown (an unspecified acceptability problem, not a corrupt certificate)
  LAccept := False;
  LAlert := TTlsAlertDescription.CertificateUnknown;
  if Assigned(AResolveVerdict) and (ACertEvent <> nil) then
    LAccept := AResolveVerdict(ACertEvent.Chain, ACertEvent.HostName, LAlert);
  AEngine.SetCertificateVerdict(LAccept, LAlert);
  Flush(AEngine, ATransport); // send the resumed flight, or the abort alert
  RaiseIfFatal(AEngine);      // a rejected verdict made the engine terminal
end;

class procedure TTlsStreamPump.DriveHandshake(const AEngine: ITlsEngine;
  const ATransport: ITlsTransport; AIsClient: Boolean);
begin
  // no resolver: with async verdicts disabled (the default) the handshake never parks, so
  // this is exactly the inline (non-async) path; if async was enabled without a resolver,
  // a park fails closed
  DriveHandshake(AEngine, ATransport, AIsClient, nil);
end;

class procedure TTlsStreamPump.DriveHandshake(const AEngine: ITlsEngine;
  const ATransport: ITlsTransport; AIsClient: Boolean;
  const AResolveVerdict: TTlsVerdictResolver);
var
  LBuf: TBytes;
  LGot: Int32;
  LTotal: Int64;
  LPeerClosed: Boolean;
  LCertEvent: ICertificateReceivedEvent;
begin
  // the client emits its opening flight now; a server has nothing to send until it
  // reads the ClientHello
  if AIsClient then
    AEngine.StartHandshake;
  LTotal := 0;
  LBuf := nil;
  SetLength(LBuf, TransportChunk);
  LCertEvent := nil;
  Flush(AEngine, ATransport);
  while AEngine.IsHandshaking do
  begin
    // a parked verdict makes no progress on the wire; resolve it before blocking on a read
    // that would never return (the peer already sent the rest of its flight)
    if AEngine.AwaitingCertificateVerdict then
    begin
      ResolveVerdict(AEngine, ATransport, LCertEvent, AResolveVerdict);
      LCertEvent := nil;
      Continue;
    end;
    LGot := ATransport.Read(LBuf, 0, TransportChunk);
    if LGot = 0 then
      raise ETlsTransportTruncated.Create(TTlsAlertDescription.InternalError,
        Format('%s (after %d handshake bytes from the peer)', [STruncatedHandshake, LTotal]));
    Inc(LTotal, LGot);
    AEngine.ProcessInput(LBuf, 0, LGot);
    Flush(AEngine, ATransport);
    RaiseIfFatal(AEngine);
    if DrainEvents(AEngine, LPeerClosed, LCertEvent) then
      RaiseIfFatal(AEngine); // a close during the handshake leaves it unfinished/terminal
  end;
end;

class function TTlsStreamPump.ReadApp(const AEngine: ITlsEngine;
  const ATransport: ITlsTransport; var ADest: TBytes; AMaxLength: Int32;
  out AStatus: TTlsReadStatus): Int32;
var
  LBuf: TBytes;
  LGot: Int32;
  LPeerClosed: Boolean;
  LCertEvent: ICertificateReceivedEvent; // unused post-handshake; a verdict parks only mid-handshake
begin
  // surface anything already buffered (app data can arrive coalesced with the peer's
  // final handshake flight) before blocking on the transport
  Result := AEngine.ReadAppData(ADest, 0, AMaxLength);
  if Result > 0 then
  begin
    AStatus := TTlsReadStatus.Data;
    Exit;
  end;
  // DrainEvents still runs for its side effect (it raises on a peer fatal alert); the clean
  // close is detected via the engine's persistent flag, not the one-shot Closed event, which
  // the handshake driver may already have drained when a close_notify coalesced with the
  // peer's final flight
  DrainEvents(AEngine, LPeerClosed, LCertEvent);
  if AEngine.IsInboundClosed then
  begin
    AStatus := TTlsReadStatus.CleanEof;
    Exit(0);
  end;

  LBuf := nil;
  SetLength(LBuf, TransportChunk);
  repeat
    LGot := ATransport.Read(LBuf, 0, TransportChunk);
    if LGot = 0 then
    begin
      // the transport closed. A prior close_notify would have surfaced above as CleanEof,
      // so an EOF here with the connection still live is a possible truncation
      AStatus := TTlsReadStatus.Truncated;
      Exit(0);
    end;
    AEngine.ProcessInput(LBuf, 0, LGot);
    RaiseIfFatal(AEngine);
    Result := AEngine.ReadAppData(ADest, 0, AMaxLength);
    if Result > 0 then
    begin
      AStatus := TTlsReadStatus.Data;
      Exit;
    end;
    DrainEvents(AEngine, LPeerClosed, LCertEvent);
    if AEngine.IsInboundClosed then
    begin
      AStatus := TTlsReadStatus.CleanEof;
      Exit(0);
    end;
    // no plaintext yet (e.g. a post-handshake ticket / KeyUpdate record): read again
  until False;
end;

class procedure TTlsStreamPump.WriteApp(const AEngine: ITlsEngine;
  const ATransport: ITlsTransport; const AData: TBytes; AOffset, ALength: Int32);
begin
  // the engine silently drops a write once terminal/closed; surface it instead of
  // letting the stream report the bytes as sent
  if AEngine.WriteClosed then
    raise EInvalidOperationTlsLibException.CreateRes(@SWriteAfterClose);
  AEngine.Write(AData, AOffset, ALength);
  RaiseIfFatal(AEngine);
  Flush(AEngine, ATransport);
end;

class procedure TTlsStreamPump.Close(const AEngine: ITlsEngine;
  const ATransport: ITlsTransport);
begin
  AEngine.SendClose;
  Flush(AEngine, ATransport);
end;

end.
