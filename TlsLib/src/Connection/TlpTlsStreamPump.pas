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
  TlpEchConfig,
  TlpTrustPolicy,
  TlpTlsConnectionInfo,
  TlpITlsEngine,
  TlpITlsTransport;

type
  /// <summary>How a single application read cycle ended.</summary>
  TTlsReadStatus = (
    Data,        // plaintext was produced (the returned count is > 0)
    CleanEof,    // the peer sent close_notify: an orderly end of stream
    Truncated);  // the transport closed without close_notify: a possible truncation

  /// <summary>
  /// Drives a sans-IO ITlsEngine over a blocking ITlsTransport: flush outbound,
  /// read inbound, repeat. The deferred certificate verdict resolves inline here (the
  /// engine's trust pipeline runs synchronously while ProcessInput drives the handshake).
  /// A fatal outcome raises ETlsStreamError; a transport EOF mid-handshake raises
  /// ETlsTransportTruncated.
  /// </summary>
  TTlsStreamPump = class sealed(TObject)
  public
  const
    // one TLS record's plaintext never exceeds 2^14; a 16 KiB transport read comfortably
    // holds a framed record and lets the record layer reassemble across reads
    TransportChunk = Int32(16384);
    // the most plaintext WriteApp seals before draining to the transport: four max-size
    // records, the record layer's retained outbound capacity, so a chunked bulk write never
    // regrows the outbound buffer and holds at most one slice of ciphertext at a time
    WriteChunk = Int32(4 * 16384);
  strict private
    /// <summary>Flushes best-effort: a transport failure here is swallowed because the caller is
    /// already surfacing a TLS-level error that a transport error must not mask.</summary>
    class procedure FlushQuietly(const AEngine: ITlsEngine;
      const ATransport: ITlsTransport); static;
    /// <summary>Flushes, then raises if the engine is terminal. The flush comes first so the
    /// fatal alert a failed ProcessInput/Write queued reaches the peer before the error surfaces
    /// here (the peer then reads an alert, not a truncation); once terminal it is best-effort.</summary>
    class procedure FlushThenRaiseIfFatal(const AEngine: ITlsEngine;
      const ATransport: ITlsTransport); static;
    /// <summary>DrainEvents for the stream: a peer fatal alert raises ETlsStreamError with its
    /// description (internal_error for an unmapped code); reports a clean peer close via
    /// APeerClosed and captures a parked-certificate event, and returns True on a clean close.</summary>
    class function DrainEventsOrRaise(const AEngine: ITlsEngine; out APeerClosed: Boolean;
      out ACertEvent: ICertificateReceivedEvent): Boolean; static;
  public
    /// <summary>Drains the engine's event queue: reports a peer fatal alert (APeerAlert, nil when
    /// none) and a peer close_notify (APeerClosed), and captures a parked-certificate event so a
    /// resolver can decide the verdict. Never raises; the caller maps a terminal event to its own
    /// signalling. Returns True when a terminal event was seen.</summary>
    class function DrainEvents(const AEngine: ITlsEngine; out APeerAlert: IPeerAlertEvent;
      out APeerClosed: Boolean; out ACertEvent: ICertificateReceivedEvent): Boolean; static;
    /// <summary>Resolves a parked peer-certificate verdict through AResolveVerdict on the captured
    /// park event; fail-closed with certificate_unknown when there is no resolver or no captured
    /// chain (an unspecified acceptability problem, not a corrupt certificate). Sets the verdict on
    /// the engine only: the caller flushes the resumed flight, or the abort alert of a reject, and
    /// surfaces a terminal outcome its own way.</summary>
    class procedure ResolveVerdict(const AEngine: ITlsEngine;
      const ACertEvent: ICertificateReceivedEvent;
      const AResolveVerdict: TCertificateVerdictResolver; APeerRole: TPeerRole); static;
    /// <summary>Raises the engine's terminal failure as the precise TLS error (its alert) when it
    /// is in a fatal state; a no-op otherwise. Lets a caller re-surface a latched handshake failure
    /// with the same alert the engine recorded.</summary>
    class procedure RaiseIfFatal(const AEngine: ITlsEngine); static;
    /// <summary>Sends every pending outbound byte to the transport.</summary>
    class procedure Flush(const AEngine: ITlsEngine;
      const ATransport: ITlsTransport); static;
    /// <summary>Runs the handshake to completion. A client sends its opening flight first
    /// (StartHandshake); a server waits for the ClientHello. Raises on failure. This overload has
    /// no resolver, so with async certificate verdicts enabled a parked verdict fails closed with
    /// certificate_unknown; use the resolver overload to decide it out-of-band.</summary>
    class procedure DriveHandshake(const AEngine: ITlsEngine;
      const ATransport: ITlsTransport; AIsClient: Boolean); overload; static;
    /// <summary>Runs the handshake to completion, resolving any parked peer-certificate
    /// verdict through AResolveVerdict (a nil resolver fails such a park closed). With async
    /// verdicts disabled the handshake never parks and this behaves exactly like the plain
    /// overload.</summary>
    class procedure DriveHandshake(const AEngine: ITlsEngine;
      const ATransport: ITlsTransport; AIsClient: Boolean;
      const AResolveVerdict: TCertificateVerdictResolver); overload; static;
    /// <summary>One application read cycle: drains engine-buffered plaintext (which may have
    /// arrived coalesced with the final handshake flight) before blocking on the transport.
    /// Returns the count copied into ADest and, via AStatus, whether more may follow, the
    /// peer closed cleanly, or the transport was truncated.</summary>
    class function ReadApp(const AEngine: ITlsEngine;
      const ATransport: ITlsTransport; var ADest: TBytes; AMaxLength: Int32;
      out AStatus: TTlsReadStatus): Int32; static;
    /// <summary>Encrypts and sends application data, sealing and draining at most WriteChunk
    /// bytes per iteration so a bulk write never holds its whole ciphertext in memory. At the
    /// AEAD usage limit with no rekey available the engine's close_notify is still sent before
    /// ERecordLimitTlsLibException propagates.</summary>
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
  SClosedDuringHandshake = 'the peer closed the connection during the handshake';
  SWriteAfterClose = 'a write was attempted after the connection was closed';

{ TTlsStreamPump }

class procedure TTlsStreamPump.RaiseIfFatal(const AEngine: ITlsEngine);
var
  LInfo: TTlsConnectionInfo;
begin
  if not AEngine.IsTerminal then
    Exit;
  // a client's ECH reject aborts with ech_required (RFC 9849 sec. 6.1.6); surface the
  // retry_configs and the retry flag through a typed exception so the application can decide to
  // reconnect. keyed on the abort itself, not EchStatus - a server reads Rejected after a benign
  // GREASE handshake that completed, so a later fatal there must surface as its true error
  LInfo := AEngine.ConnectionInfo;
  if LInfo.EchRejectAborted then
    raise EEchRejectedTlsLibException.Create(LInfo.EchRetryConfigs,
      LInfo.EchIsRetryAttempt);
  raise ETlsStreamError.Create(AEngine.LastError);
end;

class procedure TTlsStreamPump.Flush(const AEngine: ITlsEngine;
  const ATransport: ITlsTransport);
var
  LBuf: TBytes;
  LGot: Int32;
begin
  // this runs on every read cycle too; do not allocate the transport buffer when there is
  // nothing to send
  if not AEngine.WantsWrite then
    Exit;
  LBuf := nil;
  SetLength(LBuf, TransportChunk);
  repeat
    LGot := AEngine.TakeOutgoing(LBuf, 0);
    if LGot > 0 then
      ATransport.Write(LBuf, 0, LGot);
  until LGot = 0;
end;

class procedure TTlsStreamPump.FlushQuietly(const AEngine: ITlsEngine;
  const ATransport: ITlsTransport);
begin
  try
    Flush(AEngine, ATransport);
  except
    // best effort: the TLS-level error being surfaced takes precedence
  end;
end;

class procedure TTlsStreamPump.FlushThenRaiseIfFatal(const AEngine: ITlsEngine;
  const ATransport: ITlsTransport);
begin
  if AEngine.IsTerminal then
    FlushQuietly(AEngine, ATransport)
  else
    Flush(AEngine, ATransport);
  RaiseIfFatal(AEngine);
end;

class function TTlsStreamPump.DrainEvents(const AEngine: ITlsEngine;
  out APeerAlert: IPeerAlertEvent; out APeerClosed: Boolean;
  out ACertEvent: ICertificateReceivedEvent): Boolean;
var
  LEvent: ITlsEvent;
  LAlertEvent: IPeerAlertEvent;
  LCertEvent: ICertificateReceivedEvent;
begin
  Result := False;
  APeerAlert := nil;
  APeerClosed := False;
  ACertEvent := nil;
  while AEngine.NextEvent(LEvent) do
    case LEvent.Kind of
      TTlsEventKind.PeerAlert:
        // first alert wins; no event is ever queued after a terminal one, so a full drain and a
        // stop-at-first-terminal dequeue the same set
        if (APeerAlert = nil) and Supports(LEvent, IPeerAlertEvent, LAlertEvent) then
        begin
          APeerAlert := LAlertEvent;
          Result := True;
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

class function TTlsStreamPump.DrainEventsOrRaise(const AEngine: ITlsEngine;
  out APeerClosed: Boolean; out ACertEvent: ICertificateReceivedEvent): Boolean;
var
  LAlertEvent: IPeerAlertEvent;
begin
  DrainEvents(AEngine, LAlertEvent, APeerClosed, ACertEvent);
  if LAlertEvent <> nil then
  begin
    if LAlertEvent.Alert.HasKnownDescription then
      raise ETlsStreamError.Create(LAlertEvent.Alert.Description, SPeerFatalAlert)
    else
      raise ETlsStreamError.Create(TTlsAlertDescription.InternalError, SPeerFatalAlert);
  end;
  Result := APeerClosed;
end;

class procedure TTlsStreamPump.ResolveVerdict(const AEngine: ITlsEngine;
  const ACertEvent: ICertificateReceivedEvent;
  const AResolveVerdict: TCertificateVerdictResolver; APeerRole: TPeerRole);
var
  LAccept: Boolean;
  LAlert: TTlsAlertDescription;
  LCtx: TCertificateVerdictContext;
begin
  // fail-closed: with no resolver (or no captured chain) the parked handshake is rejected
  // with certificate_unknown (an unspecified acceptability problem, not a corrupt certificate)
  LAccept := False;
  LAlert := TTlsAlertDescription.CertificateUnknown;
  if Assigned(AResolveVerdict) and (ACertEvent <> nil) then
  begin
    LCtx.PeerRole := APeerRole;
    LCtx.Chain := ACertEvent.Chain;
    LCtx.ValidatedPath := ACertEvent.ValidatedPath;
    LCtx.HostName := ACertEvent.HostName;
    LCtx.OcspStaple := ACertEvent.OcspStaple;
    LAccept := AResolveVerdict(LCtx, LAlert);
  end;
  AEngine.SetCertificateVerdict(LAccept, LAlert);
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
  const AResolveVerdict: TCertificateVerdictResolver);
var
  LBuf: TBytes;
  LGot: Int32;
  LTotal: Int64;
  LPeerClosed: Boolean;
  LCertEvent: ICertificateReceivedEvent;
  LPeerRole: TPeerRole;
begin
  // our role fixes whose certificate a park concerns: a client verifies the server's chain,
  // a server the mTLS client's
  if AIsClient then
    LPeerRole := TPeerRole.Server
  else
    LPeerRole := TPeerRole.Client;
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
      ResolveVerdict(AEngine, LCertEvent, AResolveVerdict, LPeerRole);
      // send the resumed flight, or the abort alert of a rejected verdict, then surface the abort
      FlushThenRaiseIfFatal(AEngine, ATransport);
      LCertEvent := nil;
      Continue;
    end;
    LGot := ATransport.Read(LBuf, 0, TransportChunk);
    if LGot = 0 then
      raise ETlsTransportTruncated.Create(
        Format('%s (after %d handshake bytes from the peer)', [STruncatedHandshake, LTotal]));
    Inc(LTotal, LGot);
    AEngine.ProcessInput(LBuf, 0, LGot);
    FlushThenRaiseIfFatal(AEngine, ATransport);
    if DrainEventsOrRaise(AEngine, LPeerClosed, LCertEvent) then
    begin
      RaiseIfFatal(AEngine); // a fatal recorded alongside the close takes precedence
      // a peer close while still handshaking abandons it: raise rather than loop back into a read
      if AEngine.IsHandshaking then
        raise ETlsTransportTruncated.Create(SClosedDuringHandshake);
    end;
  end;
  // StartHandshake itself can fail the engine (never entering the loop); surface that alert
  RaiseIfFatal(AEngine);
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
  DrainEventsOrRaise(AEngine, LPeerClosed, LCertEvent);
  if AEngine.IsInboundClosed then
  begin
    AStatus := TTlsReadStatus.CleanEof;
    Exit(0);
  end;

  LBuf := nil;
  SetLength(LBuf, TransportChunk);
  repeat
    // a terminal engine takes no more input: reading would block forever with its alert unsent
    if AEngine.IsTerminal then
    begin
      FlushQuietly(AEngine, ATransport);
      RaiseIfFatal(AEngine);
    end;
    LGot := ATransport.Read(LBuf, 0, TransportChunk);
    if LGot = 0 then
    begin
      // the transport closed. A prior close_notify would have surfaced above as CleanEof,
      // so an EOF here with the connection still live is a possible truncation
      AStatus := TTlsReadStatus.Truncated;
      Exit(0);
    end;
    AEngine.ProcessInput(LBuf, 0, LGot);
    // only a fatal alert must reach the peer on the read path; healthy outbound (a KeyUpdate
    // reply, a warning) is left for the next write, so a reader does not write to the transport
    // and race a concurrent writer on the outbound queue
    if AEngine.IsTerminal then
      FlushQuietly(AEngine, ATransport);
    RaiseIfFatal(AEngine);
    Result := AEngine.ReadAppData(ADest, 0, AMaxLength);
    if Result > 0 then
    begin
      AStatus := TTlsReadStatus.Data;
      Exit;
    end;
    DrainEventsOrRaise(AEngine, LPeerClosed, LCertEvent);
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
var
  LOffset, LRemaining, LChunk: Int32;
begin
  // the engine's Write raises once the write side is closed; pre-check so the stream reports a
  // clear error rather than the raw engine exception (and never counts the bytes as sent)
  if AEngine.WriteClosed then
    raise EInvalidOperationTlsLibException.CreateRes(@SWriteAfterClose);
  LOffset := AOffset;
  LRemaining := ALength;
  // the engine seals whatever it is handed in full, so a bulk write sealed whole would hold the
  // entire ciphertext before the first send: seal and drain one bounded slice at a time
  while LRemaining > 0 do
  begin
    LChunk := LRemaining;
    if LChunk > WriteChunk then
      LChunk := WriteChunk;
    try
      AEngine.Write(AData, LOffset, LChunk);
    except
      on ERecordLimitTlsLibException do
      begin
        // the engine queued close_notify at the AEAD usage limit; deliver it (any slices sealed
        // before the limit are already on the wire) before surfacing the refusal to the caller
        FlushQuietly(AEngine, ATransport);
        raise;
      end;
    end;
    FlushThenRaiseIfFatal(AEngine, ATransport);
    Inc(LOffset, LChunk);
    Dec(LRemaining, LChunk);
  end;
end;

class procedure TTlsStreamPump.Close(const AEngine: ITlsEngine;
  const ATransport: ITlsTransport);
begin
  AEngine.SendClose;
  Flush(AEngine, ATransport);
end;

end.
