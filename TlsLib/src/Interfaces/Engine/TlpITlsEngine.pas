{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpITlsEngine;

{$I ..\..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpTlsAlert,
  TlpTlsAlertProtocol,
  TlpTlsError,
  TlpTlsConnectionInfo,
  TlpTrustPolicy,
  TlpHandshakeMessages;

type
  /// <summary>
  /// The result of feeding bytes to the engine: it made progress, it needs more
  /// input, or it failed fatally (the engine is now terminal; a local failure queues its alert
  /// unless our close_notify or a failed seal prevented it). Genuine API misuse raises instead.
  /// </summary>
  TTlsOutcome = (Advanced, NeedMoreInput, Fatal);

  /// <summary>The kind of a queued engine event.</summary>
  TTlsEventKind = (
    PeerAlert,          // the peer sent an alert
    Closed,             // a close_notify was received (a failure before the handshake completes)
    SessionTicketReceived, // a resumption ticket arrived and was cached (RFC 9846 4.7.1)
    EarlyDataAccepted,  // the server accepted the client's 0-RTT early data
    EarlyDataRejected,  // the server rejected 0-RTT; the accepted early data is discarded (not replayed)
    KeyUpdateReceived,  // the peer sent a post-handshake KeyUpdate; the read epoch rekeyed
    CertificateReceived // the peer chain passed and the peer proved key possession; a verdict is awaited
  );

  /// <summary>A pollable, closure-free engine event (event-as-data queue).</summary>
  ITlsEvent = interface(IInterface)
    ['{2C9A6B10-4E7F-4D28-9A31-6B0C2E5F8A44}']
    function Kind: TTlsEventKind;
  end;

  /// <summary>A received alert, carried by a PeerAlert event.</summary>
  IPeerAlertEvent = interface(ITlsEvent)
    ['{7E1D3F92-0A4C-4B6E-8D57-1C4A9B2E6F03}']
    /// <summary>
    /// The decoded alert: raw level/description bytes, plus the mapped enum when
    /// the code is recognized (a peer may send an unknown alert code).
    /// </summary>
    function Alert: TReceivedAlert;
  end;

  /// <summary>
  /// The parked peer certificate, carried by a CertificateReceived event when async
  /// certificate verdicts are enabled. The chain (leaf first, DER) has already passed the
  /// engine's built-in trust pipeline and the peer has proved it holds the leaf key (its
  /// CertificateVerify or signed ServerKeyExchange verified); the host inspects it out-of-band and
  /// resumes the handshake with SetCertificateVerdict (augment-only: the verdict can only reject).
  /// </summary>
  ICertificateReceivedEvent = interface(ITlsEvent)
    ['{3FE19C43-8399-4841-ACAE-89DB8D6AD679}']
    /// <summary>The peer certificate chain as presented, leaf first, DER.</summary>
    function Chain: TArray<TBytes>;
    /// <summary>The leaf-first path the verifier validated (the leaf's issuer at index 1 where it
    /// can name one), so an out-of-band revocation check authenticates the responder against the
    /// issuer PKIX already established; empty when nothing was validated (InsecureSkipVerify).</summary>
    function ValidatedPath: TArray<TBytes>;
    /// <summary>The host the certificate was validated for (empty on the server side).</summary>
    function HostName: string;
    /// <summary>The handshake OCSP staple the peer delivered (empty when none), so an
    /// out-of-band live check can skip a fetch the server already answered in-band.</summary>
    function OcspStaple: TBytes;
    /// <summary>The revocation posture the configuration asked for; a verdict resolver holds to it
    /// even when it was built with a laxer one.</summary>
    function RevocationPosture: TRevocationPosture;
  end;

  /// <summary>
  /// The sans-IO TLS engine: a pure transducer with no sockets, threads, or
  /// timers and the same contract for client and server, independent of the
  /// negotiated protocol version. The caller feeds transport bytes and application
  /// writes in, and drains outbound bytes, application data, and events out.
  /// Single-threaded: the caller serializes access; there are no internal locks.
  /// </summary>
  ITlsEngine = interface(IInterface)
    ['{F334F198-3F67-4109-8AE8-B1B928131889}']
    // --- network -> engine ---
    /// <summary>Feeds transport bytes; drives the record layer.</summary>
    function ProcessInput(const AWire: TBytes; AOffset, ALength: Int32): TTlsOutcome;

    // --- application -> engine ---
    /// <summary>Queues application data to be protected and sent. Raises
    /// EInvalidOperationTlsLibException if the connection is terminal, our close_notify was
    /// already sent, (TLS 1.2 only) an inbound close_notify closed it - check WriteClosed first -
    /// or the application write epoch is not yet in force: a TLS 1.3 server may write from its own
    /// Finished onward (half-RTT), a TLS 1.3 client and any TLS 1.2 endpoint once the handshake
    /// completes; drive the handshake first, and send 0-RTT through WriteEarlyData. A zero-length
    /// write (once a write epoch exists) is a no-op. Under TLS 1.3 an inbound close_notify leaves
    /// the write side open (RFC 9846 6.1). ALength is sealed in full into the outbound queue; a raw
    /// embedder bounds transient memory on a bulk write by writing in slices and draining
    /// TakeOutgoing between them.</summary>
    procedure Write(const AData: TBytes; AOffset, ALength: Int32);
    /// <summary>
    /// Queues 0-RTT early application data (RFC 9846 2.3) and returns the number of bytes
    /// accepted as early data. Valid only for a client that offered early data, after
    /// StartHandshake and before the server's response is processed. Bytes are sent under the
    /// early keys up to the ticket's max_early_data; anything beyond that budget is NOT sent -
    /// the caller resends the unaccepted remainder (ALength - result) itself once the handshake
    /// completes (IsHandshaking is False). If the server rejects 0-RTT, the accepted early data
    /// is discarded, not replayed - resending is the application's decision. Returns 0 when the
    /// early-data window is not open.
    /// </summary>
    function WriteEarlyData(const AData: TBytes; AOffset, ALength: Int32): Int32;
    /// <summary>
    /// Initiates a post-handshake TLS 1.3 KeyUpdate (RFC 9846 4.7.3): rekeys the write
    /// epoch and sends a KeyUpdate. When ARequest is UpdateRequested the peer is asked to
    /// rekey and send its own KeyUpdate back. A no-op before the handshake completes, on a
    /// TLS 1.2 connection, once terminal or after our own close_notify, and (like Write) after
    /// an inbound close_notify only under TLS 1.2 - a 1.3 write half stays open and rekeyable.
    /// Also a silent no-op once 2^48-1 KeyUpdates have been sent (RFC 9846 4.7.3). If an earlier
    /// UpdateRequested has not yet been answered by a KeyUpdate from the peer, a new
    /// UpdateRequested is sent as UpdateNotRequested; the write keys are still updated.
    /// </summary>
    procedure RequestKeyUpdate(ARequest: TKeyUpdateRequest);
    /// <summary>Sends a close_notify (clean shutdown).</summary>
    procedure SendClose;
    /// <summary>Sends a fatal alert and makes the engine terminal; nothing is queued after our
    /// close_notify (RFC 9846 6.1) or if the alert cannot be sealed.</summary>
    procedure SendAlert(ADescription: TTlsAlertDescription); overload;
    /// <summary>As above, recording AReason as the error the next operation raises.</summary>
    procedure SendAlert(ADescription: TTlsAlertDescription; const AReason: string); overload;
    /// <summary>Ends the connection after the transport failed under it, recording AReason as the
    /// error the next operation raises. Unlike SendAlert this is not a TLS fatal alert, so the
    /// sessions the connection stored stay resumable (RFC 5246 7.2.1).
    /// No alert is queued and pending outbound bytes are dropped; LastError.Origin is Transport and
    /// carries no alert.</summary>
    procedure LatchTransportFailure(const AReason: string);
    /// <summary>Starts the handshake: a client emits its first flight; a server has nothing to
    /// send until the ClientHello. Call it once: a second call raises, as does a call from inside
    /// a handshake callback; on an engine that already failed it does nothing.</summary>
    procedure StartHandshake;
    /// <summary>
    /// Resumes a handshake parked for an async peer-certificate verdict.
    /// AAccept True continues the handshake; the built-in trust
    /// pipeline has already passed, so this only confirms the augment verdict. AAccept False
    /// aborts fail-closed with AAlert (ignored on accept): typically bad_certificate; a
    /// live-revocation reject passes certificate_revoked, an indeterminate hard-fail
    /// bad_certificate_status_response. A no-op when no verdict is awaited. Called by the driver
    /// on the host's decision or with False when a resolver could not decide within its budget
    /// (the engine owns no timer).
    /// </summary>
    procedure SetCertificateVerdict(AAccept: Boolean; AAlert: TTlsAlertDescription);

    // --- engine -> caller (drains) ---
    /// <summary>Copies pending outbound bytes into ADest at ADestOffset; returns the count, at most
    /// Length(ADest) - ADestOffset (0 when that is not positive), so size ADest first.</summary>
    function TakeOutgoing(var ADest: TBytes; ADestOffset: Int32): Int32;
    /// <summary>Copies up to AMaxLength decrypted application bytes out; returns the count. It can
    /// resume a deferred inbound drain, so like ProcessInput it can leave the engine terminal or
    /// with outbound pending; a raw embedder checks IsTerminal / WantsWrite after it. It never
    /// returns 0-RTT early data; see ReadEarlyData.</summary>
    function ReadAppData(var ADest: TBytes; ADestOffset, AMaxLength: Int32): Int32;
    /// <summary>The number of decrypted 1-RTT application bytes already buffered and waiting to be
    /// read (accepted early data is counted by PendingEarlyData); 0 when the caller must read
    /// the transport for more.</summary>
    function PendingAppData: Int32;
    /// <summary>Copies up to AMaxLength bytes of accepted 0-RTT early data (RFC 9846 2.3) out;
    /// returns the count. Early data is replayable (RFC 9846 8, F.5), so act on it only when the
    /// request is idempotent. It is never returned by ReadAppData and precedes all 1-RTT data on
    /// the wire; it stays readable after the handshake completes. Always 0 on a client or when
    /// 0-RTT was not accepted.</summary>
    function ReadEarlyData(var ADest: TBytes; ADestOffset, AMaxLength: Int32): Int32;
    /// <summary>The number of accepted early-data bytes buffered and waiting to be read.</summary>
    function PendingEarlyData: Int32;
    /// <summary>Dequeues the next event; False when the queue is empty. Drain it every cycle:
    /// past a bounded backlog of undrained events the informational kinds (SessionTicketReceived,
    /// EarlyData*, KeyUpdateReceived) are dropped, so a caller that never drains cannot grow the
    /// queue without bound; PeerAlert, Closed and CertificateReceived are never dropped. Application
    /// data is not an event - it is signalled by PendingAppData and read with ReadAppData.</summary>
    function NextEvent(out AEvent: ITlsEvent): Boolean;

    // --- status ---
    /// <summary>A snapshot of the negotiated facts; zero values before the handshake resolves
    /// each of them.</summary>
    function ConnectionInfo: TTlsConnectionInfo;
    /// <summary>Whether the engine wants more transport bytes.</summary>
    function WantsRead: Boolean;
    /// <summary>Whether outbound bytes are waiting to be taken.</summary>
    function WantsWrite: Boolean;
    /// <summary>Whether the handshake is still in progress.</summary>
    function IsHandshaking: Boolean;
    /// <summary>
    /// Whether the handshake is parked awaiting an async peer-certificate verdict: the peer
    /// chain passed the built-in pipeline and a CertificateReceived event was raised; the
    /// handshake makes no further progress until SetCertificateVerdict is called. Always
    /// False when async certificate verdicts are disabled (the verdict resolves inline).
    /// </summary>
    function AwaitingCertificateVerdict: Boolean;
    /// <summary>Whether the engine has FAILED (a fatal alert was sent or received, the peer sent
    /// close_notify before the handshake completed, or the transport failed under it) and accepts
    /// no more work. It is NOT set by a close_notify after the handshake (under TLS 1.3 that
    /// half-closes: the write side stays open). To end a read loop use IsClosed (failed or
    /// peer-closed); to detect a clean inbound shutdown use IsInboundClosed.</summary>
    function IsTerminal: Boolean;
    /// <summary>Whether the engine is finished for reading: it has failed OR the peer sent
    /// close_notify. The single, honest loop condition for a raw embedder - once True no further
    /// application data will ever be read, so a `while not IsClosed do Pump` loop terminates (a
    /// loop keyed on IsTerminal alone would spin forever after a clean close).</summary>
    function IsClosed: Boolean;
    /// <summary>Whether the peer sent close_notify: a clean inbound shutdown. Unlike the
    /// one-shot Closed event, this is a persistent, idempotent query - it stays True once
    /// the close arrives, even after the event has been drained (a close_notify can coalesce
    /// with the peer's final handshake flight and be observed by the handshake driver before
    /// the read loop ever runs).</summary>
    function IsInboundClosed: Boolean;
    /// <summary>Whether outbound application data is no longer accepted: the engine is terminal,
    /// we sent close_notify, or (TLS 1.2 only) the peer's inbound close_notify closed it. Under
    /// TLS 1.3 an inbound close_notify leaves the write side open (RFC 9846 6.1). A Write in this
    /// state raises EInvalidOperationTlsLibException, so callers must check this first.</summary>
    function WriteClosed: Boolean;
    /// <summary>The structured error after a Fatal outcome or a latched transport failure.</summary>
    function LastError: TTlsError;
    /// <summary>Exported keying material derived from the connection's exporter secret with no
    /// context value (RFC 9846 7.5 / RFC 5705). Available once the exporter secret is derived: for a
    /// TLS 1.3 server that is half-RTT (after it sent its Finished) - the value binds the
    /// transcript through the server Finished and so precedes client authentication under
    /// mutual TLS; TLS 1.2 is available only after the handshake completes, and only when the session
    /// used Extended Master Secret (RFC 7627 5.4; see ConnectionInfo.ExtendedMasterSecret). Empty
    /// otherwise (and on a failed connection).</summary>
    function ExportKeyingMaterial(const ALabel: string;
      ALength: Int32): TBytes; overload;
    /// <summary>Exported keying material derived from the connection's exporter secret and bound to
    /// AContext (RFC 9846 7.5 / RFC 5705). A supplied context, empty or not, is distinct from no
    /// context at all. Availability matches the no-context overload.</summary>
    function ExportKeyingMaterial(const ALabel: string; const AContext: TBytes;
      ALength: Int32): TBytes; overload;
    /// <summary>Early-data (0-RTT) keying material (RFC 9846 7.5). TLS 1.3 only: available on a
    /// client from when it offers 0-RTT until the server rejects it, and on a server once it
    /// accepts 0-RTT; empty otherwise, once 0-RTT is rejected, on TLS 1.2, and on a failed
    /// connection. Material from early data carries the same replay caveat as ReadEarlyData.</summary>
    function ExportEarlyKeyingMaterial(const ALabel: string; const AContext: TBytes;
      ALength: Int32): TBytes;
  end;

implementation

end.
