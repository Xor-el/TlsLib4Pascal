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
  TlpTlsVersion,
  TlpIRecordProtection;

type
  /// <summary>
  /// The result of feeding bytes to the engine: it made progress, it needs more
  /// input, or it failed fatally (the alert is pre-queued and the engine is now
  /// terminal). Genuine API misuse raises instead.
  /// </summary>
  TTlsOutcome = (Advanced, NeedMoreInput, Fatal);

  /// <summary>The kind of a queued engine event.</summary>
  TTlsEventKind = (
    AppData,            // application data is available via ReadAppData
    HandshakeFragment,  // a handshake record surfaced (the handshake state machine consumes it)
    PeerAlert,          // the peer sent an alert
    Closed,             // a close_notify was received (clean shutdown)
    KeysInstalled,      // a record-protection epoch was installed
    SessionTicketReceived, // a resumption ticket arrived and was cached (RFC 8446 4.6.1)
    EarlyDataAccepted,  // the server accepted the client's 0-RTT early data
    EarlyDataRejected,  // the server rejected 0-RTT; the client replays it as 1-RTT
    KeyUpdateReceived,  // the peer sent a post-handshake KeyUpdate; the read epoch rekeyed
    CertificateReceived // the peer chain passed the pipeline; a verdict is awaited (async)
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

  /// <summary>A handshake fragment, carried by a HandshakeFragment event.</summary>
  IHandshakeDataEvent = interface(ITlsEvent)
    ['{9F5B2A48-6C1E-4D70-B3A2-0E7D5C816B2F}']
    function Data: TBytes;
  end;

  /// <summary>
  /// The parked peer certificate, carried by a CertificateReceived event when async
  /// certificate verdicts are enabled. The chain (leaf first, DER) has already passed the
  /// engine's built-in trust pipeline; the host inspects it out-of-band and resumes the
  /// handshake with SetCertificateVerdict (augment-only: the verdict can only reject).
  /// </summary>
  ICertificateReceivedEvent = interface(ITlsEvent)
    ['{1A6C4E80-3B72-4D95-8F21-7C0E5B9A2D46}']
    /// <summary>The peer certificate chain, leaf first, DER.</summary>
    function Chain: TArray<TBytes>;
    /// <summary>The host the certificate was validated for (empty on the server side).</summary>
    function HostName: string;
  end;

  /// <summary>
  /// The sans-IO TLS engine: a pure transducer with no sockets, threads, or
  /// timers and the same contract for client and server, independent of the
  /// negotiated protocol version. The caller feeds transport bytes and application
  /// writes in, and drains outbound bytes, application data, and events out.
  /// Single-threaded: the caller serializes access; there are no internal locks.
  /// </summary>
  ITlsEngine = interface(IInterface)
    ['{3A8E1C24-5D9B-4F60-A7C8-2B6E0D4F91A5}']
    // --- network -> engine ---
    /// <summary>Feeds transport bytes; drives the record layer.</summary>
    function ProcessInput(const AWire: TBytes; AOffset, ALength: Int32): TTlsOutcome;

    // --- application -> engine ---
    /// <summary>Queues application data to be protected and sent.</summary>
    procedure Write(const AData: TBytes; AOffset, ALength: Int32);
    /// <summary>
    /// Queues 0-RTT early application data (RFC 8446 2.3). Valid only for a client that
    /// offered early data, after StartHandshake and before the server's response is
    /// processed. The bytes are sent under the early keys and buffered so that, if the
    /// server rejects 0-RTT, they are transparently replayed as 1-RTT once the handshake
    /// completes. A no-op when early data is not open.
    /// </summary>
    procedure WriteEarlyData(const AData: TBytes; AOffset, ALength: Int32);
    /// <summary>
    /// Initiates a post-handshake TLS 1.3 KeyUpdate (RFC 8446 4.6.3): rekeys the write
    /// epoch and sends a KeyUpdate. When ARequestPeerUpdate is True the peer is asked to
    /// rekey and send its own KeyUpdate back. A no-op before the handshake completes, on a
    /// TLS 1.2 connection, or once terminal/closed.
    /// </summary>
    procedure RequestKeyUpdate(ARequestPeerUpdate: Boolean);
    /// <summary>Sends a close_notify (clean shutdown).</summary>
    procedure SendClose;
    /// <summary>Sends a fatal alert and makes the engine terminal.</summary>
    procedure SendAlert(ADescription: TTlsAlertDescription);
    /// <summary>Starts the handshake; raises if the engine has no handshake machine configured.</summary>
    procedure StartHandshake;
    /// <summary>
    /// Resumes a handshake parked for an async peer-certificate verdict (RFC 8446
    /// deferred-verdict seam). AAccept True continues the handshake; the built-in trust
    /// pipeline has already passed, so this only confirms the augment verdict. AAccept False
    /// aborts fail-closed with AAlert (default bad_certificate; a live-revocation reject passes
    /// certificate_revoked, an indeterminate hard-fail bad_certificate_status_response). A no-op
    /// when no verdict is awaited. Called by the driver on the host's decision or, on deadline
    /// expiry, with False (the engine owns no timer).
    /// </summary>
    procedure SetCertificateVerdict(AAccept: Boolean;
      AAlert: TTlsAlertDescription = TTlsAlertDescription.BadCertificate);

    // --- engine -> caller (drains) ---
    /// <summary>Copies pending outbound bytes into ADest at ADestOffset; returns the count.</summary>
    function TakeOutgoing(var ADest: TBytes; ADestOffset: Int32): Int32;
    /// <summary>Copies up to AMaxLength decrypted application bytes out; returns the count.</summary>
    function ReadAppData(var ADest: TBytes; ADestOffset, AMaxLength: Int32): Int32;
    /// <summary>The number of decrypted application bytes already buffered and waiting to be
    /// read; 0 when the caller must read the transport for more.</summary>
    function PendingAppData: Int32;
    /// <summary>Dequeues the next event; False when the queue is empty.</summary>
    function NextEvent(out AEvent: ITlsEvent): Boolean;

    // --- status ---
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
    /// <summary>
    /// The advisory deadline, in milliseconds, within which the host should deliver an
    /// awaited certificate verdict; the driver enforces it (the engine owns no timer) and
    /// on expiry calls SetCertificateVerdict(False). 0 when async verdicts are disabled or
    /// no deadline was configured.
    /// </summary>
    function AsyncCertificateVerdictDeadlineMs: Cardinal;
    /// <summary>Whether the engine has failed or closed and accepts no more work.</summary>
    function IsTerminal: Boolean;
    /// <summary>Whether the peer sent close_notify: a clean inbound shutdown. Unlike the
    /// one-shot Closed event, this is a persistent, idempotent query - it stays True once
    /// the close arrives, even after the event has been drained (a close_notify can coalesce
    /// with the peer's final handshake flight and be observed by the handshake driver before
    /// the read loop ever runs).</summary>
    function IsInboundClosed: Boolean;
    /// <summary>Whether outbound application data is no longer accepted: the engine is
    /// terminal, the peer half-closed (inbound close_notify), or we sent close_notify.
    /// A Write in this state is silently dropped, so callers must check this first.</summary>
    function WriteClosed: Boolean;
    /// <summary>The structured error after a Fatal outcome.</summary>
    function LastError: TTlsError;
    /// <summary>The negotiated protocol version once the handshake has installed keys
    /// (TLS 1.2 or 1.3); a zero wire code before then. Read it after the handshake.</summary>
    function NegotiatedVersion: TTlsVersion;
    /// <summary>Exported keying material derived from the established connection secrets
    /// (RFC 8446 7.5 / RFC 5705). AUseContext distinguishes a supplied (possibly empty)
    /// context from no context at all. Call after the handshake has installed keys.</summary>
    function ExportKeyingMaterial(const ALabel: string; const AContext: TBytes;
      AUseContext: Boolean; ALength: Int32): TBytes;
    /// <summary>The negotiated ALPN protocol, or empty when none was negotiated.</summary>
    function NegotiatedAlpnProtocol: string;
    /// <summary>The stapled OCSP response (DER) the peer delivered in the handshake, or
    /// empty when none was stapled (RFC 6066 / RFC 8446 4.4.2.1).</summary>
    function PeerOcspStaple: TBytes;
    /// <summary>The validated peer certificate chain (leaf first, DER) the handshake accepted:
    /// the server chain for a client, or the client chain a server verified under mutual TLS.
    /// Empty when the peer presented none (e.g. a resumed handshake, or a server the client did
    /// not authenticate). Read after the handshake.</summary>
    function PeerCertificates: TArray<TBytes>;
    /// <summary>The DER-encoded DistinguishedName certificate_authorities the peer named in its
    /// CertificateRequest (RFC 8446 4.2.4 / RFC 5246 7.4.4): the issuers a server will accept for
    /// client authentication, as seen by the client. Empty when none was requested or named.
    /// Read after the handshake.</summary>
    function RequestedCertificateAuthorities: TArray<TBytes>;
    /// <summary>The negotiated cipher suite code (IANA), or 0 before the handshake resolves it.
    /// Read after the handshake.</summary>
    function NegotiatedCipherSuite: UInt16;
    /// <summary>The negotiated named group (IANA) used for key exchange, or 0 when none applies
    /// (a non-(EC)DHE TLS 1.2 key exchange). Read after the handshake.</summary>
    function NegotiatedGroup: UInt16;
    /// <summary>The SNI server_name in play for this connection (RFC 6066): the host_name a
    /// client requested, as seen by a server, or the host_name a client sent. Empty when the
    /// client offered no SNI. Read after the handshake.</summary>
    function PeerServerName: string;
    /// <summary>Whether the handshake was resumed/abbreviated (a TLS 1.3 PSK resumption or a
    /// TLS 1.2 abbreviated handshake), so the peer presented no certificate.</summary>
    function IsResumed: Boolean;
  end;

  /// <summary>
  /// The internal seam the handshake driver uses to install record-protection
  /// epochs as they become available, turning the plaintext engine into a
  /// protected one and, on the write side, marking the handshake established.
  /// Deliberately kept off the public ITlsEngine surface (a caller never installs
  /// epochs directly); reach it with Supports(engine, IRecordEpochInstaller, x).
  /// </summary>
  IRecordEpochInstaller = interface(IInterface)
    ['{4D0F7B36-8E12-4A59-9C63-5A7E1B0D82C4}']
    procedure InstallReadProtection(const AProtection: IRecordProtection);
    procedure InstallWriteProtection(const AProtection: IRecordProtection);
    /// <summary>
    /// Reverts the write epoch to plaintext, abandoning an installed early-data write
    /// protection when a HelloRetryRequest rejects offered 0-RTT (RFC 8446 4.2.10): the
    /// second ClientHello and the rest of the client's flight are sent in the clear.
    /// </summary>
    procedure RevertWriteToPlaintext;
    /// <summary>Applies the negotiated record_size_limit plaintext caps (RFC 8449).</summary>
    procedure SetRecordSizeLimit(AOutboundPlaintext, AInboundPlaintext: Int32);
    /// <summary>
    /// Enters the 0-RTT reject skip mode (RFC 8446 4.2.10): undecryptable early-data
    /// application records are dropped, up to AMaxBytes, until a record decrypts under
    /// the installed epoch. Used when the server rejects offered early data.
    /// </summary>
    procedure SetEarlyDataSkip(AMaxBytes: Int32);
    /// <summary>
    /// Caps outbound 0-RTT at the ticket's max_early_data (RFC 8446 4.2.10): the client
    /// sends at most AMaxBytes of early data and defers any overflow to 1-RTT once the
    /// handshake completes. Set when the client opens the early-data write window.
    /// </summary>
    procedure SetEarlyDataLimit(AMaxBytes: Int32);
    /// <summary>
    /// Opens (AActive) or closes the accepted-0-RTT early-data read window (RFC 8446 4.2.10):
    /// while open, an application_data record legitimately precedes the handshake completion.
    /// A server opens it on installing the early read keys and closes it at EndOfEarlyData.
    /// </summary>
    procedure SetEarlyReadEpoch(AActive: Boolean);
  end;

implementation

end.
