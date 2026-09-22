{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpIHandshakeMachine;

{$I ..\..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpTlsAlert,
  TlpTlsVersion,
  TlpITlsEngine,
  TlpHandshakeStage,
  TlpHandshakeMessage,
  TlpHandshakeEffect,
  TlpIRecordProtection;

type
  /// <summary>
  /// A running TLS handshake for one side, as a stateful machine: Start kicks the
  /// initiating side (the client) and ProcessMessage feeds one reassembled peer
  /// message, each returning the effects the driver applies. The current phase is
  /// held internally; an in-band protocol failure is reported as a Fail effect, not
  /// by raising.
  /// </summary>
  IHandshakeMachine = interface(IInterface)
    ['{4B9E2C71-6A05-4D38-8F14-3E7C0B5A92D6}']
    /// <summary>Whether this endpoint initiates the handshake (a client sending the first
    /// ClientHello) rather than responding to it (a server). Drives the initial
    /// legacy_record_version (RFC 8446 5.1).</summary>
    function Initiates: Boolean;
    /// <summary>The coarse handshake stage (Handshaking / ParkedForVerdict / Connected), read by
    /// the engine and conductor to gate KeyUpdate, exporter availability, and completion without
    /// scanning effects or proxy flags.</summary>
    function Stage: THandshakeStage;
    function Start: TArray<THandshakeEffect>;
    function ProcessMessage(const AMessage: TTlsHandshakeMessage)
      : TArray<THandshakeEffect>;
    /// <summary>Initiates a post-handshake KeyUpdate (TLS 1.3 only), returning the effects
    /// the driver applies. A no-op (empty) for machines/versions without KeyUpdate or when
    /// the connection is not yet established.</summary>
    function RequestKeyUpdate(ARequestPeerUpdate: Boolean): TArray<THandshakeEffect>;
    /// <summary>Emits the one coalesced response owed to a peer update_requested, if any;
    /// the engine flushes it just before the next application write. Empty when none is
    /// pending or the machine/version has no KeyUpdate.</summary>
    function TakePendingKeyUpdate: TArray<THandshakeEffect>;
    /// <summary>Resumes a handshake parked for an out-of-band verdict at a point with no
    /// buffered peer message to drive it (the TLS 1.3 reverify-on-resume park at ServerFinished),
    /// returning the withheld continuation - the client's own closing flight. Empty for the
    /// initial-certificate park (the buffered server flight drives that) and for every
    /// machine/version that does not park at a message-less point.</summary>
    function ResumeAfterVerdict: TArray<THandshakeEffect>;
    /// <summary>Exported keying material over the established secrets (RFC 8446 7.5 / RFC
    /// 5705). Empty unless CanExportKeyingMaterial (the exporter secret has been derived).</summary>
    function ExportKeyingMaterial(const ALabel: string; const AContext: TBytes;
      AUseContext: Boolean; ALength: Int32): TBytes;
    /// <summary>Whether the exporter secret is available: for a TLS 1.3 server that is true in
    /// half-RTT (after it sent its Finished), before the peer's Finished (RFC 8446 7.5); TLS 1.2
    /// stays gated on completion. Never available while the machine is parked on an out-of-band
    /// peer-certificate verdict (Stage = ParkedForVerdict) - neither side exports over a peer
    /// identity still being decided.</summary>
    function CanExportKeyingMaterial: Boolean;
  end;

  /// <summary>
  /// Where the driver reports the outcomes a handshake effect cannot carry out on
  /// its own: engine events, completion, and fatal failure. The engine implements
  /// this to bridge the handshake to its own queues.
  /// </summary>
  IHandshakeSink = interface(IInterface)
    ['{8D3F6A24-5C90-4E71-B2A6-1F4E0C7B85D3}']
    procedure OnHandshakeEvent(AEvent: TTlsEventKind);
    procedure OnAlpnSelected(const AProtocol: string);
    procedure OnOcspStapleReceived(const AStaple: TBytes);
    procedure OnHandshakeEstablished;
    procedure OnHandshakeFailed(AAlert: TTlsAlertDescription);
  end;

  /// <summary>
  /// An optional companion the driver reaches with Supports on the sink to emit a warning-level
  /// alert the machine chose to raise without failing (e.g. no_renegotiation): the engine writes
  /// it under the current epoch and stays live. Kept off IHandshakeSink so existing sinks (and
  /// their test doubles) need not implement it; only the engine bridge does.
  /// </summary>
  IWarningAlertSink = interface(IInterface)
    ['{4A9E2C71-6D38-4B05-9F17-3C8A0E5B7D42}']
    procedure OnWarningAlert(AAlert: TTlsAlertDescription);
  end;

  /// <summary>
  /// An optional companion the driver reaches with Supports on the sink to report the
  /// negotiated protocol version once an epoch's keys are installed. Kept off IHandshakeSink
  /// so existing sinks (and their test doubles) need not implement it; only the engine bridge
  /// does, surfacing the version on ITlsEngine.NegotiatedVersion.
  /// </summary>
  IHandshakeVersionSink = interface(IInterface)
    ['{5E7A1C63-2D48-4F91-8B0A-6C3E5D7F1A29}']
    procedure OnVersionNegotiated(const AVersion: TTlsVersion);
  end;

  /// <summary>
  /// An optional companion the driver reaches with Supports on the sink to report that the
  /// handshake has parked for an out-of-band peer-certificate verdict (RFC 8446 - the
  /// deferred-verdict seam). The driver hands over the peer chain (leaf first, DER) and the
  /// expected host name; the host later resumes with the engine's SetCertificateVerdict.
  /// Kept off IHandshakeSink so existing sinks (and their test doubles) need not implement
  /// it; only the engine bridge does, when async certificate verdicts are enabled.
  /// </summary>
  IHandshakeVerdictSink = interface(IInterface)
    ['{6F1B4D28-7A93-4C05-9E16-2D7C4B8F0A31}']
    procedure OnCertificateVerdictNeeded(const AChain, AValidatedPath: TArray<TBytes>;
      const AHostName: string; const AStaple: TBytes);
  end;

  /// <summary>
  /// An optional companion the driver reaches with Supports on the sink to report read-only
  /// connection-info the negotiation resolved (currently the validated peer certificate
  /// chain). Kept off IHandshakeSink so existing sinks and their test doubles need not
  /// implement it; only the engine bridge does, surfacing it on ITlsEngine.
  /// </summary>
  IHandshakeConnectionInfoSink = interface(IInterface)
    ['{2B8D5F14-9C60-4A73-B1E8-4F0A7C6D3B95}']
    procedure OnPeerCertificateChain(const AChain: TArray<TBytes>);
    /// <summary>Reports the DER DistinguishedName certificate_authorities a peer named in its
    /// CertificateRequest (RFC 8446 4.2.4 / RFC 5246 7.4.4) - surfaced read-only on ITlsEngine.</summary>
    procedure OnRequestedCertificateAuthorities(const AAuthorities: TArray<TBytes>);
    /// <summary>Reports the negotiated cipher suite, named group (0 when none / non-(EC)DHE),
    /// whether the handshake resumed, and the SNI server_name in play (the host a client
    /// requested, as seen by a server; empty when none) - surfaced read-only on ITlsEngine.</summary>
    procedure OnConnectionParams(ACipherSuite, ANamedGroup: UInt16; AResumed: Boolean;
      const AServerName: string);
  end;

  /// <summary>
  /// An optional companion the driver reaches with Supports on the sink to report the
  /// Encrypted Client Hello outcome (RFC 9849). OnEchAccepted, OnEchGreased, OnEchBackend and
  /// OnEchServerRejected each record their status for connection info. OnEchRejected reports a
  /// client-side rejected handshake (sec. 6.1.6): it completed to the public_name and is now
  /// aborted with an ech_required alert, surfacing the retry_configs (empty if none) and whether
  /// this handshake was itself a retry.
  /// </summary>
  IEchStatusSink = interface(IInterface)
    ['{7C2E9A46-3B18-4D75-9E0C-5A1F6B84D2E3}']
    procedure OnEchAccepted;
    procedure OnEchGreased;
    procedure OnEchBackend;
    procedure OnEchServerRejected;
    procedure OnEchRejected(const ARetryConfigs: TBytes; AIsRetryAttempt: Boolean);
  end;

  /// <summary>
  /// Makes a TLS 1.3 client machine emit a supplied framed ClientHello verbatim instead of
  /// building one, for byte-exact replay of a recorded trace (RFC 8448 vectors, whose hello's
  /// extension order and padding differ from a built one). Reached with Supports on the machine;
  /// kept off IHandshakeMachine, and not reachable through a factory-built engine (which never
  /// exposes its machine). A verbatim ClientHello offers no PSK and no ECH, so the setter rejects
  /// a machine configured with either.
  /// </summary>
  ITls13ClientReplay = interface(IInterface)
    ['{7B0BCE0E-3CA0-47DA-A65F-76FC641C20E9}']
    procedure SetVerbatimClientHello(const AFramed: TBytes);
  end;

  /// <summary>
  /// Makes a TLS 1.3 server machine emit supplied HelloRetryRequest cookie / EncryptedExtensions /
  /// Certificate / CertificateVerify bytes verbatim, for byte-exact replay of a recorded trace (a
  /// produced CertificateVerify carries a random RSA-PSS salt, and the RFC 8448 EncryptedExtensions
  /// and cookie are bound to that trace). Reached with Supports on the machine; kept off
  /// IHandshakeMachine, and not reachable through a factory-built engine (which never exposes its
  /// machine). Each empty value leaves that message built normally.
  /// </summary>
  ITls13ServerReplay = interface(IInterface)
    ['{C8DC8971-07BB-4A26-9F0D-F6DADA0CC137}']
    procedure SetVerbatimRetryCookie(const ACookie: TBytes);
    procedure SetVerbatimEncryptedExtensions(const AFramed: TBytes);
    procedure SetVerbatimCertificate(const AFramed: TBytes);
    procedure SetVerbatimCertificateVerify(const AFramed: TBytes);
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
    /// Arms a read epoch to activate on the peer's next change_cipher_spec instead of
    /// immediately (the TLS 1.2 read-cipher switch, RFC 5246 7.1). The active read epoch
    /// stays put until that plaintext CCS is consumed, so a peer's plaintext alert sent
    /// before its CCS is read under the right epoch. TLS 1.3 installs the read epoch
    /// directly via InstallReadProtection; only TLS 1.2 read installs use this.
    /// </summary>
    procedure ArmReadProtectionOnChangeCipherSpec(const AProtection: IRecordProtection);
    /// <summary>
    /// Reverts the write epoch to plaintext, abandoning an installed early-data write
    /// protection when a HelloRetryRequest rejects offered 0-RTT (RFC 8446 4.2.10): the
    /// second ClientHello and the rest of the client's flight are sent in the clear.
    /// </summary>
    procedure RevertWriteToPlaintext;
    /// <summary>Applies the raw negotiated record_size_limit values (RFC 8449
    /// TLSInnerPlaintext caps); 0 means the extension was not negotiated.</summary>
    procedure SetRecordSizeLimit(AOutboundLimit, AInboundLimit: Int32);
    /// <summary>
    /// Enters the 0-RTT reject skip mode (RFC 8446 4.2.10): undecryptable early-data
    /// application records are dropped, up to AMaxBytes, until a record decrypts under
    /// the installed epoch. Used when the server rejects offered early data.
    /// </summary>
    procedure SetEarlyDataSkip(AMaxBytes: Int32);
    /// <summary>
    /// Caps outbound 0-RTT at the ticket's max_early_data (RFC 8446 4.2.10): the client
    /// sends at most AMaxBytes of early data; WriteEarlyData returns how much was accepted and
    /// the caller resends the rest as 1-RTT once the handshake completes. Set when the client
    /// opens the early-data write window.
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
