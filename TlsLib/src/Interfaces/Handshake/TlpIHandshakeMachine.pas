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
  TlpHandshakeMessage,
  TlpHandshakeEffect;

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
    /// <summary>Exported keying material over the established secrets (RFC 8446 7.5 / RFC
    /// 5705). Empty for a machine/version that has not yet derived its secrets.</summary>
    function ExportKeyingMaterial(const ALabel: string; const AContext: TBytes;
      AUseContext: Boolean; ALength: Int32): TBytes;
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
    procedure OnCertificateVerdictNeeded(const AChain: TArray<TBytes>;
      const AHostName: string);
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

implementation

end.
