{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpITlsHandshakeEngine;

{$I ..\..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpTlsAlert,
  TlpTlsError,
  TlpTlsConnectionInfo,
  TlpIKeySchedule,
  TlpITlsEngine,
  TlpHandshakeOutput;

type
  /// <summary>
  /// A TLS 1.3 handshake whose host owns record protection and the key lifecycle (a transport that
  /// protects its own records, such as the one RFC 9001 describes). The engine exchanges handshake
  /// messages per encryption level and exports traffic secrets; it holds no traffic keys, so it
  /// sends no change_cipher_spec, no EndOfEarlyData, no KeyUpdate and no record_size_limit, offers
  /// an empty legacy_session_id, and neither sends nor receives alerts: a failure is reported
  /// through LastError, and the host maps it. Everything flows by pull: the host feeds the bytes
  /// of one level, then drains NextOutput (handshake bytes per level, the secrets to install, the
  /// end of the handshake) and NextEvent. No host extension or transport callback runs inside a
  /// call; the host inspects ALPN and extension bodies between input and output. The engine
  /// accepts a handshake that selects no ALPN protocol (a host that requires one fails the
  /// connection itself, with no_application_protocol), and bytes at the EarlyData level fail with
  /// unexpected_message. The ticket early-data limit the factory takes fixes the value tickets
  /// carry: 0 turns a server's 0-RTT off and leaves a client's check of received tickets off,
  /// and a mismatch ends the connection without an alert. Single-threaded:
  /// the caller serializes access.
  /// </summary>
  ITlsHandshakeEngine = interface(IInterface)
    ['{58A3D7C1-E94B-4B02-8D16-27F0B65C4A93}']
    /// <summary>Starts the handshake: a client queues its ClientHello; a server waits for one.
    /// Raises EInvalidOperationTlsLibException when called twice.</summary>
    procedure StartHandshake;
    /// <summary>Feeds handshake bytes the peer sent at ALevel, which must be the level the engine
    /// reads now (Plaintext until the first read secret, then the level of the latest Handshake or
    /// Application read secret). Bytes at any other level, or a handshake message that straddles a
    /// change of read level, fail with unexpected_message. Returns Advanced when it queued an
    /// output or an event, NeedMoreInput when it waits for more bytes, and Fatal once the engine
    /// is terminal.</summary>
    function ProvideHandshakeData(ALevel: TTlsEpoch; const AData: TBytes;
      AOffset, ALength: Int32): TTlsOutcome;
    /// <summary>Dequeues the next item for the host, in the order the handshake produced it;
    /// False when none is queued. After a failure with an alert, everything queued up to the last
    /// handshake bytes stays, plus every write secret queued after them; after any other failure
    /// nothing does. A secret is the host's from here on.</summary>
    function NextOutput(out AOutput: THandshakeOutput): Boolean;
    function NextEvent(out AEvent: ITlsEvent): Boolean;
    /// <summary>Resumes a handshake parked on a peer-certificate verdict; a no-op otherwise.</summary>
    procedure SetCertificateVerdict(AAccept: Boolean; AAlert: TTlsAlertDescription);
    /// <summary>Ends the connection because the transport under it failed; no alert is involved
    /// and resumable sessions are kept.</summary>
    procedure LatchTransportFailure(const AReason: string);
    function IsHandshaking: Boolean;
    function AwaitingCertificateVerdict: Boolean;
    function IsTerminal: Boolean;
    /// <summary>Why the engine is terminal. The alert is the one a record engine would have sent
    /// (Origin Local) or the peer's (never here); with Origin LocalWithoutAlert or Transport the
    /// alert is a placeholder.</summary>
    function LastError: TTlsError;
    function ConnectionInfo: TTlsConnectionInfo;
    function ExportKeyingMaterial(const ALabel: string;
      ALength: Int32): TBytes; overload;
    function ExportKeyingMaterial(const ALabel: string; const AContext: TBytes;
      ALength: Int32): TBytes; overload;
    function ExportEarlyKeyingMaterial(const ALabel: string; const AContext: TBytes;
      ALength: Int32): TBytes;
  end;

implementation

end.
