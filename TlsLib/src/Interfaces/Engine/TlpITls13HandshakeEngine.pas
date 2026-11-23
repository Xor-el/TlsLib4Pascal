{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpITls13HandshakeEngine;

{$I ..\..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpTlsAlert,
  TlpTlsError,
  TlpTlsConnectionInfo,
  TlpIKeySchedule,
  TlpITlsEngine,
  TlpExtensionContext,
  TlpTls13HandshakeOutput;

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
  /// and a mismatch ends the connection without an alert. LastError carries the alert a record
  /// engine would have sent (Origin Local), or Origin LocalWithoutAlert or Transport with a
  /// placeholder alert; the peer's alerts never reach it. Start it with StartHandshake (a
  /// client queues its ClientHello, a server waits for one; a second call raises). Single-threaded:
  /// the caller serializes access.
  /// </summary>
  ITls13HandshakeEngine = interface(ITlsCommonEngine)
    ['{7B79762F-492A-4660-A1BC-F281F99C3C28}']
    /// <summary>The level the next ProvideHandshakeData must use. It advances when the read
    /// secret is queued, before the host drains it; EarlyData is never reported.</summary>
    function ReadLevel: TTlsEpoch;
    /// <summary>Whether a server created to pause is parked at its first ClientHello, which it
    /// has validated (ECH decrypted) but not yet answered. The call that parks returns Advanced
    /// with a ClientHelloReceived event; until ContinueAfterClientHello the engine buffers further
    /// input and queues nothing. Always False on a client and on a server created without the
    /// pause.</summary>
    function AwaitingClientHello: Boolean;
    /// <summary>The server name the parked ClientHello offered, empty when it offered none or
    /// nothing is parked. It is unauthenticated, and the outer ClientHello's when ECH was not
    /// accepted.</summary>
    function OfferedServerName: string;
    /// <summary>Answers the parked ClientHello. AReplies holds one reply body for each registered
    /// server host extension the client offered (read with ITlsHostExtensionResults) that the host
    /// wants sent, wherever that extension rides; an offered extension with no reply is not sent.
    /// A non-empty AResumptionScope, at most 32 bytes, becomes this engine's own scope: tickets are
    /// accepted and sealed under it combined with the configuration's. A misuse (a reply for an
    /// extension that was not offered or twice, a body over 65535 bytes, an overlong scope) raises
    /// EArgumentTlsLibException and leaves the engine parked and usable. A no-op when not parked,
    /// once terminal, and on a client. Raises EInvalidOperationTlsLibException when called from
    /// inside a handshake callback.</summary>
    procedure ContinueAfterClientHello(const AReplies: TArray<TTlsHostExtensionReply>;
      const AResumptionScope: TBytes);
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
    function NextOutput(out AOutput: TTls13HandshakeOutput): Boolean;
  end;

implementation

end.
