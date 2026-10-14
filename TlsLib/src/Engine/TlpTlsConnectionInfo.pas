{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpTlsConnectionInfo;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpTlsVersion,
  TlpEchConfig;

type
  /// <summary>Why 0-RTT early data was or was not used on a connection (RFC 9846 4.3.10): the
  /// first reason in this order that applies is reported; ReplayDetected is the anti-replay
  /// decline (RFC 9846 8.2).</summary>
  TEarlyDataReason = (Disabled, Accepted, ProtocolVersion, PeerDeclined, NoSessionOffered,
    SessionNotResumed, UnsupportedForSession, HelloRetryRequest, AlpnMismatch, TicketAgeSkew,
    ReplayDetected);

  /// <summary>
  /// A read-only snapshot of a connection's negotiated facts; the fields fill in as the
  /// handshake resolves them, so a field not yet resolved reads as its zero value. On a resumed
  /// handshake the peer certificate chain is the one carried in the ticket (presented when the
  /// session was issued). ServerName has two readers: through a stream it is the client's
  /// construction host (IP literals included; the stream overlays it), read straight off the
  /// engine it is the SNI host_name the handshake carried.
  /// </summary>
  TTlsConnectionInfo = record
    /// The negotiated protocol version (zero until the version is selected).
    NegotiatedVersion: TTlsVersion;
    /// The selected ALPN protocol name (RFC 7301 opaque octets; see TAlpnProtocols.TryToText for the
    /// text of an ASCII name); empty when none was negotiated.
    AlpnProtocol: TBytes;
    /// The server name in play, empty when none (see the summary for its two readers: the client's
    /// construction host through a stream, or the SNI host_name read straight off the engine).
    ServerName: string;
    /// The peer's stapled OCSP response (DER); empty when none.
    PeerOcspStaple: TBytes;
    /// The peer certificate chain as presented (leaf first, DER; empty when the peer presented none).
    /// On a resumed handshake this is the chain stored with the session.
    PeerCertificates: TArray<TBytes>;
    /// The leaf-first path the built-in pipeline validated on this connection (the leaf's issuer at
    /// index 1 and the anchor where nameable). Empty when no path was validated here: under
    /// InsecureSkipVerify, before the handshake, when the peer sent none, and on a resumption
    /// unless the client re-verified the stored chain (ResumeVerification = Reverify).
    ValidatedPath: TArray<TBytes>;
    /// The DER DistinguishedName certificate_authorities the peer named in its CertificateRequest
    /// (RFC 9846 4.3.4 / RFC 5246 7.4.4); empty when none was requested or named.
    RequestedCertificateAuthorities: TArray<TBytes>;
    /// The signature scheme (IANA code) that verified the peer's CertificateVerify or ServerKeyExchange; 0
    /// when the peer did not sign. On a resumption, the scheme of the original handshake.
    PeerSignatureScheme: UInt16;
    /// Whether a HelloRetryRequest was used (client: received; server: sent, including the stateless-cookie path).
    HelloRetryRequest: Boolean;
    /// Why 0-RTT early data was or was not used on this connection.
    EarlyDataReason: TEarlyDataReason;
    /// Server, TLS 1.3 ticket resumption: the age the client reports for the ticket less the server's own, in whole seconds.
    TicketAgeSkew: Int32;
    /// The signature_algorithms (IANA codes) the peer's CertificateRequest listed; empty when none was requested.
    RequestedSignatureSchemes: TArray<UInt16>;
    /// The identity of the pre-shared key that authenticated the connection: the TLS 1.2 PSK (RFC 4279) or
    /// the TLS 1.3 external PSK as configured (RFC 9258); empty when it used certificates.
    PskIdentity: TBytes;
    /// The negotiated cipher suite (IANA code).
    CipherSuite: UInt16;
    /// The negotiated named group (IANA code); 0 for a non-(EC)DHE key exchange. On a TLS 1.2 resumption, the
    /// group of the session's original handshake.
    NamedGroup: UInt16;
    /// Whether the handshake was resumed (abbreviated); an external PSK is not a resumption.
    Resumed: Boolean;
    /// Whether the session used Extended Master Secret (RFC 7627): the negotiated value on TLS 1.2,
    /// always True on TLS 1.3. Without it a TLS 1.2 exporter is unavailable (RFC 7627 5.4).
    ExtendedMasterSecret: Boolean;
    /// Whether 0-RTT early data was accepted (RFC 9846 4.3.10): a client's offer the server accepted, or
    /// a server that opened the early-data read window. False when none was offered or it was rejected.
    EarlyDataAccepted: Boolean;
    /// The Encrypted Client Hello outcome (RFC 9849); see TEchStatus.
    EchStatus: TEchStatus;
    /// On a client ECH reject (RFC 9849 6.1.6): the server's retry_configs (empty when none), whether
    /// this handshake was itself a retry (the one-retry cap), and whether this endpoint aborted with
    /// ech_required over its own rejected offer (never True on a server, whose Rejected is benign).
    EchRetryConfigs: TBytes;
    EchIsRetryAttempt: Boolean;
    EchRejectAborted: Boolean;
  end;

implementation

end.
