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
  /// <summary>
  /// A read-only snapshot of a connection's negotiated facts, taken after the handshake;
  /// reading it before the handshake completes yields the zero values. On a resumed handshake
  /// the peer certificate chain is the one carried in the ticket (presented when the session
  /// was issued). ServerName has two readers: through a stream it is the client's construction
  /// host (IP literals included; the stream overlays it), read straight off the engine it is
  /// the SNI host_name the handshake carried.
  /// </summary>
  TTlsConnectionInfo = record
    /// The negotiated protocol version (zero before the handshake completes).
    NegotiatedVersion: TTlsVersion;
    /// The selected ALPN protocol; empty when none was negotiated.
    AlpnProtocol: string;
    /// The server name in play, empty when none (see the summary for its two readers: the client's
    /// construction host through a stream, or the SNI host_name read straight off the engine).
    ServerName: string;
    /// The peer's stapled OCSP response (DER); empty when none.
    PeerOcspStaple: TBytes;
    /// The peer certificate chain as presented (leaf first, DER; empty when the peer presented none).
    /// On a resumed handshake this is the chain stored with the session.
    PeerCertificates: TArray<TBytes>;
    /// The leaf-first path the built-in pipeline validated on this connection (the leaf's issuer at
    /// index 1 and the anchor where nameable; the leaf alone under InsecureSkipVerify). Empty when no
    /// path was validated here: before the handshake, when the peer sent none, and on a resumption
    /// unless the client re-verified the stored chain (ResumeVerification = Reverify).
    ValidatedPath: TArray<TBytes>;
    /// The DER DistinguishedName certificate_authorities the peer named in its CertificateRequest
    /// (RFC 8446 4.2.4 / RFC 5246 7.4.4); empty when none was requested or named.
    RequestedCertificateAuthorities: TArray<TBytes>;
    /// The negotiated cipher suite (IANA code).
    CipherSuite: UInt16;
    /// The negotiated named group (IANA code); 0 for a non-(EC)DHE key exchange.
    NamedGroup: UInt16;
    /// Whether the handshake was resumed (abbreviated).
    Resumed: Boolean;
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
