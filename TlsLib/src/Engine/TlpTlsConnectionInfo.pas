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
  /// The read-only summary of a connection's negotiated facts: the negotiated protocol
  /// version, the selected ALPN protocol (empty when none), the server name in play, the
  /// peer's stapled OCSP response (DER, empty when none), the validated peer certificate
  /// chain (leaf first, DER; empty when the peer presented none. On a resumed handshake
  /// this is the chain verified when the session was issued, carried in the ticket and not
  /// re-verified here), the DER DistinguishedName certificate_authorities the peer requested,
  /// the negotiated cipher suite and named group (IANA codes; the group is 0 for a
  /// non-(EC)DHE key exchange), whether the handshake was resumed, and the Encrypted Client
  /// Hello outcome (RFC 9849: NotOffered, Greased, Accepted, Rejected, or Backend) with its
  /// reject details. ServerName has two readers: through a Tier-2 stream it is the client's
  /// construction host (IP literals included; the stream overlays it), read straight off the
  /// engine it is the SNI host_name the handshake carried (empty when none was sent). It is a
  /// snapshot after the handshake; reading it before the handshake completes yields the zero
  /// values.
  /// </summary>
  TTlsConnectionInfo = record
    NegotiatedVersion: TTlsVersion;
    AlpnProtocol: string;
    ServerName: string;
    PeerOcspStaple: TBytes;
    PeerCertificates: TArray<TBytes>;
    /// The DER DistinguishedName certificate_authorities the peer named in its CertificateRequest
    /// (RFC 8446 4.2.4 / RFC 5246 7.4.4); empty when none was requested or named.
    RequestedCertificateAuthorities: TArray<TBytes>;
    CipherSuite: UInt16;
    NamedGroup: UInt16;
    Resumed: Boolean;
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
