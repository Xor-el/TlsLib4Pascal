{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpTlsCredential;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpTlsVersion,
  TlpISigningKey;

type
  /// <summary>Supplies a server's pre-fetched stapled OCSP response (DER) for its leaf
  /// certificate, invoked per handshake when the client offered status_request. Returns
  /// an empty result to decline stapling. In-band only: it must not perform network I/O.</summary>
  TTlsOcspStapleCallback = function: TBytes of object;

  /// <summary>A complete proof-of-identity for either role: a certificate chain (leaf first,
  /// DER), the leaf's signing key, and an optional stapled OCSP response for that leaf. The
  /// key is the source of truth for which signature schemes
  /// it can sign with; the scheme actually used for CertificateVerify is negotiated per
  /// handshake against the peer's offer, so one RSA key can sign any of the rsa_pss_rsae_*
  /// variants the peer accepts. A client uses one for mutual TLS. A server staples OcspStaple
  /// (or the callback's result) for its leaf when the client offered status_request:
  /// OcspStapleCallback takes precedence over OcspStaple when set (it refreshes an expiring
  /// staple), and when both are empty no staple is sent.</summary>
  TTlsCredential = record
    CertificateChain: TArray<TBytes>;
    PrivateKey: ISigningKey;
    OcspStaple: TBytes;
    OcspStapleCallback: TTlsOcspStapleCallback;
    // zeroes the unmanaged OcspStapleCallback so no construction path leaves it garbage
    class operator Initialize({$IFDEF FPC}var{$ELSE}out{$ENDIF}
      ACredential: TTlsCredential);
  end;

  /// <summary>How a server treats client-certificate authentication (RFC 8446 4.3.2 /
  /// RFC 5246 7.4.4): None never requests one, Requested asks but tolerates a client
  /// that sends none, Required aborts when the client presents no certificate.</summary>
  TClientAuthMode = (None, Requested, Required);

  /// <summary>A read-only snapshot of the ClientHello facts a server credential resolver may
  /// select on (SNI virtual hosting). ServerName is the raw SNI host_name (RFC 6066), empty
  /// when the client sent none; the arrays are the client's offers verbatim as IANA wire
  /// codepoints (SignatureSchemes, CipherSuites, SupportedGroups) or protocol names (Alpn).
  /// ProtocolVersion is the version of the server machine performing the lookup.</summary>
  TTlsClientHelloInfo = record
    ServerName: string;
    SignatureSchemes: TArray<UInt16>;
    AlpnProtocols: TArray<string>;
    CipherSuites: TArray<UInt16>;
    SupportedGroups: TArray<UInt16>;
    ProtocolVersion: TTlsVersion;
  end;

implementation

class operator TTlsCredential.Initialize({$IFDEF FPC}var{$ELSE}out{$ENDIF}
  ACredential: TTlsCredential);
begin
  ACredential.OcspStapleCallback := nil;
end;

end.
