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
  TlpISigningKey,
  TlpImportedCredential,
  TlpSecretBuffer,
  TlpICryptoProvider,
  TlpIPkixProvider;

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
    /// <summary>The stapled OCSP response (DER) to send for this leaf: the callback's result
    /// when a callback is set (it refreshes an expiring staple), else the static OcspStaple;
    /// empty declines stapling.</summary>
    function CurrentOcspStaple: TBytes;
    /// <summary>A credential from a certificate chain (a PEM block/bundle, a single DER
    /// certificate or a PKCS#7 bundle, leaf first) and an unencrypted private key (PKCS#8,
    /// PKCS#1 or SEC1, DER or PEM), each loaded and normalized through the given providers.
    /// No OCSP staple: set OcspStaple / OcspStapleCallback on the result to staple.</summary>
    class function Load(const ACrypto: ICryptoProvider; const APkix: IPkixProvider;
      const ACertificateChainData, APrivateKeyData: TBytes): TTlsCredential;
      overload; static;
    /// <summary>As above, decrypting an encrypted private key with APassword.</summary>
    class function Load(const ACrypto: ICryptoProvider; const APkix: IPkixProvider;
      const ACertificateChainData, APrivateKeyData: TBytes;
      const APassword: string): TTlsCredential; overload; static;
    /// <summary>A credential imported from a PKCS#12 (.pfx/.p12) blob decrypted with APassword:
    /// leaf + intermediates as the chain and the enclosed private key. Fails closed on a wrong
    /// password, bad MAC or malformed store (typed exception). No OCSP staple.</summary>
    class function LoadPkcs12(const ACrypto: ICryptoProvider; const AData: TBytes;
      const APassword: string): TTlsCredential; static;
  end;

  /// <summary>How a server treats client-certificate authentication (RFC 8446 4.3.2 /
  /// RFC 5246 7.4.4): None never requests one, Requested asks but tolerates a client
  /// that sends none, Required aborts when the client presents no certificate.</summary>
  TClientAuthMode = (None, Requested, Required);

  /// <summary>How a client treats server-certificate verification when it resumes a session:
  /// ReuseOriginal (the default) reuses the original handshake's authentication without
  /// re-checking (RFC 8446 2.2); Reverify re-runs the certificate verifier against the stored
  /// peer chain, for a stricter posture that re-checks a resumed server against current trust.
  /// Sessions are scoped per configuration (see WithSessionCache), so this does not govern
  /// cross-configuration resumption; it re-checks the sessions this configuration, or a scope it
  /// explicitly shares, stored. Under Hard revocation with no live-revocation verdict a Reverify
  /// client declines resumption to a full handshake, since a resume carries no staple to check.</summary>
  TResumeVerification = (ReuseOriginal, Reverify);

  /// <summary>How a TLS 1.2 server treats a ClientHello that resumes a session established without
  /// extended_master_secret when the hello does not offer it either (RFC 7627 5.3). Decline, the
  /// default, runs a full handshake instead; Abort ends the handshake with handshake_failure;
  /// Resume performs the legacy abbreviated handshake, which RFC 7627 5.4 leaves without secure
  /// renegotiation or tls-unique (both already refused). Decline and Abort also stop issuing
  /// resumable sessions from a non-EMS full handshake, so Abort differs from Decline only on a
  /// session minted elsewhere (before an upgrade, or by a node sharing the ticket keys or store).
  /// An EMS session offered without EMS always aborts, and a non-EMS session offered with EMS
  /// always declines (RFC 7627 5.3), whatever this is set to. Moot when extended_master_secret is
  /// required.</summary>
  TNonEmsResumption = (Decline, Abort, Resume);

  /// <summary>A read-only snapshot of the ClientHello facts a server credential resolver may
  /// select on (SNI virtual hosting). ServerName is the raw SNI host_name (RFC 6066), empty
  /// when the client sent none; the arrays are the client's offers verbatim as IANA wire
  /// codepoints (SignatureSchemes, CipherSuites, SupportedGroups) or protocol-name octets (Alpn).
  /// ProtocolVersion is the version of the server machine performing the lookup.</summary>
  TTlsClientHelloInfo = record
    ServerName: string;
    SignatureSchemes: TArray<UInt16>;
    AlpnProtocols: TArray<TBytes>;
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

function TTlsCredential.CurrentOcspStaple: TBytes;
begin
  if Assigned(OcspStapleCallback) then
    Result := OcspStapleCallback
  else
    Result := OcspStaple;
end;

class function TTlsCredential.Load(const ACrypto: ICryptoProvider;
  const APkix: IPkixProvider; const ACertificateChainData,
  APrivateKeyData: TBytes): TTlsCredential;
var
  LCredential: TTlsCredential;
begin
  LCredential.CertificateChain := APkix.Certificates.LoadChain(ACertificateChainData);
  LCredential.PrivateKey := ACrypto.Signing.ImportSigningKey(APrivateKeyData, nil);
  Result := LCredential;
end;

class function TTlsCredential.Load(const ACrypto: ICryptoProvider;
  const APkix: IPkixProvider; const ACertificateChainData, APrivateKeyData: TBytes;
  const APassword: string): TTlsCredential;
var
  LCredential: TTlsCredential;
begin
  LCredential.CertificateChain := APkix.Certificates.LoadChain(ACertificateChainData);
  LCredential.PrivateKey := ACrypto.Signing.ImportSigningKey(APrivateKeyData,
    TSecretBuffer.FromString(APassword));
  Result := LCredential;
end;

class function TTlsCredential.LoadPkcs12(const ACrypto: ICryptoProvider;
  const AData: TBytes; const APassword: string): TTlsCredential;
var
  LImported: TImportedCredential;
  LCredential: TTlsCredential;
begin
  LImported := ACrypto.Signing.ImportPkcs12(AData, TSecretBuffer.FromString(APassword));
  LCredential.CertificateChain := LImported.CertificateChain;
  LCredential.PrivateKey := LImported.PrivateKey;
  Result := LCredential;
end;

end.
