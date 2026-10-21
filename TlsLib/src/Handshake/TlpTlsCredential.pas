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
  TlpArrayUtilities,
  TlpTlsVersion,
  TlpISigningKey,
  TlpImportedCredential,
  TlpSecretBuffer,
  TlpICryptoProvider,
  TlpIPkixProvider,
  TlpPkixDomainTypes,
  TlpCryptoDomainTypes;

type
  /// <summary>Whether a credential can sign a handshake as presented. Consistent when it can;
  /// otherwise the first fault found: no certificate, no key, a leaf whose keyUsage forbids
  /// digitalSignature (RFC 5280 4.2.1.3), an RSA key over an id-RSASSA-PSS leaf (RFC 9846
  /// 4.3.3), a key that cannot export its public half, a leaf that is not a well-formed
  /// certificate, or a key that is not the leaf's.</summary>
  TCredentialConsistency = (Consistent, ChainEmpty, KeyMissing, LeafCannotSign, LeafKeyRsaPss,
    KeyNotExportable, LeafMalformed, KeyLeafMismatch);

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
    /// <summary>A copy that owns its certificate chain and staple bytes; the signing key and the
    /// staple callback are shared with this credential.</summary>
    function Clone: TTlsCredential;
    /// <summary>Whether this credential can sign a handshake as presented, judged by
    /// ACertificates without a signing operation. The leaf and the key's public half are
    /// compared by key value, so equal keys that differ in encoding match. Never raises on a
    /// malformed leaf; a key that cannot export its public half fails closed.</summary>
    function Consistency(const ACertificates: ICertificateInspector): TCredentialConsistency;
    /// <summary>A credential from a certificate chain (a PEM block/bundle, a single DER
    /// certificate or a PKCS#7 bundle, leaf first) and a private key (PKCS#8, PKCS#1 or SEC1, DER
    /// or PEM; an encrypted key is decrypted under the empty passphrase), each loaded and
    /// normalized through the given providers.
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

  /// <summary>How a server treats client-certificate authentication (RFC 9846 4.4.2 /
  /// RFC 5246 7.4.4): None never requests one, Requested asks but tolerates a client
  /// that sends none, Required aborts when the client presents no certificate.</summary>
  TClientAuthMode = (None, Requested, Required);

  /// <summary>How a client treats server-certificate verification when it resumes a session:
  /// ReuseOriginal (the default) keeps the original authentication (inferred from RFC 9846 2.2);
  /// Reverify re-runs the certificate verifier against the stored peer chain before the session is
  /// offered. See WithResumeVerification.</summary>
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
  /// CertificateSignatureSchemes is the client's signature_algorithms_cert, else its
  /// signature_algorithms; a chain with a certificate (other than a self-signed one) signed with
  /// MD5, or with SHA-1 not listed here, is refused (RFC 9846 4.5.1.2; MD5 inferred from 4.5.1.3).
  /// ProtocolVersion is the version of the server machine performing the lookup.</summary>
  TTlsClientHelloInfo = record
    ServerName: string;
    SignatureSchemes: TArray<UInt16>;
    CertificateSignatureSchemes: TArray<UInt16>;
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

function TTlsCredential.Clone: TTlsCredential;
begin
  Result := Self;
  Result.CertificateChain := TArrayUtilities.DeepCopy<Byte>(CertificateChain);
  Result.OcspStaple := System.Copy(OcspStaple);
end;

function TTlsCredential.Consistency(
  const ACertificates: ICertificateInspector): TCredentialConsistency;
var
  LLeaf, LKeyPublicKeyInfo: TBytes;
  LSchemes: TArray<TSignatureScheme>;
begin
  Result := TCredentialConsistency.Consistent;
  if System.Length(CertificateChain) = 0 then
  begin
    Result := TCredentialConsistency.ChainEmpty;
    Exit;
  end;
  if PrivateKey = nil then
  begin
    Result := TCredentialConsistency.KeyMissing;
    Exit;
  end;
  LLeaf := CertificateChain[0];
  // only a definite No refuses; an absent or unreadable keyUsage passes
  if ACertificates.KeyUsagePermits(LLeaf, TCertKeyUsage.DigitalSignature) = TCertAnswer.No then
  begin
    Result := TCredentialConsistency.LeafCannotSign;
    Exit;
  end;
  // an id-RSASSA-PSS leaf pairs only with rsa_pss_pss_*, which is not offered, key match or not
  LSchemes := PrivateKey.CapableSchemes;
  if (System.Length(LSchemes) > 0) and (LSchemes[0].KeyKind = TSignatureKeyKind.Rsa) and
    (ACertificates.KeyIsRsaPss(LLeaf) = TCertAnswer.Yes) then
  begin
    Result := TCredentialConsistency.LeafKeyRsaPss;
    Exit;
  end;
  // value-compare the key's public half with the leaf's, which also catches a mis-ordered chain
  LKeyPublicKeyInfo := PrivateKey.PublicKeyInfo;
  if System.Length(LKeyPublicKeyInfo) = 0 then
    Result := TCredentialConsistency.KeyNotExportable
  else if not ACertificates.IsWellFormed(LLeaf) then
    Result := TCredentialConsistency.LeafMalformed
  else if ACertificates.SamePublicKey(ACertificates.PublicKeyInfo(LLeaf), LKeyPublicKeyInfo) <>
    TCertAnswer.Yes then
    Result := TCredentialConsistency.KeyLeafMismatch;
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
