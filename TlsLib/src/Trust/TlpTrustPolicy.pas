{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpTrustPolicy;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpICryptoProvider,
  TlpIClock,
  TlpICertificateTrust,
  TlpCertificateLimits;

type
  /// <summary>
  /// The revocation-checking posture for the stapled OCSP response (RFC 6960),
  /// consumed in-band from the handshake - no network. The posture governs only how an
  /// unknown/indeterminate outcome is treated; a definitive, authenticated Revoked in
  /// hand is always honored (the certificate is rejected) under every posture. Soft (the
  /// default) accepts a missing or indeterminate staple; Hard rejects anything short of a
  /// current Good staple (bad_certificate_status_response); Off does not require a stapled
  /// OCSP response (a missing or indeterminate staple is accepted), but still rejects a
  /// definitive Revoked. Must-staple (RFC 7633) is enforced at the TLS layer regardless
  /// of this setting.
  /// </summary>
  TRevocationPosture = (Soft, Hard, Off);

  /// <summary>
  /// An augment-only peer-certificate check the caller supplies: it runs after the
  /// built-in pipeline (PKIX, revocation, endpoint identity, pinning) has already
  /// passed and can only additionally reject (return False) - it can never turn a
  /// rejected chain into an accepted one. AChain is the peer chain (leaf first, DER);
  /// AHostName is the expected host (empty on the server side). This is how a host
  /// framework's own verify hook is bridged without loosening our trust decision.
  /// </summary>
  TTlsCertificateVerifyCallback = function(const AChain: TArray<TBytes>;
    const AHostName: string): Boolean of object;

  /// <summary>
  /// The escape hatches that deliberately weaken or extend trust, grouped so they read
  /// as one loud, opt-in surface. InsecureSkipVerify makes an otherwise-untrusted chain
  /// pass (it bypasses PKIX, revocation, endpoint identity, and pinning) and must never
  /// ship in production - it exists for tests and pinned/self-signed development peers.
  /// VerifyCallback is the augment-only hook (it can only additionally reject). When both
  /// are set the callback still runs, so a caller can skip the built-in pipeline yet keep
  /// a bespoke reject rule.
  /// </summary>
  TDangerousTrust = record
    InsecureSkipVerify: Boolean;
    VerifyCallback: TTlsCertificateVerifyCallback;
    // zero the unmanaged method pointer so no construction path leaves it garbage
    class operator Initialize({$IFDEF FPC}var{$ELSE}out{$ENDIF}
      AOptions: TDangerousTrust);
  end;

  /// <summary>
  /// The asynchronous certificate-verdict setting. When Enabled, the engine runs its
  /// built-in trust pipeline synchronously (as always) and, only if that pipeline
  /// accepts the peer chain, parks the handshake and raises a CertificateReceived event
  /// so a host can decide out-of-band (e.g. live OCSP/CRL, an operator prompt) and resume
  /// with SetCertificateVerdict. This is augment-only: the host verdict can only
  /// additionally reject, never resurrect a chain the pipeline already rejected. The park
  /// is fail-closed - no verdict, a rejection, or an expired deadline aborts the handshake.
  /// DeadlineMs is advisory to the driver (the sans-IO engine owns no timer); 0 means the
  /// host imposes no engine-suggested deadline. Disabled (the default) keeps the verdict
  /// inline.
  /// </summary>
  TAsyncCertificateVerdict = record
    Enabled: Boolean;
    DeadlineMs: Cardinal;
  end;

  /// <summary>
  /// The minimum-strength floors a peer certificate chain's keys must meet, applied to the
  /// leaf and intermediates (a configured trust anchor is exempt). MinRsaModulusBits sets the
  /// smallest accepted RSA modulus; MaxRsaModulusBits caps it as a verify-cost defence (0 = no
  /// cap); AllowedEcCurves is the accepted ECDSA named-group codes (empty = any curve the
  /// provider recognises); AllowEdDsa admits Ed25519/Ed448 keys. The chain-signature algorithm
  /// check (peer chain signed only with an advertised scheme, and the MD5/SHA-1 rejection RFC
  /// 8446 4.4.2 mandates) is always applied and is not gated by this record.
  /// </summary>
  TCertificateStrengthPolicy = record
    MinRsaModulusBits: Int32;
    MaxRsaModulusBits: Int32;
    AllowedEcCurves: TArray<UInt16>;
    AllowEdDsa: Boolean;
    /// <summary>The default floors, applied by every preset: RSA 2048..8192, the NIST P-curves,
    /// EdDSA admitted.</summary>
    class function Defaults: TCertificateStrengthPolicy; static;
  end;

  /// <summary>
  /// The trust parameters the engine gathers once from the frozen config and hands a
  /// verifier source to build the server-certificate verifier for a connection. The clock
  /// and posture are carried here so a source constructs its verifier with them injected
  /// (the built-in and the OS-native delegate alike), rather than receiving a pre-built
  /// verifier that could not see the connection's clock or revocation posture. SPKI pinning
  /// is applied by a decorator over the source output, so no pins appear here.
  /// </summary>
  TServerTrustContext = record
    Provider: ICryptoProvider;
    Clock: ITlsClock;
    TrustStore: ITrustAnchorStore;
    CheckHostName: Boolean;
    ChainLimits: TCertificateChainLimits;
    RevocationPosture: TRevocationPosture;
    Dangerous: TDangerousTrust;
    AsyncVerdictEnabled: Boolean;
    Intermediates: TArray<TBytes>;
    StrengthPolicy: TCertificateStrengthPolicy;
    AdvertisedSignatureSchemes: TArray<UInt16>;
  end;

  /// <summary>
  /// The trust parameters the engine hands a source to build the client-certificate verifier
  /// for an mTLS connection. TrustStore is the configured client-CA anchor set; there is no
  /// host identity to match (a client certificate is never checked against a name) and no
  /// stapled OCSP (a client certificate is not stapled). An OS-native delegate treats TrustStore
  /// as an exclusive trust root, so a client is authenticated only against these anchors, never
  /// the OS/public-web-PKI roots.
  /// </summary>
  TClientTrustContext = record
    Provider: ICryptoProvider;
    Clock: ITlsClock;
    TrustStore: ITrustAnchorStore;
    ChainLimits: TCertificateChainLimits;
    RevocationPosture: TRevocationPosture;
    Dangerous: TDangerousTrust;
    AsyncVerdictEnabled: Boolean;
    Intermediates: TArray<TBytes>;
    StrengthPolicy: TCertificateStrengthPolicy;
    AdvertisedSignatureSchemes: TArray<UInt16>;
  end;

implementation

class operator TDangerousTrust.Initialize({$IFDEF FPC}var{$ELSE}out{$ENDIF}
  AOptions: TDangerousTrust);
begin
  AOptions.InsecureSkipVerify := False;
  AOptions.VerifyCallback := nil;
end;

class function TCertificateStrengthPolicy.Defaults: TCertificateStrengthPolicy;
begin
  Result.MinRsaModulusBits := 2048;
  Result.MaxRsaModulusBits := 8192;
  // secp256r1 / secp384r1 / secp521r1 IANA supported-group codes
  Result.AllowedEcCurves := TArray<UInt16>.Create($0017, $0018, $0019);
  Result.AllowEdDsa := True;
end;

end.
