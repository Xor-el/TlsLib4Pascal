{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpTlsPresets;

{$I ..\Include\TlsLib.inc}

interface

uses
  TlpTlsVersion,
  TlpICryptoProvider,
  TlpIPkixProvider,
  TlpNegotiationTypes,
  TlpCipherSuiteRegistry,
  TlpSignatureSchemeRegistry,
  TlpNamedGroups,
  TlpCertificateLimits,
  TlpITlsConfigBuilder,
  TlpTlsConfigBuilder,
  TlpTlsLibExceptions;

resourcestring
  SNilCryptoProvider = 'a crypto provider is required (pass a provider, not nil)';

type
  /// <summary>
  /// The named security profiles, ordered by how much reach they trade for hardening.
  /// Compatible is the broad default, offering TLS 1.3 and the hardened TLS 1.2 profile
  /// (ECDHE + AEAD + Extended Master Secret); Hardened is TLS 1.3 only with the
  /// post-quantum hybrid group preferred; Strict is TLS 1.3 only over a fixed group
  /// allowlist (X25519 and the PQ hybrid) with tight certificate limits. The names
  /// describe posture rather than an era, so their contents can track evolving best
  /// practice without the labels going stale. Each returns a still-mutable builder to
  /// which the caller adds a trust source or credential.
  /// </summary>
  TTlsPresets = class sealed(TObject)
  strict private
    class function Base(const ACryptoProvider: ICryptoProvider): TTlsConfigProfile; static;
  public
    class function Compatible(const ACryptoProvider: ICryptoProvider;
      const APkixProvider: IPkixProvider): ITlsConfigBuilder; static;
    class function Hardened(const ACryptoProvider: ICryptoProvider;
      const APkixProvider: IPkixProvider): ITlsConfigBuilder; static;
    class function Strict(const ACryptoProvider: ICryptoProvider;
      const APkixProvider: IPkixProvider): ITlsConfigBuilder; static;
  end;

implementation

{ TTlsPresets }

class function TTlsPresets.Base(const ACryptoProvider: ICryptoProvider): TTlsConfigProfile;
begin
  if ACryptoProvider = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilCryptoProvider);
  // the presets decide the shared, endpoint-neutral defaults as data, then hand a chooser
  // seeded with them back to the caller, who narrows to .Client or .Server
  Result := TTlsConfigProfile.Default;
  Result.CipherSuites := TCipherSuiteRegistry.CreateDefault(ACryptoProvider);
  Result.SignatureSchemes := TSignatureSchemeRegistry.CreateDefault;
  Result.NamedGroups := TNamedGroups.CreateDefaultRegistry(ACryptoProvider);
  Result.SupportedVersions := TArray<UInt16>.Create(TlsWireVersionTls13);
end;

class function TTlsPresets.Compatible(const ACryptoProvider: ICryptoProvider;
  const APkixProvider: IPkixProvider): ITlsConfigBuilder;
var
  LProfile: TTlsConfigProfile;
begin
  LProfile := Base(ACryptoProvider);
  // the broad default offers TLS 1.3 and the hardened TLS 1.2 suites over one registry
  LProfile.CipherSuites := TCipherSuiteRegistry.CreateDualVersion(ACryptoProvider);
  LProfile.SupportedVersions := TArray<UInt16>.Create(TlsWireVersionTls13,
    TlsWireVersionTls12);
  // X25519 first, then the hybrid and the NIST curves (the hybrid is 1.3-only)
  LProfile.PreferredGroups := TArray<UInt16>.Create(
    TNamedGroupCatalog.X25519, TNamedGroupCatalog.X25519MlKem768,
    TNamedGroupCatalog.SecP256r1MlKem768, TNamedGroupCatalog.Secp256r1,
    TNamedGroupCatalog.Secp384r1, TNamedGroupCatalog.Secp521r1);
  Result := TTlsConfigBuilder.CreateFromProfile(ACryptoProvider, APkixProvider, LProfile);
end;

class function TTlsPresets.Hardened(const ACryptoProvider: ICryptoProvider;
  const APkixProvider: IPkixProvider): ITlsConfigBuilder;
var
  LProfile: TTlsConfigProfile;
begin
  LProfile := Base(ACryptoProvider);
  // the post-quantum hybrid is preferred, then classical X25519 and P-256
  LProfile.PreferredGroups := TArray<UInt16>.Create(
    TNamedGroupCatalog.X25519MlKem768, TNamedGroupCatalog.SecP256r1MlKem768,
    TNamedGroupCatalog.X25519, TNamedGroupCatalog.Secp256r1);
  // request an OCSP staple so the revocation pipeline has status to act on and any must-staple
  // is enforceable; the posture stays soft-fail, so this never breaks a server that does not staple
  LProfile.RequestOcspStapling := True;
  // the certificate strength floors and signature schemes stay at the web-PKI-compatible defaults:
  // the RSA floor covers public CAs, and PKCS#1-v1.5 codepoints are certificate-only in TLS 1.3
  // (RFC 8446 4.2.3), while the handshake CertificateVerify is already PSS-only by construction, so
  // there is nothing to tighten without refusing the servers a hardened client must still reach
  Result := TTlsConfigBuilder.CreateFromProfile(ACryptoProvider, APkixProvider, LProfile);
end;

class function TTlsPresets.Strict(const ACryptoProvider: ICryptoProvider;
  const APkixProvider: IPkixProvider): ITlsConfigBuilder;
var
  LProfile: TTlsConfigProfile;
  LLimits: TCertificateChainLimits;
begin
  LProfile := Base(ACryptoProvider);
  // a fixed allowlist: only X25519 and the post-quantum hybrid
  LProfile.PreferredGroups := TArray<UInt16>.Create(
    TNamedGroupCatalog.X25519MlKem768, TNamedGroupCatalog.X25519);
  // a hardened profile expects a short chain of compact certificates
  LLimits.MaxCertificateLength := 1 shl 14;
  LLimits.MaxTotalChainLength := 1 shl 15;
  LProfile.CertificateChainLimits := LLimits;
  // the strictest posture defaults resumption off; a caller may re-enable it with no guard
  LProfile.Resumption := False;
  // request an OCSP staple so a caller can opt into WithRevocation(Hard) without every handshake
  // failing for a missing staple; the posture stays soft-fail (hard-fail OCSP breaks connectivity
  // to the many servers that do not staple), and strength floors stay web-PKI-compatible as in
  // Hardened. Public-key pinning is operator-supplied (WithCertificatePinning): a preset cannot
  // know a deployment's pins.
  LProfile.RequestOcspStapling := True;
  Result := TTlsConfigBuilder.CreateFromProfile(ACryptoProvider, APkixProvider, LProfile);
end;

end.
