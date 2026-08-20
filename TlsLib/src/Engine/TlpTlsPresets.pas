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
  TlpNegotiationTypes,
  TlpCipherSuiteRegistry,
  TlpSignatureSchemeRegistry,
  TlpNamedGroups,
  TlpCertificateLimits,
  TlpITlsConfigBuilder,
  TlpTlsConfigBuilder;

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
    class function Base(const AProvider: ICryptoProvider): TTlsConfigBuilder; static;
  public
    class function Compatible(const AProvider: ICryptoProvider): ITlsConfigBuilder; static;
    class function Hardened(const AProvider: ICryptoProvider): ITlsConfigBuilder; static;
    class function Strict(const AProvider: ICryptoProvider): ITlsConfigBuilder; static;
  end;

implementation

{ TTlsPresets }

class function TTlsPresets.Base(
  const AProvider: ICryptoProvider): TTlsConfigBuilder;
begin
  // the presets seed the shared defaults through the concrete builder, then hand back
  // the endpoint selector; the caller narrows to .Client or .Server
  Result := TTlsConfigBuilder.Create(AProvider);
  Result.WithCipherSuites(TCipherSuiteRegistry.CreateDefault(AProvider));
  Result.WithSignatureSchemes(TSignatureSchemeRegistry.CreateDefault);
  Result.WithNamedGroups(TNamedGroups.CreateDefaultRegistry(AProvider));
  Result.WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls13));
end;

class function TTlsPresets.Compatible(
  const AProvider: ICryptoProvider): ITlsConfigBuilder;
var
  LBuilder: TTlsConfigBuilder;
begin
  LBuilder := Base(AProvider);
  // the broad default offers TLS 1.3 and the hardened TLS 1.2 suites over one registry
  LBuilder.WithCipherSuites(TCipherSuiteRegistry.CreateDualVersion(AProvider));
  LBuilder.WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls13,
    TlsWireVersionTls12));
  // X25519 first, then the hybrid and the NIST curves (the hybrid is 1.3-only)
  LBuilder.WithPreferredGroups(TArray<UInt16>.Create(
    TNamedGroupCatalog.X25519, TNamedGroupCatalog.X25519MlKem768,
    TNamedGroupCatalog.Secp256r1, TNamedGroupCatalog.Secp384r1,
    TNamedGroupCatalog.Secp521r1));
  Result := LBuilder;
end;

class function TTlsPresets.Hardened(
  const AProvider: ICryptoProvider): ITlsConfigBuilder;
var
  LBuilder: TTlsConfigBuilder;
begin
  LBuilder := Base(AProvider);
  // the post-quantum hybrid is preferred, then classical X25519 and P-256
  LBuilder.WithPreferredGroups(TArray<UInt16>.Create(
    TNamedGroupCatalog.X25519MlKem768, TNamedGroupCatalog.X25519,
    TNamedGroupCatalog.Secp256r1));
  Result := LBuilder;
end;

class function TTlsPresets.Strict(
  const AProvider: ICryptoProvider): ITlsConfigBuilder;
var
  LBuilder: TTlsConfigBuilder;
  LLimits: TCertificateChainLimits;
begin
  LBuilder := Base(AProvider);
  // a fixed allowlist: only X25519 and the post-quantum hybrid
  LBuilder.WithPreferredGroups(TArray<UInt16>.Create(
    TNamedGroupCatalog.X25519MlKem768, TNamedGroupCatalog.X25519));
  // a hardened profile expects a short chain of compact certificates
  LLimits.MaxChainLength := 5;
  LLimits.MaxCertificateLength := 1 shl 15;
  LLimits.MaxTotalChainLength := 1 shl 16;
  LBuilder.WithCertificateChainLimits(LLimits);
  // the strictest posture defaults resumption off; a caller may re-enable it with no guard
  LBuilder.WithResumption(False);
  // revocation stays soft-fail even here (the architecture's locked default): hard-fail
  // OCSP breaks connectivity to the many servers that do not staple, so a caller opts into
  // it explicitly with WithRevocation(Hard). Public-key pinning is likewise operator-supplied
  // (WithCertificatePinning), since a preset cannot know a deployment's pins.
  Result := LBuilder;
end;

end.
