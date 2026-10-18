{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpOSSystemTrust;

{$I ..\..\TlsLib\src\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpArrayUtilities,
  TlpTlsLibExceptions,
  TlpIPkixProvider,
  TlpICertificateTrust,
  TlpITrustAnchorStore,
  TlpICertificateVerifierSource,
  TlpITlsConfig,
  TlpTrustPolicy,
  TlpSignatureSchemeRegistry,
  TlpSystemTrustBase,
  TlpIPlatformChainEngine,
  TlpOSDelegateVerifier,
  TlpOSLiveRevocation,
  TlpSystemTrustExceptions
{$IF DEFINED(TLSLIB_MSWINDOWS)}
  , TlpWindowsSystemTrust
{$ELSEIF DEFINED(TLSLIB_IOS) OR DEFINED(TLSLIB_MACOS)}
  , TlpAppleSystemTrust
{$ELSEIF DEFINED(TLSLIB_ANDROID)}
  , TlpAndroidSystemTrust
{$ELSEIF DEFINED(TLSLIB_LINUX) OR DEFINED(TLSLIB_BSD) OR DEFINED(TLSLIB_SOLARIS)}
  , TlpUnixSystemTrust
{$IFEND}
  ;

type
  /// <summary>
  /// How the platform trust is consumed. Default selects the OS delegate where this OS has a
  /// verifier (Windows, Apple, Android), else harvests OS roots (Linux, BSD, Solaris). Anchors forces
  /// harvesting OS roots into our own validator; Delegate forces the OS verifier. Forcing a
  /// mode the platform cannot honor is a typed exception.
  /// </summary>
  TSystemTrustMode = (Default, Anchors, Delegate);

  /// <summary>
  /// Factory for the platform trust sources: an anchor store (OS roots fed to our
  /// validator) and a verifier source (the OS chain engine, network disabled).
  /// Dispatch is compile-time, most-specific OS first; every produced object hides
  /// its OS handles behind the neutral trust interfaces.
  /// </summary>
  TOSSystemTrust = class sealed(TObject)
  strict private
    /// <summary>The platform chain engine, or False where this OS exposes none (anchors-only
    /// targets); the four delegate factories build the generic verifier source and live resolver
    /// over it.</summary>
    class function TryChainEngine(out AEngine: IPlatformChainEngine): Boolean; static;
    /// <summary>The platform root source, or raises where this OS cannot enumerate roots.</summary>
    class function CreateRootSource(const APkixProvider: IPkixProvider)
      : TSystemRootSourceBase; static;
  public
    /// <summary>True if this platform can honor AMode.</summary>
    class function Supports(AMode: TSystemTrustMode): Boolean; static;
    /// <summary>The OS-anchor store for our validator. Raises where the platform cannot
    /// enumerate OS roots (a delegate-only platform). APkixProvider parses a PEM store. The set is
    /// harvested for server authentication (Windows keeps serverAuth-capable roots, macOS applies the
    /// SSL policy), so installing it as a server's client-CA is a deliberate, explicit choice that
    /// authenticates clients against the public PKI - never do it from a shared or process-wide setting.</summary>
    class function AnchorStore(const APkixProvider: IPkixProvider)
      : ITrustAnchorStore; static;
    /// <summary>The OS server-certificate verifier source, built per connection from the trust
    /// context. AFetch fixes the inline behaviour: CacheOnly (no socket) or Live (defer an
    /// indeterminate revocation to the async park). Raises where the platform exposes no system
    /// verifier, or where Live is asked of a platform without OS-native live revocation.</summary>
    class function ServerVerifierSource(AFetch: TSystemTrustFetch)
      : IServerCertificateVerifierSource; overload; static;
    /// <summary>As above, also trusting AExtraAnchors (nil for none) beside the OS roots inside the
    /// OS evaluation, so the platform's own policy still runs, and refusing a path through a
    /// certificate the OS distrusts (read with APkix where the platform exposes that list) or that
    /// AExtraAnchors distrusts. Both lists are snapshotted when the source is built.</summary>
    class function ServerVerifierSource(AFetch: TSystemTrustFetch;
      const AExtraAnchors: ITrustAnchorStore; const APkix: IPkixProvider):
      IServerCertificateVerifierSource; overload; static;
    /// <summary>A host-owned OS-native live-revocation resolver read from the client config
    /// (provider, clock, posture, strength policy, advertised schemes, resolver fetch budget, and the
    /// config's trust-store anchors as the exclusive trust root when it has a store, else the OS
    /// roots): assign its ResolveVerdict to the verdict seam. AFallback (may be nil) runs on an
    /// indeterminate OS outcome before the posture decides. The caller owns and frees the result.
    /// Raises where the platform has no OS-native live revocation.</summary>
    class function LiveRevocationResolver(const AConfig: ITlsClientConfig;
      const AFallback: TCertificateVerdictResolver)
      : TOSLiveRevocationResolverBase; overload; static;
    class function LiveRevocationResolver(const AConfig: ITlsClientConfig)
      : TOSLiveRevocationResolverBase; overload; static;
    /// <summary>A host-owned OS-native live-revocation resolver for the peer CLIENT certificate an
    /// mTLS server verifies, read from the server config (provider, clock, posture, strength policy,
    /// advertised schemes, resolver fetch budget, and the client-CA anchors as the exclusive trust root):
    /// assign its ResolveVerdict to the verdict seam. AFallback (may be nil) runs on an indeterminate
    /// OS outcome before the posture decides. The caller owns and frees the result. Raises where the
    /// platform has no OS-native live revocation.</summary>
    class function LiveRevocationResolver(const AConfig: ITlsServerConfig;
      const AFallback: TCertificateVerdictResolver)
      : TOSLiveRevocationResolverBase; overload; static;
    class function LiveRevocationResolver(const AConfig: ITlsServerConfig)
      : TOSLiveRevocationResolverBase; overload; static;
    /// <summary>The OS client-certificate verifier source for an mTLS server: an exclusive-root
    /// chain engine over the configured client-CA anchors (never the OS/public roots). AFetch fixes
    /// the inline behaviour: CacheOnly (no socket) or Live (defer an indeterminate revocation to the
    /// async park). Raises where the platform exposes no OS client-certificate verifier, or where
    /// Live is asked of a platform without OS-native live revocation. On Android the OS reports no
    /// validated path for a client certificate, so the chain-algorithm and key-strength floors apply
    /// to the leaf alone, not to the presented intermediates. The client-CA store's distrusted
    /// certificates are withheld from the engine and refused on any reported path.</summary>
    class function ClientVerifierSource(AFetch: TSystemTrustFetch)
      : IClientCertificateVerifierSource; static;
  end;

implementation

resourcestring
  SNoHarvest =
    'this platform exposes no root-enumeration API; use the OS delegate verifier';
  SNoDelegate =
    'this platform exposes no system certificate verifier; harvest OS anchors instead';
  SHostRootsNeedProvider =
    'a PKIX provider is required to read the OS distrust list beside host roots';
  SNoClientDelegate =
    'this platform exposes no OS client-certificate verifier; use the built-in verifier over ' +
    'the configured client-CA anchors';

{ TOSSystemTrust }

class function TOSSystemTrust.TryChainEngine(out AEngine: IPlatformChainEngine): Boolean;
begin
{$IF DEFINED(TLSLIB_MSWINDOWS)}
  AEngine := TWindowsChainEngine.Create as IPlatformChainEngine;
  Result := True;
{$ELSEIF DEFINED(TLSLIB_IOS) OR DEFINED(TLSLIB_MACOS)}
  AEngine := TAppleChainEngine.Create as IPlatformChainEngine;
  Result := True;
{$ELSEIF DEFINED(TLSLIB_ANDROID)}
  AEngine := TAndroidChainEngine.Create as IPlatformChainEngine;
  Result := True;
{$ELSE}
  // an anchors-only platform (Unix/BSD/Solaris) exposes no OS chain engine
  AEngine := nil;
  Result := False;
{$IFEND}
end;

class function TOSSystemTrust.Supports(AMode: TSystemTrustMode): Boolean;
begin
  case AMode of
    TSystemTrustMode.Anchors:
{$IF DEFINED(TLSLIB_IOS) OR DEFINED(TLSLIB_ANDROID)}
      // iOS: no enumeration API. Android: harvest is unsafe (stale/partial) and banned - delegate-only.
      Result := False;
{$ELSE}
      Result := True;
{$IFEND}
    TSystemTrustMode.Delegate:
{$IF DEFINED(TLSLIB_MSWINDOWS) OR DEFINED(TLSLIB_IOS) OR DEFINED(TLSLIB_MACOS) OR DEFINED(TLSLIB_ANDROID)}
      Result := True;
{$ELSE}
      Result := False;
{$IFEND}
  else
    // Default: every supported target offers at least one source.
    Result := True;
  end;
end;

class function TOSSystemTrust.CreateRootSource(const APkixProvider: IPkixProvider)
  : TSystemRootSourceBase;
begin
  Result := nil;
{$IF DEFINED(TLSLIB_MSWINDOWS)}
  Result := TWindowsRootSource.Create(APkixProvider);
{$ELSEIF DEFINED(TLSLIB_IOS)}
  raise ESystemTrustUnsupportedTlsLibException.CreateRes(@SNoHarvest);
{$ELSEIF DEFINED(TLSLIB_MACOS)}
  Result := TAppleRootSource.Create(APkixProvider);
{$ELSEIF DEFINED(TLSLIB_ANDROID)}
  // Android is delegate-only: the filesystem store is stale/partial (APEX-updated roots,
  // user-installed CAs, network-security-config), so harvesting is banned - use the OS delegate.
  raise ESystemTrustUnsupportedTlsLibException.CreateRes(@SNoHarvest);
{$ELSEIF DEFINED(TLSLIB_LINUX) OR DEFINED(TLSLIB_BSD) OR DEFINED(TLSLIB_SOLARIS)}
  Result := TUnixRootSource.Create(APkixProvider);
{$ELSE}
  {$MESSAGE ERROR 'UNSUPPORTED TARGET.'}
{$IFEND}
end;

class function TOSSystemTrust.AnchorStore(const APkixProvider: IPkixProvider)
  : ITrustAnchorStore;
var
  LSource: TSystemRootSourceBase;
begin
  LSource := CreateRootSource(APkixProvider);
  try
    Result := LSource.Snapshot;
  finally
    LSource.Free;
  end;
end;

class function TOSSystemTrust.ServerVerifierSource(AFetch: TSystemTrustFetch)
  : IServerCertificateVerifierSource;
begin
  Result := ServerVerifierSource(AFetch, nil, nil);
end;

class function TOSSystemTrust.ServerVerifierSource(AFetch: TSystemTrustFetch;
  const AExtraAnchors: ITrustAnchorStore; const APkix: IPkixProvider):
  IServerCertificateVerifierSource;
var
  LEngine: IPlatformChainEngine;
  LExtra, LDistrusted: TArray<TBytes>;
  LSource: TSystemRootSourceBase;
begin
  // where a platform chain engine exists, the generic source over it (the source refuses a Live
  // fetch on an engine without live fetch at construction, matching the per-platform refusal timing)
  if not TryChainEngine(LEngine) then
    raise ESystemTrustUnsupportedTlsLibException.CreateRes(@SNoDelegate);
  LExtra := nil;
  LDistrusted := nil;
  if AExtraAnchors <> nil then
  begin
    LExtra := AExtraAnchors.RootCertificates;
    LDistrusted := AExtraAnchors.DistrustedCertificates;
  end;
  // the OS list matters only beside host roots, and only where the OS exposes it
  if (System.Length(LExtra) > 0) and Supports(TSystemTrustMode.Anchors) then
  begin
    if APkix = nil then
      raise EArgumentTlsLibException.CreateRes(@SHostRootsNeedProvider);
    LSource := CreateRootSource(APkix);
    try
      LDistrusted := TArrayUtilities.Concat<TBytes>(LDistrusted, LSource.ReadDistrusted);
    finally
      LSource.Free;
    end;
  end;
  Result := TOSVerifierSource.Create(LEngine, AFetch, LExtra, LDistrusted)
    as IServerCertificateVerifierSource;
end;

class function TOSSystemTrust.LiveRevocationResolver(const AConfig: ITlsClientConfig;
  const AFallback: TCertificateVerdictResolver): TOSLiveRevocationResolverBase;
var
  LEngine: IPlatformChainEngine;
  LPolicy: TOSDelegatePolicy;
  LSource: IOSServerVerifierSource;
begin
  if TryChainEngine(LEngine) then
  begin
    LPolicy := Default(TOSDelegatePolicy);
    LPolicy.Pkix := AConfig.Pkix;
    LPolicy.Clock := AConfig.Clock;
    LPolicy.Posture := AConfig.RevocationPosture;
    LPolicy.Fetch := TSystemTrustFetch.Live;
    LPolicy.StrengthPolicy := AConfig.CertificateStrengthPolicy;
    LPolicy.ChainLimits := AConfig.CertificateChainLimits;
    LPolicy.AdvertisedSchemes := TSignatureSchemeCodes.FromRegistry(AConfig.SignatureSchemes);
    LPolicy.CheckHostName := AConfig.CheckServerName;
    // the live pass must build against the same roots as the inline one
    LPolicy.Anchors := nil;
    if AConfig.TrustStore <> nil then
      LPolicy.Anchors := AConfig.TrustStore.RootCertificates;
    LPolicy.Intermediates := AConfig.IntermediateCertificates;
    if SysUtils.Supports(AConfig.ServerVerifierSource, IOSServerVerifierSource, LSource) then
    begin
      LPolicy.ExtraAnchors := LSource.ExtraAnchors;
      LPolicy.Distrusted := LSource.Distrusted;
    end;
    LPolicy.DeadlineMs := AConfig.AsyncCertificateVerdict.DeadlineMs;
    Exit(TOSDelegateLiveResolver.Create(LEngine, TPeerRole.Server, LPolicy, AFallback));
  end;
  raise ESystemTrustUnsupportedTlsLibException.CreateRes(@SNoLiveRevocation);
end;

class function TOSSystemTrust.LiveRevocationResolver(const AConfig: ITlsClientConfig)
  : TOSLiveRevocationResolverBase;
begin
  Result := LiveRevocationResolver(AConfig, nil);
end;

class function TOSSystemTrust.LiveRevocationResolver(const AConfig: ITlsServerConfig;
  const AFallback: TCertificateVerdictResolver): TOSLiveRevocationResolverBase;
var
  LEngine: IPlatformChainEngine;
  LPolicy: TOSDelegatePolicy;
  LAnchors, LDistrusted: TArray<TBytes>;
begin
  // the client-CA anchors are the exclusive trust root the live re-check builds against
  LAnchors := nil;
  LDistrusted := nil;
  if AConfig.TrustStore <> nil then
  begin
    LAnchors := AConfig.TrustStore.RootCertificates;
    LDistrusted := AConfig.TrustStore.DistrustedCertificates;
  end;
  if TryChainEngine(LEngine) then
  begin
    LPolicy := Default(TOSDelegatePolicy);
    LPolicy.Pkix := AConfig.Pkix;
    LPolicy.Clock := AConfig.Clock;
    LPolicy.Posture := AConfig.RevocationPosture;
    LPolicy.Fetch := TSystemTrustFetch.Live;
    LPolicy.StrengthPolicy := AConfig.CertificateStrengthPolicy;
    LPolicy.ChainLimits := AConfig.CertificateChainLimits;
    LPolicy.AdvertisedSchemes := TSignatureSchemeCodes.FromRegistry(AConfig.SignatureSchemes);
    // a client certificate carries no server name to match
    LPolicy.CheckHostName := False;
    LPolicy.Anchors := LAnchors;
    LPolicy.Distrusted := LDistrusted;
    LPolicy.DeadlineMs := AConfig.AsyncCertificateVerdict.DeadlineMs;
    Exit(TOSDelegateLiveResolver.Create(LEngine, TPeerRole.Client, LPolicy, AFallback));
  end;
  raise ESystemTrustUnsupportedTlsLibException.CreateRes(@SNoLiveRevocation);
end;

class function TOSSystemTrust.LiveRevocationResolver(const AConfig: ITlsServerConfig)
  : TOSLiveRevocationResolverBase;
begin
  Result := LiveRevocationResolver(AConfig, nil);
end;

class function TOSSystemTrust.ClientVerifierSource(AFetch: TSystemTrustFetch)
  : IClientCertificateVerifierSource;
var
  LEngine: IPlatformChainEngine;
begin
  if TryChainEngine(LEngine) then
    Exit(TOSVerifierSource.Create(LEngine, AFetch) as IClientCertificateVerifierSource);
  raise ESystemTrustUnsupportedTlsLibException.CreateRes(@SNoClientDelegate);
end;

end.
