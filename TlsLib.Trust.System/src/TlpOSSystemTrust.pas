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
  TlpIPkixProvider,
  TlpICertificateTrust,
  TlpICertificateVerifierSource,
  TlpITlsConfig,
  TlpTrustPolicy,
  TlpTlsEngineFactory,
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
  /// How the platform trust is consumed. Default selects the best source this OS offers
  /// (harvest OS roots where they can be enumerated, else the OS delegate). Anchors forces
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
  public
    /// <summary>True if this platform can honor AMode.</summary>
    class function Supports(AMode: TSystemTrustMode): Boolean; static;
    /// <summary>The OS-anchor store for our validator. Raises where the platform cannot
    /// enumerate OS roots (a delegate-only platform). APkixProvider parses a PEM store.</summary>
    class function AnchorStore(const APkixProvider: IPkixProvider)
      : ITrustAnchorStore; static;
    /// <summary>The OS server-certificate verifier source, built per connection from the trust
    /// context. AFetch fixes the inline behaviour: CacheOnly (no socket) or Live (defer an
    /// indeterminate revocation to the async park). Raises where the platform exposes no system
    /// verifier, or where Live is asked of a platform without OS-native live revocation.</summary>
    class function ServerVerifierSource(AFetch: TSystemTrustFetch)
      : IServerCertificateVerifierSource; static;
    /// <summary>A host-owned OS-native live-revocation resolver read from the client config
    /// (provider, clock, posture, strength policy, advertised schemes, resolver fetch budget): assign
    /// its ResolveVerdict to the verdict seam. AFallback (may be nil) runs on an indeterminate OS
    /// outcome before the posture decides. The caller owns and frees the result. Raises where the
    /// platform has no OS-native live revocation.</summary>
    class function LiveRevocationResolver(const AConfig: ITlsClientConfig;
      const AFallback: TCertificateVerdictResolver): TOSLiveRevocationResolver; overload; static;
    class function LiveRevocationResolver(const AConfig: ITlsClientConfig)
      : TOSLiveRevocationResolver; overload; static;
    /// <summary>A host-owned OS-native live-revocation resolver for the peer CLIENT certificate an
    /// mTLS server verifies, read from the server config (provider, clock, posture, strength policy,
    /// advertised schemes, resolver fetch budget, and the client-CA anchors as the exclusive trust root):
    /// assign its ResolveVerdict to the verdict seam. AFallback (may be nil) runs on an indeterminate
    /// OS outcome before the posture decides. The caller owns and frees the result. Raises where the
    /// platform has no OS-native live revocation.</summary>
    class function LiveRevocationResolver(const AConfig: ITlsServerConfig;
      const AFallback: TCertificateVerdictResolver): TOSLiveRevocationResolver; overload; static;
    class function LiveRevocationResolver(const AConfig: ITlsServerConfig)
      : TOSLiveRevocationResolver; overload; static;
    /// <summary>The OS client-certificate verifier source for an mTLS server: an exclusive-root
    /// chain engine over the configured client-CA anchors (never the OS/public roots). AFetch fixes
    /// the inline behaviour: CacheOnly (no socket) or Live (defer an indeterminate revocation to the
    /// async park). Raises where the platform exposes no OS client-certificate verifier, or where
    /// Live is asked of a platform without OS-native live revocation.</summary>
    class function ClientVerifierSource(AFetch: TSystemTrustFetch)
      : IClientCertificateVerifierSource; static;
  end;

implementation

resourcestring
  SNoHarvest =
    'this platform exposes no root-enumeration API; use the OS delegate verifier';
  SNoDelegate =
    'this platform exposes no system certificate verifier; harvest OS anchors instead';
  SNoClientDelegate =
    'this platform exposes no OS client-certificate verifier; use the built-in verifier over ' +
    'the configured client-CA anchors';
  SNoLiveRevocation =
    'this platform has no OS-native live revocation (only Windows and Apple do); keep cache-only ' +
    'trust and compose the portable live-revocation checker for a live check here';

{ TOSSystemTrust }

class function TOSSystemTrust.TryChainEngine(out AEngine: IPlatformChainEngine): Boolean;
begin
{$IF DEFINED(TLSLIB_MSWINDOWS)}
  AEngine := TWindowsChainEngine.Create as IPlatformChainEngine;
  Result := True;
{$ELSEIF DEFINED(TLSLIB_IOS) OR DEFINED(TLSLIB_MACOS)}
  AEngine := TAppleChainEngine.Create as IPlatformChainEngine;
  Result := True;
{$ELSE}
  // Android exposes an engine too; that arm is wired when Android is ported.
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

class function TOSSystemTrust.AnchorStore(const APkixProvider: IPkixProvider)
  : ITrustAnchorStore;
var
  LSource: TSystemRootSource;
begin
  LSource := nil;
{$IF DEFINED(TLSLIB_MSWINDOWS)}
  LSource := TWindowsRootSource.Create(APkixProvider);
{$ELSEIF DEFINED(TLSLIB_IOS)}
  raise ESystemTrustUnsupportedTlsLibException.CreateRes(@SNoHarvest);
{$ELSEIF DEFINED(TLSLIB_MACOS)}
  LSource := TAppleRootSource.Create(APkixProvider);
{$ELSEIF DEFINED(TLSLIB_ANDROID)}
  // Android is delegate-only: the filesystem store is stale/partial (APEX-updated roots,
  // user-installed CAs, network-security-config), so harvesting is banned - use the OS delegate.
  raise ESystemTrustUnsupportedTlsLibException.CreateRes(@SNoHarvest);
{$ELSEIF DEFINED(TLSLIB_LINUX) OR DEFINED(TLSLIB_BSD) OR DEFINED(TLSLIB_SOLARIS)}
  LSource := TUnixRootSource.Create(APkixProvider);
{$ELSE}
  {$MESSAGE ERROR 'UNSUPPORTED TARGET.'}
{$IFEND}
  try
    Result := LSource.Snapshot;
  finally
    LSource.Free;
  end;
end;

class function TOSSystemTrust.ServerVerifierSource(AFetch: TSystemTrustFetch)
  : IServerCertificateVerifierSource;
var
  LEngine: IPlatformChainEngine;
begin
  // where a platform chain engine exists, the generic source over it (the source refuses a Live
  // fetch on an engine without live fetch at construction, matching the per-platform refusal timing)
  if TryChainEngine(LEngine) then
    Exit(TOSVerifierSource.Create(LEngine, AFetch) as IServerCertificateVerifierSource);
{$IF DEFINED(TLSLIB_ANDROID)}
  // Android's platform TrustManager owns revocation and has no network-revocation knob; only
  // cache-only (the staple post-check) is honoured here
  if AFetch = TSystemTrustFetch.Live then
    raise ESystemTrustUnsupportedTlsLibException.CreateRes(@SNoLiveRevocation);
  Result := TAndroidServerVerifierSource.Create as IServerCertificateVerifierSource;
{$ELSE}
  raise ESystemTrustUnsupportedTlsLibException.CreateRes(@SNoDelegate);
{$IFEND}
end;

class function TOSSystemTrust.LiveRevocationResolver(const AConfig: ITlsClientConfig;
  const AFallback: TCertificateVerdictResolver): TOSLiveRevocationResolver;
var
  LEngine: IPlatformChainEngine;
  LPolicy: TOSDelegatePolicy;
begin
  if TryChainEngine(LEngine) then
  begin
    LPolicy := Default(TOSDelegatePolicy);
    LPolicy.Pkix := AConfig.Pkix;
    LPolicy.Clock := AConfig.Clock;
    LPolicy.Posture := AConfig.RevocationPosture;
    LPolicy.Fetch := TSystemTrustFetch.Live;
    LPolicy.StrengthPolicy := AConfig.CertificateStrengthPolicy;
    LPolicy.AdvertisedSchemes := TTlsEngineFactory.SchemeCodes(AConfig.SignatureSchemes);
    // a server certificate is validated against the OS roots, so no exclusive anchor set
    LPolicy.Anchors := nil;
    LPolicy.DeadlineMs := AConfig.AsyncCertificateVerdict.DeadlineMs;
    Exit(TOSDelegateLiveResolver.Create(LEngine, TPeerRole.Server, LPolicy, AFallback));
  end;
  raise ESystemTrustUnsupportedTlsLibException.CreateRes(@SNoLiveRevocation);
end;

class function TOSSystemTrust.LiveRevocationResolver(const AConfig: ITlsClientConfig)
  : TOSLiveRevocationResolver;
begin
  Result := LiveRevocationResolver(AConfig, nil);
end;

class function TOSSystemTrust.LiveRevocationResolver(const AConfig: ITlsServerConfig;
  const AFallback: TCertificateVerdictResolver): TOSLiveRevocationResolver;
var
  LEngine: IPlatformChainEngine;
  LPolicy: TOSDelegatePolicy;
  LAnchors: TArray<TBytes>;
begin
  // the client-CA anchors are the exclusive trust root the live re-check builds against
  LAnchors := nil;
  if AConfig.TrustStore <> nil then
    LAnchors := AConfig.TrustStore.RootCertificates;
  if TryChainEngine(LEngine) then
  begin
    LPolicy := Default(TOSDelegatePolicy);
    LPolicy.Pkix := AConfig.Pkix;
    LPolicy.Clock := AConfig.Clock;
    LPolicy.Posture := AConfig.RevocationPosture;
    LPolicy.Fetch := TSystemTrustFetch.Live;
    LPolicy.StrengthPolicy := AConfig.CertificateStrengthPolicy;
    LPolicy.AdvertisedSchemes := TTlsEngineFactory.SchemeCodes(AConfig.SignatureSchemes);
    LPolicy.Anchors := LAnchors;
    LPolicy.DeadlineMs := AConfig.AsyncCertificateVerdict.DeadlineMs;
    Exit(TOSDelegateLiveResolver.Create(LEngine, TPeerRole.Client, LPolicy, AFallback));
  end;
  raise ESystemTrustUnsupportedTlsLibException.CreateRes(@SNoLiveRevocation);
end;

class function TOSSystemTrust.LiveRevocationResolver(const AConfig: ITlsServerConfig)
  : TOSLiveRevocationResolver;
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
{$IF DEFINED(TLSLIB_ANDROID)}
  // Android's platform TrustManager owns revocation and has no network-revocation knob; only
  // cache-only client verification is honoured here
  if AFetch = TSystemTrustFetch.Live then
    raise ESystemTrustUnsupportedTlsLibException.CreateRes(@SNoLiveRevocation);
  Result := TAndroidClientVerifierSource.Create as IClientCertificateVerifierSource;
{$ELSE}
  raise ESystemTrustUnsupportedTlsLibException.CreateRes(@SNoClientDelegate);
{$IFEND}
end;

end.
