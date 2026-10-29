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
  TlpTrustAnchorStore,
  TlpICertificateVerifierSource,
  TlpITlsConfig,
  TlpTrustPolicy,
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
  /// Which roots vouch for a server chain. OsRoots (also Default(TSystemTrustRoots)) is the OS
  /// roots alone. OsAndHostRoots trusts the host's roots in addition to the OS roots. HostRoots
  /// trusts the host's roots and nothing else (a private PKI): the OS roots never vouch, though the
  /// OS distrust list still applies where the platform exposes one.
  /// </summary>
  TSystemTrustRoots = record
  strict private
    FStore: ITrustAnchorStore;
    FScope: TSystemTrustRootScope;
  public
    class function OsRoots: TSystemTrustRoots; static;
    /// <summary>AStore (nil for none, which is OsRoots) trusted with the OS roots.</summary>
    class function OsAndHostRoots(const AStore: ITrustAnchorStore): TSystemTrustRoots; static;
    /// <summary>AStore trusted alone. Raises EArgumentTlsLibException for nil or a store with
    /// no root certificate.</summary>
    class function HostRoots(const AStore: ITrustAnchorStore): TSystemTrustRoots; static;
    property Store: ITrustAnchorStore read FStore;
    property Scope: TSystemTrustRootScope read FScope;
  end;

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
    /// indeterminate revocation to the async park). The roots in ARoots are trusted inside the OS
    /// evaluation, so the platform's own policy still runs: OS and host roots, or host roots alone
    /// (one pass, the OS roots never vouch; raises where the engine cannot trust host roots alone).
    /// A path through a certificate the OS distrusts (read with APkix where the platform exposes
    /// that list) or that the host store distrusts is refused. Both lists are snapshotted when
    /// the source is built. Raises where the platform exposes no system verifier, where Live is
    /// asked of a platform without OS-native live revocation, or when HostRoots is left with no
    /// root once the distrust lists are applied.</summary>
    class function ServerVerifierSource(AFetch: TSystemTrustFetch;
      const ARoots: TSystemTrustRoots; const APkix: IPkixProvider):
      IServerCertificateVerifierSource; static;
    /// <summary>The certificates the OS distrusts, as a store with no root (an empty distrust
    /// set where the platform exposes no list). Raises where the platform has no OS roots to
    /// read.</summary>
    class function DistrustStore(const APkix: IPkixProvider): ITrustAnchorStore; static;
    /// <summary>A host-owned OS-native live-revocation resolver read from the client config
    /// (provider, clock, posture, strength policy, advertised schemes, resolver fetch budget, and the
    /// roots of its OS verifier source, else its trust-store anchors as the exclusive trust root,
    /// else the OS roots): assign its ResolveVerdict to the verdict seam. AFallback (may be nil)
    /// runs on an indeterminate OS outcome before the posture decides. The caller owns and frees
    /// the result.
    /// Raises where the platform has no OS-native live revocation, or when the config's server
    /// verifier source is neither the OS source nor backed by a trust store (a wrapped source's
    /// roots cannot be read, so the re-check would use the OS roots instead; a PSK-only or
    /// skip-verify config has no server certificate to re-check). The resolver evaluates with a
    /// fresh platform engine, not the one inside the config's source; for a host source
    /// that decorates the OS source, pass the OS source it wraps to the overload below.</summary>
    class function LiveRevocationResolver(const AConfig: ITlsClientConfig;
      const AFallback: TCertificateVerdictResolver)
      : TOSLiveRevocationResolverBase; overload; static;
    /// <summary>The resolver above for a host that decorates the OS source: the roots, extra
    /// anchors and OS distrust come from ARootsOf, the OS verifier source the decorator wraps and
    /// is configured with, as that source was built, so the live pass equals the inline one.
    /// Raises EArgumentTlsLibException unless ARootsOf is the library's OS verifier source, or when
    /// the config's own source is a different OS verifier source, and where the platform has no
    /// OS-native live revocation. The resolver evaluates with a fresh platform engine, not the one
    /// inside ARootsOf.</summary>
    class function LiveRevocationResolver(const AConfig: ITlsClientConfig;
      const ARootsOf: IServerCertificateVerifierSource;
      const AFallback: TCertificateVerdictResolver)
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
    /// <summary>The OS client-certificate verifier source for an mTLS server: an exclusive-root
    /// chain engine over the configured client-CA anchors (never the OS/public roots). AFetch fixes
    /// the inline behaviour: CacheOnly (no socket) or Live (defer an indeterminate revocation to the
    /// async park). Raises where the platform exposes no OS client-certificate verifier, or where
    /// Live is asked of a platform without OS-native live revocation. On Android, where the OS
    /// reports no validated path for a client certificate, the delegate builds it to the configured
    /// anchors with the portable validator. The client-CA store's distrusted certificates are
    /// withheld from the engine and refused on any reported path.</summary>
    class function ClientVerifierSource(AFetch: TSystemTrustFetch)
      : IClientCertificateVerifierSource; static;
  end;

implementation

resourcestring
  SNoHarvest =
    'this platform exposes no root-enumeration API; use the OS delegate verifier';
  SNoDelegate =
    'this platform exposes no system certificate verifier; harvest OS anchors instead';
  SDistrustNeedsProvider =
    'a PKIX provider is required to read the OS distrust list';
  SNoClientDelegate =
    'this platform exposes no OS client-certificate verifier; use the built-in verifier over ' +
    'the configured client-CA anchors';

{ TSystemTrustRoots }

class function TSystemTrustRoots.OsRoots: TSystemTrustRoots;
begin
  Result.FStore := nil;
  Result.FScope := TSystemTrustRootScope.OsAndHostRoots;
end;

class function TSystemTrustRoots.OsAndHostRoots(const AStore: ITrustAnchorStore)
  : TSystemTrustRoots;
begin
  Result.FStore := AStore;
  Result.FScope := TSystemTrustRootScope.OsAndHostRoots;
end;

class function TSystemTrustRoots.HostRoots(const AStore: ITrustAnchorStore)
  : TSystemTrustRoots;
begin
  if (AStore = nil) or (AStore.AnchorCount = 0) then
    raise EArgumentTlsLibException.CreateRes(@SHostRootsNeedRoots);
  Result.FStore := AStore;
  Result.FScope := TSystemTrustRootScope.HostRoots;
end;

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

class function TOSSystemTrust.DistrustStore(const APkix: IPkixProvider): ITrustAnchorStore;
var
  LSource: TSystemRootSourceBase;
begin
  if APkix = nil then
    raise EArgumentTlsLibException.CreateRes(@SDistrustNeedsProvider);
  LSource := CreateRootSource(APkix);
  try
    Result := TTrustAnchorStore.Create(nil, LSource.ReadDistrusted) as ITrustAnchorStore;
  finally
    LSource.Free;
  end;
end;

class function TOSSystemTrust.ServerVerifierSource(AFetch: TSystemTrustFetch;
  const ARoots: TSystemTrustRoots; const APkix: IPkixProvider):
  IServerCertificateVerifierSource;
var
  LEngine: IPlatformChainEngine;
  LHostRoots, LDistrusted: TArray<TBytes>;
begin
  // where a platform chain engine exists, the generic source over it (the source refuses a Live
  // fetch on an engine without live fetch at construction, matching the per-platform refusal timing)
  if not TryChainEngine(LEngine) then
    raise ESystemTrustUnsupportedTlsLibException.CreateRes(@SNoDelegate);
  LHostRoots := nil;
  LDistrusted := nil;
  if ARoots.Store <> nil then
  begin
    LHostRoots := ARoots.Store.RootCertificates;
    LDistrusted := ARoots.Store.DistrustedCertificates;
  end;
  // the OS list matters only with host roots, and only where the OS exposes it
  if (System.Length(LHostRoots) > 0) and Supports(TSystemTrustMode.Anchors) then
    LDistrusted := TArrayUtilities.Concat<TBytes>(LDistrusted,
      DistrustStore(APkix).DistrustedCertificates);
  Result := TOSVerifierSource.Create(LEngine, AFetch, ARoots.Scope, LHostRoots,
    LDistrusted) as IServerCertificateVerifierSource;
end;

class function TOSSystemTrust.LiveRevocationResolver(const AConfig: ITlsClientConfig;
  const AFallback: TCertificateVerdictResolver): TOSLiveRevocationResolverBase;
var
  LEngine: IPlatformChainEngine;
begin
  if not TryChainEngine(LEngine) then
    raise ESystemTrustUnsupportedTlsLibException.CreateRes(@SNoLiveRevocation);
  Result := TOSDelegateLiveResolver.Create(LEngine, TPeerRole.Server,
    TOSDelegatePolicy.FromClientConfig(AConfig, AConfig.ServerVerifierSource), AFallback);
end;

class function TOSSystemTrust.LiveRevocationResolver(const AConfig: ITlsClientConfig;
  const ARootsOf: IServerCertificateVerifierSource;
  const AFallback: TCertificateVerdictResolver): TOSLiveRevocationResolverBase;
var
  LEngine: IPlatformChainEngine;
begin
  if not (ARootsOf is TOSVerifierSource) then
    raise EArgumentTlsLibException.CreateRes(@SLiveRootsOfNeedsOsSource);
  if (AConfig.ServerVerifierSource is TOSVerifierSource) and
    (AConfig.ServerVerifierSource <> ARootsOf) then
    raise EArgumentTlsLibException.CreateRes(@SLiveRootsOfSourceDiffers);
  if not TryChainEngine(LEngine) then
    raise ESystemTrustUnsupportedTlsLibException.CreateRes(@SNoLiveRevocation);
  Result := TOSDelegateLiveResolver.Create(LEngine, TPeerRole.Server,
    TOSDelegatePolicy.FromClientConfig(AConfig, ARootsOf), AFallback);
end;

class function TOSSystemTrust.LiveRevocationResolver(const AConfig: ITlsServerConfig;
  const AFallback: TCertificateVerdictResolver): TOSLiveRevocationResolverBase;
var
  LEngine: IPlatformChainEngine;
begin
  if not TryChainEngine(LEngine) then
    raise ESystemTrustUnsupportedTlsLibException.CreateRes(@SNoLiveRevocation);
  Result := TOSDelegateLiveResolver.Create(LEngine, TPeerRole.Client,
    TOSDelegatePolicy.FromServerConfig(AConfig), AFallback);
end;

class function TOSSystemTrust.ClientVerifierSource(AFetch: TSystemTrustFetch)
  : IClientCertificateVerifierSource;
var
  LEngine: IPlatformChainEngine;
begin
  if TryChainEngine(LEngine) then
    Exit(TOSVerifierSource.Create(LEngine, AFetch, TSystemTrustRootScope.OsAndHostRoots, nil, nil)
      as IClientCertificateVerifierSource);
  raise ESystemTrustUnsupportedTlsLibException.CreateRes(@SNoClientDelegate);
end;

end.
