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
  TlpICryptoProvider,
  TlpICertificateTrust,
  TlpICertificateVerifierSource,
  TlpITlsConfig,
  TlpTrustPolicy,
  TlpTlsEngineFactory,
  TlpSystemTrustBase,
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
  public
    /// <summary>True if this platform can honor AMode.</summary>
    class function Supports(AMode: TSystemTrustMode): Boolean; static;
    /// <summary>The OS-anchor store for our validator. Raises where the platform cannot
    /// enumerate OS roots (a delegate-only platform). AProvider parses a PEM store.</summary>
    class function AnchorStore(const AProvider: ICryptoProvider)
      : ITrustAnchorStore; static;
    /// <summary>The OS server-certificate verifier source, built per connection from the trust
    /// context. AFetch fixes the inline behaviour: CacheOnly (no socket) or Live (defer an
    /// indeterminate revocation to the async park). Raises where the platform exposes no system
    /// verifier, or where Live is asked of a platform without OS-native live revocation.</summary>
    class function ServerVerifierSource(const AProvider: ICryptoProvider;
      AFetch: TSystemTrustFetch): IServerCertificateVerifierSource; static;
    /// <summary>A host-owned OS-native live-revocation resolver read from the client config
    /// (provider, clock, posture, strength policy, advertised schemes, park deadline): assign its
    /// ResolveVerdict to the verdict seam. AFallback (may be nil) runs on an indeterminate OS
    /// outcome before the posture decides. The caller owns and frees the result. Raises where the
    /// platform has no OS-native live revocation.</summary>
    class function LiveRevocationResolver(const AConfig: ITlsClientConfig;
      const AFallback: TCertificateVerdictResolver): TOSLiveRevocationResolver; overload; static;
    class function LiveRevocationResolver(const AConfig: ITlsClientConfig)
      : TOSLiveRevocationResolver; overload; static;
    /// <summary>The OS client-certificate verifier source for an mTLS server: an exclusive-root
    /// chain engine over the configured client-CA anchors (never the OS/public roots). Raises
    /// where the platform exposes no OS client-certificate verifier.</summary>
    class function ClientVerifierSource(const AProvider: ICryptoProvider)
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

class function TOSSystemTrust.AnchorStore(const AProvider: ICryptoProvider)
  : ITrustAnchorStore;
var
  LSource: TSystemRootSource;
begin
  LSource := nil;
{$IF DEFINED(TLSLIB_MSWINDOWS)}
  LSource := TWindowsRootSource.Create(AProvider);
{$ELSEIF DEFINED(TLSLIB_IOS)}
  raise ESystemTrustUnsupportedTlsLibException.CreateRes(@SNoHarvest);
{$ELSEIF DEFINED(TLSLIB_MACOS)}
  LSource := TAppleRootSource.Create(AProvider);
{$ELSEIF DEFINED(TLSLIB_ANDROID)}
  // Android is delegate-only: the filesystem store is stale/partial (APEX-updated roots,
  // user-installed CAs, network-security-config), so harvesting is banned - use the OS delegate.
  raise ESystemTrustUnsupportedTlsLibException.CreateRes(@SNoHarvest);
{$ELSEIF DEFINED(TLSLIB_LINUX) OR DEFINED(TLSLIB_BSD) OR DEFINED(TLSLIB_SOLARIS)}
  LSource := TUnixRootSource.Create(AProvider);
{$ELSE}
  {$MESSAGE ERROR 'UNSUPPORTED TARGET.'}
{$IFEND}
  try
    Result := LSource.Snapshot;
  finally
    LSource.Free;
  end;
end;

class function TOSSystemTrust.ServerVerifierSource(const AProvider: ICryptoProvider;
  AFetch: TSystemTrustFetch): IServerCertificateVerifierSource;
begin
  Result := nil;
{$IF DEFINED(TLSLIB_MSWINDOWS)}
  Result := TWindowsServerVerifierSource.Create(AFetch) as IServerCertificateVerifierSource;
{$ELSEIF DEFINED(TLSLIB_IOS) OR DEFINED(TLSLIB_MACOS)}
  Result := TAppleServerVerifierSource.Create(AFetch) as IServerCertificateVerifierSource;
{$ELSEIF DEFINED(TLSLIB_ANDROID)}
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
begin
  Result := nil;
{$IF DEFINED(TLSLIB_MSWINDOWS)}
  Result := TWindowsLiveRevocationResolver.Create(AConfig.Provider,
    AConfig.RevocationPosture, AConfig.Clock, AConfig.CertificateStrengthPolicy,
    TTlsEngineFactory.SchemeCodes(AConfig.SignatureSchemes),
    AConfig.AsyncCertificateVerdict.DeadlineMs, AFallback);
{$ELSEIF DEFINED(TLSLIB_IOS) OR DEFINED(TLSLIB_MACOS)}
  // Apple has no per-evaluation revocation timeout, so the park deadline is not threaded here
  Result := TAppleLiveRevocationResolver.Create(AConfig.Provider,
    AConfig.RevocationPosture, AConfig.Clock, AConfig.CertificateStrengthPolicy,
    TTlsEngineFactory.SchemeCodes(AConfig.SignatureSchemes), AFallback);
{$ELSE}
  raise ESystemTrustUnsupportedTlsLibException.CreateRes(@SNoLiveRevocation);
{$IFEND}
end;

class function TOSSystemTrust.LiveRevocationResolver(const AConfig: ITlsClientConfig)
  : TOSLiveRevocationResolver;
begin
  Result := LiveRevocationResolver(AConfig, nil);
end;

class function TOSSystemTrust.ClientVerifierSource(const AProvider: ICryptoProvider)
  : IClientCertificateVerifierSource;
begin
  Result := nil;
{$IF DEFINED(TLSLIB_MSWINDOWS)}
  Result := TWindowsClientVerifierSource.Create as IClientCertificateVerifierSource;
{$ELSEIF DEFINED(TLSLIB_IOS) OR DEFINED(TLSLIB_MACOS)}
  Result := TAppleClientVerifierSource.Create as IClientCertificateVerifierSource;
{$ELSEIF DEFINED(TLSLIB_ANDROID)}
  Result := TAndroidClientVerifierSource.Create as IClientCertificateVerifierSource;
{$ELSE}
  raise ESystemTrustUnsupportedTlsLibException.CreateRes(@SNoClientDelegate);
{$IFEND}
end;

end.
