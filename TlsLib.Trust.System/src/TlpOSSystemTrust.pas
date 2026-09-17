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
  TlpCertificateVerifierSource,
  TlpSystemTrustBase,
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
    /// <summary>The OS server-certificate verifier source (cache-only delegate), built per
    /// connection from the trust context. Raises where the platform exposes no system
    /// verifier.</summary>
    class function ServerVerifierSource(const AProvider: ICryptoProvider)
      : IServerCertificateVerifierSource; static;
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

class function TOSSystemTrust.ServerVerifierSource(const AProvider: ICryptoProvider)
  : IServerCertificateVerifierSource;
begin
  Result := nil;
{$IF DEFINED(TLSLIB_MSWINDOWS)}
  Result := TWindowsServerVerifierSource.Create as IServerCertificateVerifierSource;
{$ELSEIF DEFINED(TLSLIB_IOS) OR DEFINED(TLSLIB_MACOS)}
  Result := TInstanceServerVerifierSource.Create(
    TAppleDelegateVerifier.Create as IServerCertificateVerifier)
    as IServerCertificateVerifierSource;
{$ELSEIF DEFINED(TLSLIB_ANDROID)}
  Result := TInstanceServerVerifierSource.Create(
    TAndroidDelegateVerifier.Create(AProvider) as IServerCertificateVerifier)
    as IServerCertificateVerifierSource;
{$ELSE}
  raise ESystemTrustUnsupportedTlsLibException.CreateRes(@SNoDelegate);
{$IFEND}
end;

class function TOSSystemTrust.ClientVerifierSource(const AProvider: ICryptoProvider)
  : IClientCertificateVerifierSource;
begin
  Result := nil;
{$IF DEFINED(TLSLIB_MSWINDOWS)}
  Result := TWindowsClientVerifierSource.Create as IClientCertificateVerifierSource;
{$ELSE}
  raise ESystemTrustUnsupportedTlsLibException.CreateRes(@SNoClientDelegate);
{$IFEND}
end;

end.
