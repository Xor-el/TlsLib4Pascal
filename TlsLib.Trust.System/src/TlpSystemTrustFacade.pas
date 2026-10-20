{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpSystemTrustFacade;

{$I ..\..\TlsLib\src\Include\TlsLib.inc}

interface

uses
  SyncObjs,
  TlpIPkixProvider,
  TlpICertificateTrust,
  TlpITrustAnchorStore,
  TlpICertificateVerifierSource,
  TlpCertificateVerifierSource,
  TlpITlsConfigBuilder,
  TlpTrustPolicy,
  TlpTlsLibExceptions,
  TlpISystemTrustInstaller,
  TlpSystemTrustBase,
  TlpOSSystemTrust;

type
  /// <summary>
  /// OS trust as the server-certificate verification policy of a client.
  /// Default picks the OS verifier (the delegate) wherever the platform has one (Windows, Apple,
  /// Android) and harvests OS anchors into our validator elsewhere (Linux, BSD, Solaris); Anchors
  /// and Delegate force a source and raise a typed error where it cannot be honored. A delegate
  /// checks revocation from the OS cache and the staple unless the live-revocation verdict is
  /// armed (see WithLiveSystemTrust). Anchors also honour OS distrust of an exact certificate
  /// anywhere on a path (Windows Disallowed, macOS Deny), as far as the platform lets it be read;
  /// a delegate applies the full OS policy. With OsAndHostRoots, Anchors unions the host roots with
  /// the harvested OS roots and distrust from either wins; a delegate trusts the host roots with
  /// the OS roots and distrust from the OS or the host store still wins on a path through
  /// them. Host roots alone
  /// are the only trust root: Anchors harvests nothing, a delegate evaluates in one pass, and the
  /// OS distrust list still applies. A delegate reads the distrust lists once, when the verifier
  /// source is built. System trust verifies server certificates only; an mTLS server's client-CA
  /// is never the OS store - supply it with TClientVerification (see
  /// TOSSystemTrust.ClientVerifierSource for the OS engine over that private CA).
  /// </summary>
  TSystemTrust = class sealed(TObject)
  strict private
    class procedure ResolveSource(const APkixProvider: IPkixProvider;
      AMode: TSystemTrustMode; const ARoots: TSystemTrustRoots;
      out AStores: TArray<ITrustAnchorStore>;
      out ASource: IServerCertificateVerifierSource); static;
  public
    /// <summary>OS trust in the given mode, with ARoots deciding which roots vouch: the OS roots
    /// alone, with the host's, or the host's alone. Anchors also honours OS distrust of any
    /// certificate (an intermediate or a leaf, not only a root) by exact match, and with host roots
    /// alone it harvests nothing from the OS; Delegate applies the full OS policy.</summary>
    class function ServerVerification(const APkixProvider: IPkixProvider;
      AMode: TSystemTrustMode; const ARoots: TSystemTrustRoots)
      : IServerVerificationBuilder; static;
    /// <summary>Installs OS trust that checks revocation live: the OS delegate under APosture, plus
    /// the async certificate-verdict park (deadline ADeadlineMs, which must be non-zero) that the
    /// host-side OS-native resolver resolves in. Both are set together because a live source
    /// without the park would let a Hard posture behave as Soft. ARoots decides which roots vouch,
    /// as for ServerVerification; APkixProvider reads the OS distrust list where the platform
    /// exposes one. Pair it with TOSSystemTrust.LiveRevocationResolver on the stream/adapter.
    /// Raises where the platform has no OS-native live revocation.</summary>
    class function WithLiveSystemTrust(const ABuilder: ITlsClientConfigBuilder;
      const APkixProvider: IPkixProvider; const ARoots: TSystemTrustRoots;
      APosture: TRevocationPosture; ADeadlineMs: Cardinal): ITlsClientConfigBuilder; static;
  end;

  /// <summary>
  /// The one implementation of the host-neutral system-trust seam: it supplies the OS
  /// server-certificate trust policy from TSystemTrust, so a host-neutral config composer adds the
  /// OS store without depending on this package.
  /// </summary>
  TSystemTrustInstaller = class sealed(TInterfacedObject, ISystemTrustInstaller)
  strict private
  class var
    FShared: ISystemTrustInstaller;
    FSharedLock: TCriticalSection;
  public
    constructor Create; overload;
    class constructor Create;
    class destructor Destroy;
    /// <summary>A process-wide, lazily-created installer. It is stateless, so one instance
    /// serves every connection and keeps a stable identity for callers that cache by installer.</summary>
    class function Shared: ISystemTrustInstaller; static;

    function Identity: string;
    function ServerVerification(const APkix: IPkixProvider;
      const AExtraAnchors: ITrustAnchorStore): IServerVerification;
  end;

implementation

resourcestring
  SLiveNeedsDeadline = 'a live revocation fetch needs a non-zero verdict deadline';

{ TSystemTrust }

class procedure TSystemTrust.ResolveSource(const APkixProvider: IPkixProvider;
  AMode: TSystemTrustMode; const ARoots: TSystemTrustRoots;
  out AStores: TArray<ITrustAnchorStore>; out ASource: IServerCertificateVerifierSource);
var
  LMode: TSystemTrustMode;
begin
  AStores := nil;
  ASource := nil;
  LMode := AMode;
  if LMode = TSystemTrustMode.Default then
  begin
    if TOSSystemTrust.Supports(TSystemTrustMode.Delegate) then
      LMode := TSystemTrustMode.Delegate
    else
      LMode := TSystemTrustMode.Anchors;
  end;
  // A forced mode the platform cannot honor raises a typed error inside these.
  if LMode = TSystemTrustMode.Delegate then
    ASource := TOSSystemTrust.ServerVerifierSource(TSystemTrustFetch.CacheOnly, ARoots,
      APkixProvider)
  else if ARoots.Scope = TSystemTrustRootScope.HostRoots then
    // harvests nothing, so a host without a CA bundle works; OS distrust still filters the roots
    AStores := TArray<ITrustAnchorStore>.Create(ARoots.Store,
      TOSSystemTrust.DistrustStore(APkixProvider))
  else if ARoots.Store <> nil then
    // the harvested roots and the host's join in one union, so OS distrust still filters the host's
    AStores := TArray<ITrustAnchorStore>.Create(TOSSystemTrust.AnchorStore(APkixProvider),
      ARoots.Store)
  else
    AStores := TArray<ITrustAnchorStore>.Create(TOSSystemTrust.AnchorStore(APkixProvider));
end;

class function TSystemTrust.ServerVerification(const APkixProvider: IPkixProvider;
  AMode: TSystemTrustMode; const ARoots: TSystemTrustRoots): IServerVerificationBuilder;
var
  LStores: TArray<ITrustAnchorStore>;
  LSource: IServerCertificateVerifierSource;
begin
  ResolveSource(APkixProvider, AMode, ARoots, LStores, LSource);
  if LSource <> nil then
    Exit(TServerVerification.VerifierSource(LSource));
  Result := TServerVerification.WebPki(LStores, nil);
end;

class function TSystemTrust.WithLiveSystemTrust(const ABuilder: ITlsClientConfigBuilder;
  const APkixProvider: IPkixProvider; const ARoots: TSystemTrustRoots;
  APosture: TRevocationPosture; ADeadlineMs: Cardinal): ITlsClientConfigBuilder;
begin
  if ADeadlineMs = 0 then
    raise EArgumentTlsLibException.CreateRes(@SLiveNeedsDeadline);
  ABuilder.WithServerVerification(TServerVerification.VerifierSource(
    TOSSystemTrust.ServerVerifierSource(TSystemTrustFetch.Live, ARoots, APkixProvider))
    .WithRevocation(APosture).Build);
  Result := ABuilder.WithLiveRevocationVerdict(ADeadlineMs);
end;

{ TSystemTrustInstaller }

function TSystemTrustInstaller.Identity: string;
begin
  // stateless: every instance installs the same OS trust
  Result := 'os-system-trust';
end;

function TSystemTrustInstaller.ServerVerification(const APkix: IPkixProvider;
  const AExtraAnchors: ITrustAnchorStore): IServerVerification;
begin
  Result := TSystemTrust.ServerVerification(APkix, TSystemTrustMode.Default,
    TSystemTrustRoots.OsAndHostRoots(AExtraAnchors)).Build;
end;

constructor TSystemTrustInstaller.Create;
begin
  inherited Create;
end;

class constructor TSystemTrustInstaller.Create;
begin
  FSharedLock := TCriticalSection.Create;
end;

class destructor TSystemTrustInstaller.Destroy;
begin
  FShared := nil;
  FSharedLock.Free;
end;

class function TSystemTrustInstaller.Shared: ISystemTrustInstaller;
begin
  FSharedLock.Acquire;
  try
    if FShared = nil then
      FShared := TSystemTrustInstaller.Create as ISystemTrustInstaller;
    Result := FShared;
  finally
    FSharedLock.Release;
  end;
end;

end.
