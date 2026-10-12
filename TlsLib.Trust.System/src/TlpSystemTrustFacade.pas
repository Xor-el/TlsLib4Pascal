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
  /// Default picks the best source this platform offers (harvest OS anchors into our validator
  /// where they can be enumerated, else a delegate); Anchors and Delegate force a source and raise
  /// a typed error where it cannot be honored. Anchors also honour OS distrust of an exact
  /// certificate anywhere on a path (Windows Disallowed, macOS Deny), as far as the platform lets
  /// it be read; use Delegate where the full OS policy matters. Host roots passed as extra anchors
  /// join the harvested ones, and distrust from either wins; a delegate owns its roots, so it
  /// takes extra anchors only where the platform can union them. System trust verifies server
  /// certificates only; an mTLS server's client-CA is never the OS store - supply it with
  /// TClientVerification (see TOSSystemTrust.ClientVerifierSource for the OS engine over that
  /// private CA).
  /// </summary>
  TSystemTrust = class sealed(TObject)
  strict private
    class procedure ResolveSource(const APkixProvider: IPkixProvider;
      AMode: TSystemTrustMode; out AStore: ITrustAnchorStore;
      out ASource: IServerCertificateVerifierSource;
      const AExtraAnchors: ITrustAnchorStore); static;
  public
    /// <summary>OS trust in the Default mode (see the class summary).</summary>
    class function ServerVerification(const APkixProvider: IPkixProvider)
      : IServerVerificationBuilder; overload; static;
    /// <summary>OS trust in the given mode, with the host's own roots (nil for none) beside the OS
    /// ones. Anchors also honours OS distrust of any certificate (an intermediate or a leaf, not
    /// only a root) by exact match; Delegate applies the full OS policy.</summary>
    class function ServerVerification(const APkixProvider: IPkixProvider;
      AMode: TSystemTrustMode; const AExtraAnchors: ITrustAnchorStore)
      : IServerVerificationBuilder; overload; static;
    /// <summary>Installs OS trust that checks revocation live: the OS delegate under APosture, plus
    /// the async certificate-verdict park (deadline ADeadlineMs, which must be non-zero) that the
    /// host-side OS-native resolver resolves in. Both are set together because a live source
    /// without the park would let a Hard posture behave as Soft. Pair it with
    /// TOSSystemTrust.LiveRevocationResolver on the stream/adapter. Raises where the platform has
    /// no OS-native live revocation.</summary>
    class function WithLiveSystemTrust(const ABuilder: ITlsClientConfigBuilder;
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
  AMode: TSystemTrustMode; out AStore: ITrustAnchorStore;
  out ASource: IServerCertificateVerifierSource; const AExtraAnchors: ITrustAnchorStore);
var
  LMode: TSystemTrustMode;
begin
  AStore := nil;
  ASource := nil;
  LMode := AMode;
  // Default = the best available source for this platform.
  if LMode = TSystemTrustMode.Default then
  begin
    if TOSSystemTrust.Supports(TSystemTrustMode.Anchors) then
      LMode := TSystemTrustMode.Anchors
    else
      LMode := TSystemTrustMode.Delegate;
  end;
  // A forced mode the platform cannot honor raises a typed error inside these.
  if LMode = TSystemTrustMode.Delegate then
    ASource := TOSSystemTrust.ServerVerifierSource(TSystemTrustFetch.CacheOnly, AExtraAnchors,
      APkixProvider)
  else
    AStore := TOSSystemTrust.AnchorStore(APkixProvider);
end;

class function TSystemTrust.ServerVerification(const APkixProvider: IPkixProvider)
  : IServerVerificationBuilder;
begin
  Result := ServerVerification(APkixProvider, TSystemTrustMode.Default, nil);
end;

class function TSystemTrust.ServerVerification(const APkixProvider: IPkixProvider;
  AMode: TSystemTrustMode; const AExtraAnchors: ITrustAnchorStore): IServerVerificationBuilder;
var
  LStore: ITrustAnchorStore;
  LSource: IServerCertificateVerifierSource;
begin
  ResolveSource(APkixProvider, AMode, LStore, LSource, AExtraAnchors);
  if LSource <> nil then
    Exit(TServerVerification.VerifierSource(LSource));
  // the harvested roots and the host's join in one union, so OS distrust still filters the host's
  if AExtraAnchors <> nil then
    Result := TServerVerification.WebPki(
      TArray<ITrustAnchorStore>.Create(LStore, AExtraAnchors), nil)
  else
    Result := TServerVerification.WebPki(LStore);
end;

class function TSystemTrust.WithLiveSystemTrust(const ABuilder: ITlsClientConfigBuilder;
  APosture: TRevocationPosture; ADeadlineMs: Cardinal): ITlsClientConfigBuilder;
begin
  if ADeadlineMs = 0 then
    raise EArgumentTlsLibException.CreateRes(@SLiveNeedsDeadline);
  ABuilder.WithServerVerification(TServerVerification.VerifierSource(
    TOSSystemTrust.ServerVerifierSource(TSystemTrustFetch.Live)).WithRevocation(APosture).Build);
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
    AExtraAnchors).Build;
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
