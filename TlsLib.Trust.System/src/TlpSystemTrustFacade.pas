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
  TlpICertificateVerifierSource,
  TlpITlsConfigBuilder,
  TlpISystemTrustInstaller,
  TlpSystemTrustBase,
  TlpOSSystemTrust;

type
  /// <summary>
  /// One-call OS trust for a client config builder, as the server-certificate trust source.
  /// Default picks the best source this platform offers (harvest OS anchors into our validator
  /// where they can be enumerated, else a delegate); Anchors and Delegate force a source and raise
  /// a typed error where it cannot be honored. Anchors compose with any other trust contribution; a
  /// delegate is exclusive - both enforced at the builder's Build. System trust verifies server
  /// certificates only; an mTLS server's client-CA is never the OS store - supply it with
  /// WithTrustAnchors / WithTrustStore (see TOSSystemTrust.ClientVerifierSource for the OS engine
  /// over that private CA).
  /// </summary>
  TSystemTrust = class sealed(TObject)
  strict private
    class procedure ResolveSource(const APkixProvider: IPkixProvider;
      AMode: TSystemTrustMode; out AStore: ITrustAnchorStore;
      out ASource: IServerCertificateVerifierSource); static;
  public
    class function WithSystemTrust(const ABuilder: ITlsClientConfigBuilder;
      const APkixProvider: IPkixProvider;
      AMode: TSystemTrustMode = TSystemTrustMode.Default)
      : ITlsClientConfigBuilder; overload; static;
    /// <summary>OS trust with a revocation fetch mode. This form always uses the OS delegate
    /// (Live is meaningless over harvested anchors), and for Live it also arms the async
    /// certificate-verdict park (deadline ADeadlineMs, which must be non-zero) that the host-side
    /// OS-native resolver resolves in. Pair it with TOSSystemTrust.LiveRevocationResolver on the
    /// stream/adapter. Raises where the platform has no OS-native live revocation.</summary>
    class function WithSystemTrust(const ABuilder: ITlsClientConfigBuilder;
      const APkixProvider: IPkixProvider; AFetch: TSystemTrustFetch;
      ADeadlineMs: Cardinal): ITlsClientConfigBuilder; overload; static;
  end;

  /// <summary>
  /// The one implementation of the host-neutral system-trust seam: it installs OS server-certificate
  /// trust into a client builder by forwarding to TSystemTrust.WithSystemTrust, so a host-neutral
  /// config composer adds the OS store without depending on this package.
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

    procedure InstallClientTrust(const ABuilder: ITlsClientConfigBuilder;
      const APkix: IPkixProvider);
  end;

implementation

{ TSystemTrust }

class procedure TSystemTrust.ResolveSource(const APkixProvider: IPkixProvider;
  AMode: TSystemTrustMode; out AStore: ITrustAnchorStore;
  out ASource: IServerCertificateVerifierSource);
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
    ASource := TOSSystemTrust.ServerVerifierSource(TSystemTrustFetch.CacheOnly)
  else
    AStore := TOSSystemTrust.AnchorStore(APkixProvider);
end;

class function TSystemTrust.WithSystemTrust(
  const ABuilder: ITlsClientConfigBuilder; const APkixProvider: IPkixProvider;
  AMode: TSystemTrustMode): ITlsClientConfigBuilder;
var
  LStore: ITrustAnchorStore;
  LSource: IServerCertificateVerifierSource;
begin
  ResolveSource(APkixProvider, AMode, LStore, LSource);
  if LSource <> nil then
    ABuilder.WithCertificateVerifierSource(LSource)
  else
    ABuilder.WithTrustStore(LStore);
  Result := ABuilder;
end;

class function TSystemTrust.WithSystemTrust(const ABuilder: ITlsClientConfigBuilder;
  const APkixProvider: IPkixProvider; AFetch: TSystemTrustFetch;
  ADeadlineMs: Cardinal): ITlsClientConfigBuilder;
var
  LSource: IServerCertificateVerifierSource;
begin
  // this form always delegates to the OS engine; Live additionally defers an indeterminate
  // revocation to the async park and arms it (the host wires TOSSystemTrust.LiveRevocationResolver)
  LSource := TOSSystemTrust.ServerVerifierSource(AFetch);
  ABuilder.WithCertificateVerifierSource(LSource);
  if AFetch = TSystemTrustFetch.Live then
    ABuilder.WithLiveRevocationVerdict(ADeadlineMs);
  Result := ABuilder;
end;

{ TSystemTrustInstaller }

procedure TSystemTrustInstaller.InstallClientTrust(
  const ABuilder: ITlsClientConfigBuilder; const APkix: IPkixProvider);
begin
  TSystemTrust.WithSystemTrust(ABuilder, APkix);
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
