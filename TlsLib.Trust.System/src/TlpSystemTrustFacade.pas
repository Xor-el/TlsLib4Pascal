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
  TlpIPkixProvider,
  TlpICertificateTrust,
  TlpICertificateVerifierSource,
  TlpITlsConfigBuilder,
  TlpSystemTrustExceptions,
  TlpSystemTrustBase,
  TlpOSSystemTrust;

resourcestring
  // a server cannot delegate client-certificate (mTLS) verification to the OS; the guidance
  // differs by platform, since Anchors mode is only available where the OS roots can be enumerated
  SNoServerDelegateUseAnchors =
    'OS trust delegation verifies server certificates only; a server cannot delegate ' +
    'client-certificate (mTLS) verification to the OS. Use Anchors mode (harvest the OS ' +
    'roots into the validator) or a custom verifier';
  SNoServerDelegateNoAnchors =
    'OS trust delegation verifies server certificates only; a server cannot delegate ' +
    'client-certificate (mTLS) verification to the OS. This platform cannot enumerate the ' +
    'OS roots, so supply an explicit trust anchor (WithTrustAnchors/WithTrustStore) or a ' +
    'custom verifier';

type
  /// <summary>
  /// One-call OS trust for a config builder. Default picks the best source this platform
  /// offers (harvest OS anchors into our validator where they can be enumerated, else a
  /// delegate); Anchors and Delegate force a source and raise a typed error where it cannot
  /// be honored. Anchors compose with any other trust contribution; a delegate is exclusive -
  /// both enforced at the builder's Build.
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
    class function WithSystemTrust(const ABuilder: ITlsServerConfigBuilder;
      const APkixProvider: IPkixProvider;
      AMode: TSystemTrustMode = TSystemTrustMode.Default)
      : ITlsServerConfigBuilder; overload; static;
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
  /// The one implementation of the host-neutral system-trust seam: it installs OS trust into a
  /// builder for the role the builder serves by forwarding to TSystemTrust.WithSystemTrust, so a
  /// host-neutral config composer adds the OS store without depending on this package. The server
  /// role authenticates client certificates and never roots them at the public OS store - the
  /// forwarded call raises where only a delegate exists.
  /// </summary>
  TSystemTrustInstaller = class sealed(TInterfacedObject, ISystemTrustInstaller)
  public
    procedure InstallClientTrust(const ABuilder: ITlsClientConfigBuilder;
      const APkix: IPkixProvider);
    procedure InstallClientAuthTrust(const ABuilder: ITlsServerConfigBuilder;
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

class function TSystemTrust.WithSystemTrust(
  const ABuilder: ITlsServerConfigBuilder; const APkixProvider: IPkixProvider;
  AMode: TSystemTrustMode): ITlsServerConfigBuilder;
var
  LStore: ITrustAnchorStore;
  LSource: IServerCertificateVerifierSource;
begin
  ResolveSource(APkixProvider, AMode, LStore, LSource);
  // WithSystemTrust's delegate roots against the OS (public web-PKI) store, which is never right for
  // authenticating a CLIENT certificate. Point at Anchors mode where the platform can enumerate OS
  // roots, else at an explicit anchor - so a server never authenticates clients against public roots
  // by accident. (To verify client certificates with the OS engine, install the OS client delegate
  // over your private client-CA anchors instead: TOSSystemTrust.ClientVerifierSource.)
  if LSource <> nil then
    if TOSSystemTrust.Supports(TSystemTrustMode.Anchors) then
      raise ESystemTrustUnsupportedTlsLibException.CreateRes(@SNoServerDelegateUseAnchors)
    else
      raise ESystemTrustUnsupportedTlsLibException.CreateRes(@SNoServerDelegateNoAnchors);
  ABuilder.WithTrustStore(LStore);
  Result := ABuilder;
end;

{ TSystemTrustInstaller }

procedure TSystemTrustInstaller.InstallClientTrust(
  const ABuilder: ITlsClientConfigBuilder; const APkix: IPkixProvider);
begin
  TSystemTrust.WithSystemTrust(ABuilder, APkix);
end;

procedure TSystemTrustInstaller.InstallClientAuthTrust(
  const ABuilder: ITlsServerConfigBuilder; const APkix: IPkixProvider);
begin
  // the server overload roots client-certificate trust at OS-enumerable anchors and raises where
  // only a delegate exists (never authenticating clients against the public web-PKI store)
  TSystemTrust.WithSystemTrust(ABuilder, APkix);
end;

end.
