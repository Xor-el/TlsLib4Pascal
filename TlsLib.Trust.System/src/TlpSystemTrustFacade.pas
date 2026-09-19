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
  TlpICryptoProvider,
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
    class procedure ResolveSource(const AProvider: ICryptoProvider;
      AMode: TSystemTrustMode; out AStore: ITrustAnchorStore;
      out ASource: IServerCertificateVerifierSource); static;
  public
    class function WithSystemTrust(const ABuilder: ITlsClientConfigBuilder;
      const AProvider: ICryptoProvider;
      AMode: TSystemTrustMode = TSystemTrustMode.Default)
      : ITlsClientConfigBuilder; overload; static;
    class function WithSystemTrust(const ABuilder: ITlsServerConfigBuilder;
      const AProvider: ICryptoProvider;
      AMode: TSystemTrustMode = TSystemTrustMode.Default)
      : ITlsServerConfigBuilder; overload; static;
    /// <summary>OS trust with a revocation fetch mode. This form always uses the OS delegate
    /// (Live is meaningless over harvested anchors), and for Live it also arms the async
    /// certificate-verdict park (deadline ADeadlineMs, which must be non-zero) that the host-side
    /// OS-native resolver resolves in. Pair it with TOSSystemTrust.LiveRevocationResolver on the
    /// stream/adapter. Raises where the platform has no OS-native live revocation.</summary>
    class function WithSystemTrust(const ABuilder: ITlsClientConfigBuilder;
      const AProvider: ICryptoProvider; AFetch: TSystemTrustFetch;
      ADeadlineMs: Cardinal): ITlsClientConfigBuilder; overload; static;
  end;

implementation

{ TSystemTrust }

class procedure TSystemTrust.ResolveSource(const AProvider: ICryptoProvider;
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
    ASource := TOSSystemTrust.ServerVerifierSource(AProvider, TSystemTrustFetch.CacheOnly)
  else
    AStore := TOSSystemTrust.AnchorStore(AProvider);
end;

class function TSystemTrust.WithSystemTrust(
  const ABuilder: ITlsClientConfigBuilder; const AProvider: ICryptoProvider;
  AMode: TSystemTrustMode): ITlsClientConfigBuilder;
var
  LStore: ITrustAnchorStore;
  LSource: IServerCertificateVerifierSource;
begin
  ResolveSource(AProvider, AMode, LStore, LSource);
  if LSource <> nil then
    ABuilder.WithCertificateVerifierSource(LSource)
  else
    ABuilder.WithTrustStore(LStore);
  Result := ABuilder;
end;

class function TSystemTrust.WithSystemTrust(const ABuilder: ITlsClientConfigBuilder;
  const AProvider: ICryptoProvider; AFetch: TSystemTrustFetch;
  ADeadlineMs: Cardinal): ITlsClientConfigBuilder;
var
  LSource: IServerCertificateVerifierSource;
begin
  // this form always delegates to the OS engine; Live additionally defers an indeterminate
  // revocation to the async park and arms it (the host wires TOSSystemTrust.LiveRevocationResolver)
  LSource := TOSSystemTrust.ServerVerifierSource(AProvider, AFetch);
  ABuilder.WithCertificateVerifierSource(LSource);
  if AFetch = TSystemTrustFetch.Live then
    ABuilder.WithAsyncCertificateVerdict(True, ADeadlineMs);
  Result := ABuilder;
end;

class function TSystemTrust.WithSystemTrust(
  const ABuilder: ITlsServerConfigBuilder; const AProvider: ICryptoProvider;
  AMode: TSystemTrustMode): ITlsServerConfigBuilder;
var
  LStore: ITrustAnchorStore;
  LSource: IServerCertificateVerifierSource;
begin
  ResolveSource(AProvider, AMode, LStore, LSource);
  // the OS delegate verifies SERVER certificates (serverAuth); it cannot verify a peer
  // CLIENT certificate for an mTLS server. Point at Anchors mode where the platform can
  // enumerate OS roots, else at an explicit anchor - so a server never authenticates
  // clients against the OS (public web-PKI) roots by accident.
  if LSource <> nil then
    if TOSSystemTrust.Supports(TSystemTrustMode.Anchors) then
      raise ESystemTrustUnsupportedTlsLibException.CreateRes(@SNoServerDelegateUseAnchors)
    else
      raise ESystemTrustUnsupportedTlsLibException.CreateRes(@SNoServerDelegateNoAnchors);
  ABuilder.WithTrustStore(LStore);
  Result := ABuilder;
end;

end.
