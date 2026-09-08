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
  TlpITlsConfigBuilder,
  TlpSystemTrustExceptions,
  TlpOSSystemTrust;

resourcestring
  SNoServerDelegate =
    'OS trust delegation verifies server certificates only; a server cannot delegate ' +
    'client-certificate (mTLS) verification to the OS. Use Anchors mode or a custom verifier';

type
  /// <summary>
  /// One-call OS trust for a config builder. Default picks the best source this
  /// platform offers (harvest OS anchors into our validator everywhere except iOS
  /// and Android, which are delegate-only); Anchors and Delegate force a source and raise a
  /// typed error where it cannot be honored. Anchors compose with any other trust
  /// contribution; a delegate is exclusive - both enforced at the builder's Build.
  /// </summary>
  TSystemTrust = class sealed(TObject)
  strict private
    class procedure ResolveSource(const AProvider: ICryptoProvider;
      AMode: TSystemTrustMode; out AStore: ITrustAnchorStore;
      out AVerifier: IServerCertificateVerifier); static;
  public
    class function WithSystemTrust(const ABuilder: ITlsClientConfigBuilder;
      const AProvider: ICryptoProvider;
      AMode: TSystemTrustMode = TSystemTrustMode.Default)
      : ITlsClientConfigBuilder; overload; static;
    class function WithSystemTrust(const ABuilder: ITlsServerConfigBuilder;
      const AProvider: ICryptoProvider;
      AMode: TSystemTrustMode = TSystemTrustMode.Default)
      : ITlsServerConfigBuilder; overload; static;
  end;

implementation

{ TSystemTrust }

class procedure TSystemTrust.ResolveSource(const AProvider: ICryptoProvider;
  AMode: TSystemTrustMode; out AStore: ITrustAnchorStore;
  out AVerifier: IServerCertificateVerifier);
var
  LMode: TSystemTrustMode;
begin
  AStore := nil;
  AVerifier := nil;
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
    AVerifier := TOSSystemTrust.DelegateVerifier(AProvider)
  else
    AStore := TOSSystemTrust.AnchorStore(AProvider);
end;

class function TSystemTrust.WithSystemTrust(
  const ABuilder: ITlsClientConfigBuilder; const AProvider: ICryptoProvider;
  AMode: TSystemTrustMode): ITlsClientConfigBuilder;
var
  LStore: ITrustAnchorStore;
  LVerifier: IServerCertificateVerifier;
begin
  ResolveSource(AProvider, AMode, LStore, LVerifier);
  if LVerifier <> nil then
    ABuilder.WithCertificateVerifier(LVerifier)
  else
    ABuilder.WithTrustStore(LStore);
  Result := ABuilder;
end;

class function TSystemTrust.WithSystemTrust(
  const ABuilder: ITlsServerConfigBuilder; const AProvider: ICryptoProvider;
  AMode: TSystemTrustMode): ITlsServerConfigBuilder;
var
  LStore: ITrustAnchorStore;
  LVerifier: IServerCertificateVerifier;
begin
  ResolveSource(AProvider, AMode, LStore, LVerifier);
  // the OS delegate verifies SERVER certificates (serverAuth); it cannot verify a peer
  // CLIENT certificate for an mTLS server. Anchors mode (harvest OS roots) still applies.
  if LVerifier <> nil then
    raise ESystemTrustUnsupportedTlsLibException.CreateRes(@SNoServerDelegate);
  ABuilder.WithTrustStore(LStore);
  Result := ABuilder;
end;

end.
