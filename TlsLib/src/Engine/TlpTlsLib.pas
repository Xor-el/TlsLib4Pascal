{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpTlsLib;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpDefaultCryptoProvider,
  TlpDefaultPkixProvider,
  TlpICertificateTrust,
  TlpTlsCredential,
  TlpITlsConfig,
  TlpITlsConfigBuilder,
  TlpTlsPresets;

type
  /// <summary>
  /// The one-call entry point. It wires the shared default CryptoLib provider and the
  /// Compatible preset into a frozen client or server config. Build the config once and pass it
  /// to TTlsEngineFactory per connection: the config owns the session-ticket key, so a fresh
  /// config per connection would silently disable resumption. There is deliberately no Provider
  /// accessor: to use a different backend, start from a TTlsPresets profile (or
  /// TTlsConfigBuilder.CreateSeeded) with your own provider.
  /// </summary>
  TTlsLib = class sealed(TObject)
  public
    /// <summary>A frozen client config (shared default provider, Compatible preset, given trust).</summary>
    class function NewClientConfig(const ATrustStore: ITrustAnchorStore)
      : ITlsClientConfig; overload; static;
    /// <summary>As above, with trust anchors from a PEM block/bundle or a DER certificate.</summary>
    class function NewClientConfig(const ATrustAnchorsData: TBytes)
      : ITlsClientConfig; overload; static;
    /// <summary>A frozen server config (shared default provider, Compatible preset, given credential).</summary>
    class function NewServerConfig(const ACredential: TTlsCredential)
      : ITlsServerConfig; overload; static;
    /// <summary>As above, from a certificate chain and an unencrypted private key, each a
    /// PEM block or DER.</summary>
    class function NewServerConfig(const ACertificateChainData,
      APrivateKeyData: TBytes): ITlsServerConfig; overload; static;
  end;

implementation

{ TTlsLib }

class function TTlsLib.NewClientConfig(
  const ATrustStore: ITrustAnchorStore): ITlsClientConfig;
begin
  Result := TTlsPresets.Compatible(TDefaultCryptoProvider.Shared,
    TDefaultPkixProvider.Shared)
    .Client.WithTrustStore(ATrustStore).Build;
end;

class function TTlsLib.NewClientConfig(
  const ATrustAnchorsData: TBytes): ITlsClientConfig;
begin
  Result := TTlsPresets.Compatible(TDefaultCryptoProvider.Shared,
    TDefaultPkixProvider.Shared)
    .Client.WithTrustAnchors(ATrustAnchorsData).Build;
end;

class function TTlsLib.NewServerConfig(
  const ACredential: TTlsCredential): ITlsServerConfig;
begin
  Result := TTlsPresets.Compatible(TDefaultCryptoProvider.Shared,
    TDefaultPkixProvider.Shared)
    .Server.WithCredential(ACredential).Build;
end;

class function TTlsLib.NewServerConfig(const ACertificateChainData,
  APrivateKeyData: TBytes): ITlsServerConfig;
begin
  Result := TTlsPresets.Compatible(TDefaultCryptoProvider.Shared,
    TDefaultPkixProvider.Shared)
    .Server.WithCredential(ACertificateChainData, APrivateKeyData).Build;
end;

end.
