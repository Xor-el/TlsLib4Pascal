{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpServerOfferSelection;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpTlsAlert,
  TlpTlsVersion,
  TlpTlsLibExceptions,
  TlpExtensionContext,
  TlpITlsCredentialResolver,
  TlpTlsCredential;

type
  /// <summary>
  /// The version-neutral server-side selections a ClientHello drives: the ALPN protocol and,
  /// via the credential resolver, the server certificate for the requested SNI host. Both are
  /// pure of connection state - they read the client's offers and the server's configuration
  /// and either return a selection or abort with the RFC-mandated alert - so the 1.2 and 1.3
  /// server machines share one implementation.
  /// </summary>
  TServerOfferSelection = class sealed(TObject)
  public
    /// <summary>Selects the ALPN protocol for the flight (RFC 7301): the first server-preferred
    /// protocol the client also offered. Returns empty when the server is not configured for
    /// ALPN or the client offered none. Aborts with no_application_protocol when the server
    /// rejects all offers, or when it is configured and the client offered but nothing overlaps.</summary>
    class function SelectAlpn(const AServerProtocols, AClientOffered: TArray<string>;
      ARejectAll: Boolean): string; static;
    /// <summary>Selects the server certificate for this handshake from the client's SNI (virtual
    /// hosting) via AResolver, over the offers in AContext and ACipherSuites for AVersion. Aborts
    /// with handshake_failure when no resolver is configured, unrecognized_name when the client
    /// named a host the resolver has no certificate for (else handshake_failure with no name to
    /// be "unrecognized"), and handshake_failure when the resolved credential carries no signing
    /// key. The returned credential always has a signing key.</summary>
    class function ResolveCredential(const AResolver: ITlsServerCredentialResolver;
      const AContext: TExtensionContext; const ACipherSuites: TArray<UInt16>;
      AVersion: TTlsVersion): TTlsCredential; static;
  end;

implementation

resourcestring
  SNoAlpnOverlap =
    'the client offered no application protocol the server accepts';
  SNoServerCredential =
    'no server certificate is configured to authenticate the handshake';
  SNoCredentialForServerName =
    'no server certificate is configured for the requested SNI host';
  SNoDefaultServerCredential =
    'no default server certificate is configured for a client that sent no SNI';
  SCredentialHasNoSigningKey =
    'the selected server certificate has no signing key';

{ TServerOfferSelection }

class function TServerOfferSelection.SelectAlpn(const AServerProtocols,
  AClientOffered: TArray<string>; ARejectAll: Boolean): string;
var
  LPref, LOffered: string;
begin
  Result := '';
  // reject mode: any client ALPN offer is refused with no_application_protocol (RFC 7301 3.2)
  if ARejectAll and (System.Length(AClientOffered) > 0) then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.NoApplicationProtocol, @SNoAlpnOverlap);
  // no selection when the server is not configured for ALPN or the client did not offer it
  if (System.Length(AServerProtocols) = 0) or (System.Length(AClientOffered) = 0) then
    Exit;
  for LPref in AServerProtocols do
    for LOffered in AClientOffered do
      if LPref = LOffered then
        Exit(LPref);
  // configured, offered, but nothing overlaps (RFC 7301 3.2)
  raise EFatalAlertTlsLibException.CreateRes(
    TTlsAlertDescription.NoApplicationProtocol, @SNoAlpnOverlap);
end;

class function TServerOfferSelection.ResolveCredential(
  const AResolver: ITlsServerCredentialResolver; const AContext: TExtensionContext;
  const ACipherSuites: TArray<UInt16>; AVersion: TTlsVersion): TTlsCredential;
var
  LInfo: TTlsClientHelloInfo;
begin
  // a PSK-only server (nil resolver) has no certificate to fall back on
  if AResolver = nil then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.HandshakeFailure, @SNoServerCredential);
  LInfo.ServerName := AContext.ServerName;
  LInfo.SignatureSchemes := AContext.SignatureSchemes;
  LInfo.AlpnProtocols := AContext.AlpnProtocols;
  LInfo.CipherSuites := ACipherSuites;
  LInfo.SupportedGroups := AContext.SupportedGroups;
  LInfo.ProtocolVersion := AVersion;
  if not AResolver.TryResolve(LInfo, Result) then
  begin
    // no certificate for the requested host: unrecognized_name when the client named one
    // (RFC 6066 3), else handshake_failure with no name to be "unrecognized" (RFC 8446 6.2)
    if AContext.ServerName <> '' then
      raise EFatalAlertTlsLibException.CreateRes(
        TTlsAlertDescription.UnrecognizedName, @SNoCredentialForServerName);
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.HandshakeFailure, @SNoDefaultServerCredential);
  end;
  // a resolved credential with no signing key cannot complete certificate auth; reject it as a
  // handshake_failure rather than dereferencing a nil key during scheme selection
  if not Assigned(Result.PrivateKey) then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.HandshakeFailure, @SCredentialHasNoSigningKey);
end;

end.
