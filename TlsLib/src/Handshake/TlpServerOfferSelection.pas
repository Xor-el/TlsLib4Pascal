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
  TlpAlpnProtocols,
  TlpArrayUtilities,
  TlpTlsAlert,
  TlpTlsVersion,
  TlpNegotiationTypes,
  TlpTlsLibExceptions,
  TlpExtensionContext,
  TlpIPkixProvider,
  TlpChainAlgorithmPolicy,
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
    class function SelectAlpn(const AServerProtocols, AClientOffered: TArray<TBytes>;
      ARejectAll: Boolean): TBytes; static;
    /// <summary>Selects the server certificate for this handshake from the client's SNI (virtual
    /// hosting) via AResolver, over the offers in AContext and ACipherSuites for AVersion. Aborts
    /// with handshake_failure when no resolver is configured, unrecognized_name when the client
    /// named a host the resolver has no certificate for (else handshake_failure with no name to
    /// be "unrecognized"), and handshake_failure when the resolved credential carries no signing
    /// key or an empty chain. The returned credential always has both. Also handshake_failure
    /// when its chain is signed with MD5, or with SHA-1 the client did not advertise (RFC 9846
    /// 4.5.1.2; MD5 inferred from 4.5.1.3).</summary>
    class function ResolveCredential(const AResolver: ITlsServerCredentialResolver;
      const AInspector: ICertificateInspector; const AContext: TExtensionContext;
      const ACipherSuites: TArray<UInt16>; AVersion: TTlsVersion): TTlsCredential; static;
    /// <summary>Whether the client signals TLS_FALLBACK_SCSV although its highest known version
    /// is below AServerHighest (RFC 7507 3, obsoleted by RFC 8996).</summary>
    class function IsSpuriousFallback(const ACipherSuites,
      ASupportedVersions: TArray<UInt16>; ALegacyVersion,
      AServerHighest: UInt16): Boolean; static;
    /// <summary>Aborts with inappropriate_fallback when IsSpuriousFallback.</summary>
    class procedure RejectSpuriousFallback(const ACipherSuites,
      ASupportedVersions: TArray<UInt16>; ALegacyVersion,
      AServerHighest: UInt16); static;
    /// <summary>Aborts with protocol_version unless the ClientHello's legacy_version is 0x0303
    /// (RFC 9846 4.2.2). Call it only for a ClientHello that has supported_versions.</summary>
    class procedure RejectUnexpectedLegacyVersion(ALegacyVersion: UInt16); static;
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
  SCredentialHasNoCertificates =
    'the selected server credential has an empty certificate chain';
  SCredentialChainNotSendable =
    'the certificate chain is signed with MD5 or with SHA-1 the client did not advertise';
  SSpuriousFallback =
    'the client signalled TLS_FALLBACK_SCSV but the server supports a higher version';
  SUnexpectedLegacyVersion =
    'the ClientHello legacy_version is not 0x0303';

{ TServerOfferSelection }

class function TServerOfferSelection.SelectAlpn(const AServerProtocols,
  AClientOffered: TArray<TBytes>; ARejectAll: Boolean): TBytes;
var
  LPref: TBytes;
begin
  Result := nil;
  // reject mode (local policy): any client ALPN offer is refused with no_application_protocol
  // (the alert of RFC 7301 3.2)
  if ARejectAll and (System.Length(AClientOffered) > 0) then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.NoApplicationProtocol, @SNoAlpnOverlap);
  // no selection when the server is not configured for ALPN or the client did not offer it
  if (System.Length(AServerProtocols) = 0) or (System.Length(AClientOffered) = 0) then
    Exit;
  for LPref in AServerProtocols do
    if TAlpnProtocols.Contains(AClientOffered, LPref) then
      Exit(LPref);
  // configured, offered, but nothing overlaps (RFC 7301 3.2)
  raise EFatalAlertTlsLibException.CreateRes(
    TTlsAlertDescription.NoApplicationProtocol, @SNoAlpnOverlap);
end;

class function TServerOfferSelection.ResolveCredential(
  const AResolver: ITlsServerCredentialResolver; const AInspector: ICertificateInspector;
  const AContext: TExtensionContext; const ACipherSuites: TArray<UInt16>;
  AVersion: TTlsVersion): TTlsCredential;
var
  LInfo: TTlsClientHelloInfo;
  LCertSchemes: TArray<UInt16>;
begin
  // a PSK-only server (nil resolver) has no certificate to fall back on
  if AResolver = nil then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.HandshakeFailure, @SNoServerCredential);
  LInfo.ServerName := AContext.ServerName;
  LInfo.SignatureSchemes := AContext.SignatureSchemes;
  // signature_algorithms_cert governs certificate signatures, else signature_algorithms does
  if System.Length(AContext.SignatureSchemesCert) > 0 then
    LCertSchemes := AContext.SignatureSchemesCert
  else
    LCertSchemes := AContext.SignatureSchemes;
  LInfo.CertificateSignatureSchemes := LCertSchemes;
  LInfo.AlpnProtocols := TArrayUtilities.DeepCopy<Byte>(AContext.AlpnProtocols);
  LInfo.CipherSuites := ACipherSuites;
  LInfo.SupportedGroups := AContext.SupportedGroups;
  LInfo.ProtocolVersion := AVersion;
  if not AResolver.TryResolve(LInfo, Result) then
  begin
    // no certificate for the requested host: unrecognized_name when the client named one
    // (RFC 6066 3), else handshake_failure with no name to be "unrecognized" (RFC 9846 6.2)
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
  // an empty chain would emit an empty certificate_list (RFC 9846 4.5.1)
  if System.Length(Result.CertificateChain) = 0 then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.HandshakeFailure, @SCredentialHasNoCertificates);
  if not TChainAlgorithmPolicy.SendableTo(AInspector, Result.CertificateChain, LCertSchemes) then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.HandshakeFailure, @SCredentialChainNotSendable);
end;

class function TServerOfferSelection.IsSpuriousFallback(const ACipherSuites,
  ASupportedVersions: TArray<UInt16>; ALegacyVersion, AServerHighest: UInt16): Boolean;
var
  LClientHighest: UInt16;
begin
  LClientHighest := TTlsVersion.ClientHighest(ASupportedVersions, ALegacyVersion);
  Result := (LClientHighest <> 0) and (LClientHighest < AServerHighest) and
    (TArrayUtilities.Contains<UInt16>(ACipherSuites, TlsFallbackScsv));
end;

class procedure TServerOfferSelection.RejectSpuriousFallback(const ACipherSuites,
  ASupportedVersions: TArray<UInt16>; ALegacyVersion, AServerHighest: UInt16);
begin
  if IsSpuriousFallback(ACipherSuites, ASupportedVersions, ALegacyVersion,
    AServerHighest) then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.InappropriateFallback, @SSpuriousFallback);
end;

class procedure TServerOfferSelection.RejectUnexpectedLegacyVersion(
  ALegacyVersion: UInt16);
begin
  if ALegacyVersion <> TlsWireVersionTls12 then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.ProtocolVersion, @SUnexpectedLegacyVersion);
end;

end.
