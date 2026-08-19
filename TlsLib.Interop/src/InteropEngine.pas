{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit InteropEngine;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

interface

uses
  SysUtils,
  TlpTlsVersion,
  TlpCryptoAlgorithms,
  TlpICryptoProvider,
  TlpDefaultCryptoProvider,
  TlpINamedGroup,
  TlpNamedGroups,
  TlpINegotiation,
  TlpSignatureSchemeRegistry,
  TlpICertificateTrust,
  TlpTlsAlert,
  TlpTlsCredential,
  TlpISession,
  TlpSession,
  TlpIClock,
  TlpITlsConfig,
  TlpITlsConfigBuilder,
  TlpTlsPresets,
  TlpITlsEngine,
  TlpTlsEngineFactory;

type
  /// <summary>Which side of the connection the harness engine plays.</summary>
  TInteropRole = (Client, Server);

  /// <summary>
  /// The transport-agnostic settings a harness driver turns into a wired engine:
  /// the role, the SNI/expected host, an optional explicit key-share/offered group
  /// set (empty keeps the preset default), ALPN, and the role's trust source or
  /// credential.
  /// </summary>
  TInteropEngineOptions = record
    Role: TInteropRole;
    ServerName: string;
    OfferedGroups: TArray<UInt16>;
    /// <summary>The client's offered signature schemes (verify preferences) as IANA
    /// codepoints; empty keeps the preset default set.</summary>
    VerifySchemes: TArray<UInt16>;
    /// <summary>A server that rejects any client ALPN offer with no_application_protocol.</summary>
    AlpnReject: Boolean;
    /// <summary>The DER DistinguishedName certificate_authorities a server names in its
    /// CertificateRequest (RFC 8446 4.2.4 / RFC 5246 7.4.4); empty names none.</summary>
    ClientCertificateAuthorities: TArray<TBytes>;
    /// <summary>The offered protocol versions (preference order); empty keeps the
    /// Compatible preset's TLS 1.3 + hardened 1.2 default.</summary>
    SupportedVersions: TArray<UInt16>;
    AlpnProtocols: TArray<string>;
    Trust: ITrustAnchorStore;
    CheckServerName: Boolean;
    /// <summary>When set, a server omits the empty server_name acknowledgement (RFC 6066 3).</summary>
    SuppressServerNameAck: Boolean;
    /// <summary>Whether a client sends GREASE (RFC 8701). Off unless the runner asks.</summary>
    Grease: Boolean;
    Credential: TTlsCredential;
    HasCredential: Boolean;
    /// <summary>The out-of-band external PSKs (RFC 9258) a client imports and offers or a
    /// server imports and matches, in preference order. Empty leaves external PSK off.</summary>
    ExternalPsks: TArray<TExternalPsk>;
    /// <summary>Whether a client with configured external PSKs requires one (rejects a
    /// certificate-only ServerHello). True unless the test also accepts a certificate.</summary>
    ExternalPskRequired: Boolean;
    /// <summary>A server's client-certificate policy (mutual TLS); None on a client.</summary>
    ClientAuth: TClientAuthMode;
    /// <summary>When True, the peer certificate chain is accepted without CA validation via
    /// an accept-any whole-verifier: a server requesting a client cert with no CA
    /// (-require-any-client-certificate), or a client given no trust anchor. Ignored when a
    /// trust store is supplied (the chain is then verified against it). The engine's
    /// structural checks (leaf parse, signature) still run before the verdict.</summary>
    AcceptAnyPeerCert: Boolean;
    /// <summary>A server's pre-fetched OCSP staple (DER) sent when the client offers
    /// status_request; empty leaves the server unstapled.</summary>
    OcspStaple: TBytes;
    /// <summary>The client-side session cache, shared across a resume-count loop so a
    /// later connection resumes an earlier one; nil disables client resumption.</summary>
    SessionCache: ISessionCache;
    /// <summary>The clock the client reads for a resumption PSK's obfuscated_ticket_age and
    /// ticket-lifetime expiry; nil uses the system clock. Injected so the harness can advance
    /// it by -resumption-delay to drive deterministic ticket timing.</summary>
    Clock: ITlsClock;
    SessionStore: ISessionStore;
    /// <summary>The server-side stateless ticket keys, shared across a resume-count loop;
    /// nil disables server ticket issuance/acceptance.</summary>
    SessionTicketKeys: ISessionTicketKeyManager;
    /// <summary>The client offers 0-RTT early data when a cached ticket authorizes it.</summary>
    OfferEarlyData: Boolean;
    /// <summary>The client offers status_request (OCSP stapling); off unless a test asks for
    /// a staple, so an unsolicited server staple is rejected.</summary>
    RequestOcsp: Boolean;
    /// <summary>The server's 0-RTT early-data byte budget (0 = no early data).</summary>
    MaxEarlyData: UInt32;
    /// <summary>When True, an augment-only verify callback that rejects is installed, so the
    /// peer-certificate verdict fails after the built-in pipeline accepts the chain (the
    /// harness's -verify-fail: verification must fail). Augment-only, so it never rescues an
    /// otherwise-rejected chain. Ignored under AsyncVerify, where the verdict is instead
    /// decided out-of-band via SetCertificateVerdict.</summary>
    VerifyFail: Boolean;
    /// <summary>When True, async certificate verdicts are enabled (the harness's -async): the
    /// handshake parks after the built-in pipeline accepts the peer chain and the driver
    /// resolves it out-of-band with SetCertificateVerdict. Inert where no peer certificate is
    /// verified (a server without client-auth). Exercises the deferred-verdict seam end to end.</summary>
    AsyncVerify: Boolean;
  end;

  /// <summary>
  /// Builds a wired ITlsEngine from the harness options over the default
  /// CryptoLib-backed provider, reusing the Compatible preset and the engine
  /// factory so the shim exercises the exact public composition an integrator uses.
  /// </summary>
  TInteropEngine = class sealed(TObject)
  strict private
    /// <summary>True when a non-empty offered-group set holds only KEM/hybrid groups:
    /// such a set is 1.3-only and cannot satisfy a TLS 1.2 handshake, which needs a
    /// classical ECDHE group.</summary>
    class function OnlyPostQuantumGroups(const AProvider: ICryptoProvider;
      const ACodes: TArray<UInt16>): Boolean; static;
    /// <summary>Returns AVersions without the TLS 1.2 wire version.</summary>
    class function WithoutTls12(const AVersions: TArray<UInt16>): TArray<UInt16>; static;
    /// <summary>An ordered signature-scheme registry built from IANA codepoints (unknown
    /// codepoints are skipped), for the client's -verify-prefs offer.</summary>
    class function SignatureSchemesFromCodes(
      const ACodes: TArray<UInt16>): ISignatureSchemeRegistry; static;
  public
    /// <summary>The default CryptoLib-backed crypto provider.</summary>
    class function DefaultProvider: ICryptoProvider; static;
    /// <summary>A client or server engine ready for the harness pump.</summary>
    class function Build(const AProvider: ICryptoProvider;
      const AOptions: TInteropEngineOptions): ITlsEngine; static;
  end;

implementation

type
  /// <summary>An augment-only verify callback that always rejects, held as a singleton so its
  /// method pointer stays valid for the life of the process (the harness's -verify-fail).</summary>
  TInteropRejectingVerifier = class sealed(TObject)
  public
    function Reject(const AChain: TArray<TBytes>;
      const AHostName: string): Boolean;
  end;

  /// <summary>A whole-verifier that accepts any presented client-certificate chain without
  /// CA validation (the harness's -require-any-client-certificate). An empty chain never
  /// reaches here - the Required client-auth mode rejects that first.</summary>
  TInteropAcceptAnyVerifier = class sealed(TInterfacedObject, ICertificateVerifier)
  public
    function Verify(const AChain: TArray<TBytes>; const AHostName: string;
      const AOcspStaple: TBytes; out AAlert: TTlsAlertDescription): Boolean;
  end;

var
  GRejecter: TInteropRejectingVerifier;

function TInteropRejectingVerifier.Reject(const AChain: TArray<TBytes>;
  const AHostName: string): Boolean;
begin
  Result := False;
end;

function TInteropAcceptAnyVerifier.Verify(const AChain: TArray<TBytes>;
  const AHostName: string; const AOcspStaple: TBytes;
  out AAlert: TTlsAlertDescription): Boolean;
begin
  AAlert := TTlsAlertDescription.CertificateRequired;
  Result := System.Length(AChain) > 0;
end;

{ TInteropEngine }

class function TInteropEngine.DefaultProvider: ICryptoProvider;
begin
  Result := TDefaultCryptoProvider.Create as ICryptoProvider;
end;

class function TInteropEngine.OnlyPostQuantumGroups(const AProvider: ICryptoProvider;
  const ACodes: TArray<UInt16>): Boolean;
var
  LRegistry: INamedGroupRegistry;
  LGroup: INamedGroup;
  LCode: UInt16;
begin
  Result := System.Length(ACodes) > 0;
  if not Result then
    Exit;
  LRegistry := TNamedGroups.CreateDefaultRegistry(AProvider);
  for LCode in ACodes do
    if LRegistry.TryGet(LCode, LGroup) and (LGroup.Kind = TNamedGroupKind.Ecdhe) then
      Exit(False);
end;

class function TInteropEngine.WithoutTls12(
  const AVersions: TArray<UInt16>): TArray<UInt16>;
var
  LVersion: UInt16;
  LN: Int32;
begin
  Result := nil;
  for LVersion in AVersions do
    if LVersion <> TlsWireVersionTls12 then
    begin
      LN := System.Length(Result);
      SetLength(Result, LN + 1);
      Result[LN] := LVersion;
    end;
end;

class function TInteropEngine.SignatureSchemesFromCodes(
  const ACodes: TArray<UInt16>): ISignatureSchemeRegistry;
var
  LCode: UInt16;
  LScheme: TSignatureScheme;
begin
  Result := TSignatureSchemeRegistry.Create;
  for LCode in ACodes do
    if TSignatureScheme.TryFromCode(LCode, LScheme) then
      Result.Add(LScheme);
end;

class function TInteropEngine.Build(const AProvider: ICryptoProvider;
  const AOptions: TInteropEngineOptions): ITlsEngine;
var
  LBuilder: ITlsConfigBuilder;
  LClient: ITlsClientConfigBuilder;
  LServer: ITlsServerConfigBuilder;
  LVersions: TArray<UInt16>;
  LCredential: TTlsCredential;
begin
  // Compatible seeds the suites, signature schemes, named-group registry and the
  // TLS 1.3 + hardened 1.2 version offer; the harness only overrides what a test dictates
  LBuilder := TTlsPresets.Compatible(AProvider);
  // a curve restriction to post-quantum-only groups is implicitly 1.3-only; drop the
  // 1.2 offer so the version/group pair stays consistent (the preset default offers 1.2)
  LVersions := AOptions.SupportedVersions;
  if OnlyPostQuantumGroups(AProvider, AOptions.OfferedGroups) then
    if System.Length(LVersions) = 0 then
      LVersions := TArray<UInt16>.Create(TlsWireVersionTls13)
    else
      LVersions := WithoutTls12(LVersions);

  if AOptions.Role = TInteropRole.Client then
  begin
    LClient := LBuilder.Client;
    if System.Length(AOptions.OfferedGroups) > 0 then
      LClient.WithPreferredGroups(AOptions.OfferedGroups);
    if System.Length(AOptions.VerifySchemes) > 0 then
      LClient.WithSignatureSchemes(SignatureSchemesFromCodes(AOptions.VerifySchemes));
    if System.Length(LVersions) > 0 then
      LClient.WithSupportedVersions(LVersions);
    if System.Length(AOptions.AlpnProtocols) > 0 then
      LClient.WithAlpnProtocols(AOptions.AlpnProtocols);
    // verify the server chain against the supplied trust anchor, or accept any chain when
    // the test supplies none (the leaf-parse and signature checks still run first)
    if AOptions.AcceptAnyPeerCert and (AOptions.Trust = nil) then
      LClient.WithCertificateVerifier(
        TInteropAcceptAnyVerifier.Create as ICertificateVerifier)
    else
      LClient.WithTrustStore(AOptions.Trust);
    LClient.WithNameCheck(AOptions.CheckServerName);
    // GREASE (RFC 8701) is optional; the shim keeps it off unless the runner enables it, so
    // deterministic assertions (e.g. exact key_share counts) are not perturbed
    LClient.WithGrease(AOptions.Grease);
    LClient.WithOcspStaplingRequest(AOptions.RequestOcsp);
    // async verdict (-async): park after the pipeline accepts and let the driver resolve the
    // verdict out-of-band. Otherwise -verify-fail installs an augment hook that rejects inline.
    if AOptions.AsyncVerify then
      LClient.WithAsyncCertificateVerdict(True, 0)
    else if AOptions.VerifyFail then
      LClient.WithCertificateVerifyCallback(GRejecter.Reject);
    // a mutual-TLS client presents its own credential when the server requests one
    if AOptions.HasCredential then
      LClient.WithCredential(AOptions.Credential);
    // out-of-band external PSKs (RFC 9258): imported and offered alongside a cached session
    if System.Length(AOptions.ExternalPsks) > 0 then
    begin
      LClient.WithExternalPreSharedKeys(AOptions.ExternalPsks);
      LClient.WithExternalPskRequired(AOptions.ExternalPskRequired);
    end;
    // resumption: the shared cache carries a ticket from an earlier connection; 0-RTT is
    // a separate opt-in on the 1.3 facet
    if AOptions.SessionCache <> nil then
      LClient.WithSessionCache(AOptions.SessionCache);
    if AOptions.Clock <> nil then
      LClient.WithClock(AOptions.Clock);
    if AOptions.OfferEarlyData then
      LClient.Tls13.WithEarlyData(True);
    Result := TTlsEngineFactory.CreateClientEngine(
      LClient.Build, AOptions.ServerName);
  end
  else
  begin
    LServer := LBuilder.Server;
    if System.Length(AOptions.OfferedGroups) > 0 then
      LServer.WithPreferredGroups(AOptions.OfferedGroups);
    if System.Length(LVersions) > 0 then
      LServer.WithSupportedVersions(LVersions);
    if System.Length(AOptions.AlpnProtocols) > 0 then
      LServer.WithAlpnProtocols(AOptions.AlpnProtocols);
    if AOptions.AlpnReject then
      LServer.WithAlpnRejection(True);
    if System.Length(AOptions.ClientCertificateAuthorities) > 0 then
      LServer.WithClientCertificateAuthorities(
        AOptions.ClientCertificateAuthorities);
    if AOptions.SuppressServerNameAck then
      LServer.WithServerNameAcknowledgement(False);
    // the stapled OCSP rides on the credential; the server sends it when the client
    // offers status_request
    LCredential := AOptions.Credential;
    if System.Length(AOptions.OcspStaple) > 0 then
      LCredential.OcspStaple := AOptions.OcspStaple;
    // a PSK-only server presents no certificate; only set a credential when one was supplied
    if AOptions.HasCredential then
      LServer.WithCredential(LCredential);
    // out-of-band external PSKs (RFC 9258): imported and matched against the ClientHello,
    // preferred over the certificate
    if System.Length(AOptions.ExternalPsks) > 0 then
      LServer.WithExternalPreSharedKeys(AOptions.ExternalPsks);
    // mutual TLS: request the client certificate and either verify it against the trust
    // store or, for -require-any-client-certificate, accept any chain via a whole-verifier
    if AOptions.ClientAuth <> TClientAuthMode.None then
    begin
      LServer.WithPeerAuth(AOptions.ClientAuth);
      if AOptions.AcceptAnyPeerCert and (AOptions.Trust = nil) then
        LServer.WithCertificateVerifier(
          TInteropAcceptAnyVerifier.Create as ICertificateVerifier)
      else
        LServer.WithTrustStore(AOptions.Trust);
      // async verdict (-async) parks after the pipeline accepts the client chain; otherwise
      // -verify-fail rejects it inline through the augment hook
      if AOptions.AsyncVerify then
        LServer.WithAsyncCertificateVerdict(True, 0)
      else if AOptions.VerifyFail then
        LServer.WithCertificateVerifyCallback(GRejecter.Reject);
    end;
    // resumption: the shared STEK issues and re-opens tickets across the resume-count loop;
    // 0-RTT authorizes early data on the 1.3 facet. With neither ticket keys nor a session store
    // the harness is driving a non-resumption scenario: opt out of resumption explicitly so the
    // engine issues no NewSessionTicket. The harness is exact about ticket presence and does not
    // lean on the engine's resume-by-default (which mints a STEK when resumption is left on).
    if (AOptions.SessionTicketKeys = nil) and (AOptions.SessionStore = nil) then
      LServer.WithResumption(False);
    if AOptions.SessionTicketKeys <> nil then
      LServer.WithSessionTicketKeys(AOptions.SessionTicketKeys);
    if AOptions.SessionStore <> nil then
      LServer.WithSessionStore(AOptions.SessionStore);
    // the injected clock drives the server's ticket-issue time and the 0-RTT ticket-age
    // freshness window (RFC 8446 8.2), advanced between connections by -resumption-delay
    if AOptions.Clock <> nil then
      LServer.WithClock(AOptions.Clock);
    if AOptions.MaxEarlyData > 0 then
      LServer.Tls13.WithEarlyData(AOptions.MaxEarlyData);
    Result := TTlsEngineFactory.CreateServerEngine(LServer.Build);
  end;
end;

initialization
  GRejecter := TInteropRejectingVerifier.Create;

finalization
  GRejecter.Free;

end.
