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
  TlpArrayUtilities,
  TlpTlsVersion,
  TlpCryptoDomainTypes,
  TlpICryptoProvider,
  TlsLibTestProviders,
  TlpINamedGroup,
  TlpNamedGroups,
  TlpINegotiation,
  TlpSignatureSchemeRegistry,
  TlpICertificateTrust,
  TlpITrustAnchorStore,
  TlpTrustPolicy,
  TlpTrustTypes,
  TlpServerName,
  TlpTlsAlert,
  TlpTlsCredential,
  TlpISession,
  TlpSession,
  TlpIClock,
  TlpIEch,
  TlpEchConfig,
  TlpEchClient,
  TlpICertificateCompression,
  TlpITlsConfig,
  TlpITlsConfigBuilder,
  TlpITlsCredentialResolver,
  TlpCertificateVerifierSource,
  TlpTlsPresets,
  TlpITlsEngine,
  TlpTlsEngineFactory;

type
  /// <summary>Which side of the connection the harness engine plays.</summary>
  TInteropRole = (Client, Server);

  /// <summary>Told each ClientHello the server's credential resolver is asked about, so the harness
  /// can assert on the offer (ALPN, signature algorithms).</summary>
  IInteropClientHelloObserver = interface(IInterface)
    ['{4D400DD2-C5CD-4A5D-AD51-A242C29C673A}']
    procedure Observe(const AHello: TTlsClientHelloInfo);
  end;

  /// <summary>An augment-only verify callback that records the host each peer-certificate
  /// verification ran against, in order. It rejects when ARejectResume; in a 0-RTT reject test
  /// (ARetryState) a verification after a passing first one rejects when ARejectRetry.</summary>
  TInteropVerifyNameRecorder = class sealed(TInterfacedObject)
  strict private
  var
    FNames: TArray<string>;
    FRejectResume, FRejectRetry, FRetryState, FRetryRejected: Boolean;
  public
    constructor Create(ARejectResume, ARejectRetry, ARetryState: Boolean);
    function Observe(const APresented, AValidated: TArray<TBytes>;
      const AHostName: string): Boolean;
    property Names: TArray<string> read FNames;
    /// <summary>Whether a retry verification ran and was rejected.</summary>
    property RetryRejected: Boolean read FRetryRejected;
  end;

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
    /// CertificateRequest (RFC 9846 4.3.4 / RFC 5246 7.4.4); empty names none.</summary>
    ClientCertificateAuthorities: TArray<TBytes>;
    /// <summary>The offered protocol versions (preference order); empty keeps the
    /// Compatible preset's TLS 1.3 + hardened 1.2 default.</summary>
    SupportedVersions: TArray<UInt16>;
    /// <summary>The cipher-suite codes the harness restricts the suites to, in preference order
    /// (the shim's -cipher); empty keeps the preset's suites.</summary>
    CipherSuites: TArray<UInt16>;
    AlpnProtocols: TArray<TBytes>;
    Trust: ITrustAnchorStore;
    CheckServerName: Boolean;
    /// <summary>When set, a server omits the empty server_name acknowledgement (RFC 6066 3).</summary>
    SuppressServerNameAck: Boolean;
    /// <summary>When set, CertificateCompressors and CertificateDecompressors replace the
    /// config's defaults for this endpoint (an empty array turns that direction off); when
    /// clear the defaults stand.</summary>
    OverrideCertCompression: Boolean;
    CertificateCompressors: TArray<ICertificateCompressor>;
    CertificateDecompressors: TArray<ICertificateDecompressor>;
    /// <summary>How a TLS 1.2 server treats resuming a session set up without
    /// extended_master_secret (RFC 7627 5.3); the library default, Decline, unless the runner asks.
    /// Ignored when TLS 1.2 is not offered.</summary>
    NonEmsResumption: TNonEmsResumption;
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
    /// <summary>The TLS 1.2 pre-shared keys (RFC 4279 / RFC 5489): a client presents the first, a
    /// server accepts them all. Empty leaves the TLS 1.2 PSK suites off.</summary>
    Tls12Psks: TArray<TTls12Psk>;
    /// <summary>Whether a client holding a TLS 1.2 PSK offers only the PSK suites for TLS 1.2.</summary>
    Tls12PskRequired: Boolean;
    /// <summary>The psk_identity_hint a server sends (RFC 4279 5.2); empty sends none.</summary>
    Tls12PskIdentityHint: TBytes;
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
    /// <summary>The cache scope, shared across the resume-count loop so the per-connection
    /// rebuilt client configs resume each other (they are the same logical client).</summary>
    SessionScope: TBytes;
    /// <summary>The clock the client reads for a resumption PSK's obfuscated_ticket_age and
    /// ticket-lifetime expiry; nil uses the system clock. Injected so the harness can advance
    /// it by -resumption-delay to drive deterministic ticket timing.</summary>
    Clock: ITlsClock;
    SessionStore: ISessionStore;
    /// <summary>The server-side resumption scope, partitioning tickets when a supplied store or
    /// ticket-key manager is used under client authentication; empty leaves it unset.</summary>
    ResumptionScope: TBytes;
    /// <summary>The server-side stateless ticket keys, shared across a resume-count loop;
    /// nil disables server ticket issuance/acceptance.</summary>
    SessionTicketKeys: ISessionTicketKeyManager;
    /// <summary>The client offers 0-RTT early data when a cached ticket authorizes it.</summary>
    OfferEarlyData: Boolean;
    /// <summary>The client offers status_request (OCSP stapling); off unless a test asks for
    /// a staple, so an unsolicited server staple is rejected.</summary>
    RequestOcsp: Boolean;
    /// <summary>When True, the client's revocation posture is set to RevocationPosture;
    /// otherwise the preset default stands (so shims that do not drive revocation are
    /// unaffected).</summary>
    ApplyRevocation: Boolean;
    /// <summary>The client revocation posture applied under ApplyRevocation: Soft tolerates an
    /// indeterminate staple, Hard rejects it, Off skips the check. A definitive Revoked and an
    /// unsatisfied must-staple leaf reject regardless of this.</summary>
    RevocationPosture: TRevocationPosture;
    /// <summary>The server's 0-RTT early-data byte budget (0 = no early data).</summary>
    MaxEarlyData: UInt32;
    /// <summary>When True, an augment-only verify callback that rejects is installed, so the
    /// peer-certificate verdict fails after the built-in pipeline accepts the chain (the
    /// harness's -verify-fail: verification must fail). Augment-only, so it never rescues an
    /// otherwise-rejected chain. Ignored under AsyncVerify, where the verdict is instead
    /// decided out-of-band via SetCertificateVerdict.</summary>
    VerifyFail: Boolean;
    /// <summary>Records the host of each client verification; replaces the VerifyFail hook when set.</summary>
    VerifyNameRecorder: TInteropVerifyNameRecorder;
    /// <summary>When True, a resuming client re-runs its certificate verifier against the stored
    /// peer chain before offering the session (the harness's -reverify-on-resume); otherwise
    /// resumption reuses the original authentication. Beside VerifyFail the session is declined
    /// and the full handshake that follows fails.</summary>
    ReverifyOnResume: Boolean;
    /// <summary>When True, async certificate verdicts are enabled (the harness's -async): the
    /// handshake parks after the built-in pipeline accepts the peer chain and the driver
    /// resolves it out-of-band with SetCertificateVerdict. Inert where no peer certificate is
    /// verified (a server without client-auth). Exercises the deferred-verdict seam end to end.</summary>
    AsyncVerify: Boolean;
    /// <summary>A client's Encrypted Client Hello configuration (RFC 9849): the ECHConfigList
    /// it offers. Empty leaves ECH off.</summary>
    EchConfigList: TBytes;
    /// <summary>Whether a client sends a GREASE ECH when it has no usable config.</summary>
    EchGrease: Boolean;
    /// <summary>A server's Encrypted Client Hello key store (config + private key per config
    /// id); nil leaves ECH off, so an ECH-offering client is shared-mode rejected.</summary>
    EchKeyStore: IEchServerKeyStore;
    /// <summary>A server's observer of the ClientHellos its credential is resolved for; nil
    /// installs the credential directly.</summary>
    ClientHelloObserver: IInteropClientHelloObserver;
  end;

  /// <summary>
  /// Builds a wired ITlsEngine from the harness options over the default
  /// crypto provider, reusing the Compatible preset and the engine
  /// factory so the shim exercises the exact public composition an integrator uses.
  /// </summary>
  TInteropEngine = class sealed(TObject)
  strict private
    /// <summary>True when a non-empty offered-group set holds only KEM/hybrid groups:
    /// such a set is 1.3-only and cannot satisfy a TLS 1.2 handshake, which needs a
    /// classical ECDHE group.</summary>
    class function OnlyPostQuantumGroups(const ACryptoProvider: ICryptoProvider;
      const ACodes: TArray<UInt16>): Boolean; static;
    /// <summary>The client's ECH choice from the runner's list and GREASE flags: nil, Enable, or
    /// Grease (an unusable list falls back to GREASE only when GREASE was asked for).</summary>
    class function ClientEchMode(const ACryptoProvider: ICryptoProvider;
      const AOptions: TInteropEngineOptions): IEchClientMode; static;
    /// <summary>Returns AVersions without the TLS 1.2 wire version.</summary>
    class function WithoutTls12(const AVersions: TArray<UInt16>): TArray<UInt16>; static;
    // whether the version list offers TLS 1.3 (an empty list = the preset default, which does)
    class function Offers13(const AVersions: TArray<UInt16>): Boolean; static;
    // whether the version list offers TLS 1.2 (an empty list = the preset default, which does)
    class function Offers12(const AVersions: TArray<UInt16>): Boolean; static;
    /// <summary>An ordered signature-scheme registry built from IANA codepoints (unknown
    /// codepoints are skipped), for the client's -verify-prefs offer.</summary>
    class function SignatureSchemesFromCodes(
      const ACodes: TArray<UInt16>): ISignatureSchemeRegistry; static;
  public
    /// <summary>A client or server engine ready for the harness pump.</summary>
    class function Build(const ACryptoProvider: ICryptoProvider;
      const AOptions: TInteropEngineOptions): ITlsEngine; static;
  end;

implementation

type
  /// <summary>An augment-only verify callback that always rejects, held as a singleton so its
  /// method pointer stays valid for the life of the process (the harness's -verify-fail).</summary>
  TInteropRejectingVerifier = class sealed(TObject)
  public
    function Reject(const APresented, AValidated: TArray<TBytes>;
      const AHostName: string): Boolean;
  end;

  /// <summary>A whole-verifier that accepts any presented client-certificate chain without
  /// CA validation (the harness's -require-any-client-certificate). An empty chain never
  /// reaches here - the Required client-auth mode rejects that first.</summary>
  TInteropAcceptAnyVerifier = class sealed(TInterfacedObject,
    IServerCertificateVerifier, IClientCertificateVerifier)
  public
    function VerifyServerCertificate(const AChain: TArray<TBytes>;
      const AServerName: TServerName; const AOcspStaple: TBytes;
      out AVerified: TVerifiedChain;
      out AAlert: TTlsAlertDescription): Boolean;
    function VerifyClientCertificate(const AChain: TArray<TBytes>;
      out AVerified: TVerifiedChain;
      out AAlert: TTlsAlertDescription): Boolean;
  end;

  /// <summary>Resolves the one server credential for every ClientHello, telling the observer what
  /// the client offered.</summary>
  TInteropObservingResolver = class sealed(TInterfacedObject, ITlsServerCredentialResolver)
  strict private
    FCredential: TTlsCredential;
    FObserver: IInteropClientHelloObserver;
  public
    constructor Create(const ACredential: TTlsCredential;
      const AObserver: IInteropClientHelloObserver);
    function TryResolve(const AClientHello: TTlsClientHelloInfo;
      out ACredential: TTlsCredential): Boolean;
  end;

var
  GRejecter: TInteropRejectingVerifier;

constructor TInteropObservingResolver.Create(const ACredential: TTlsCredential;
  const AObserver: IInteropClientHelloObserver);
begin
  inherited Create;
  FCredential := ACredential;
  FObserver := AObserver;
end;

function TInteropObservingResolver.TryResolve(const AClientHello: TTlsClientHelloInfo;
  out ACredential: TTlsCredential): Boolean;
begin
  FObserver.Observe(AClientHello);
  ACredential := FCredential;
  Result := True;
end;

constructor TInteropVerifyNameRecorder.Create(ARejectResume, ARejectRetry,
  ARetryState: Boolean);
begin
  inherited Create;
  FRejectResume := ARejectResume;
  FRejectRetry := ARejectRetry;
  FRetryState := ARetryState;
end;

function TInteropVerifyNameRecorder.Observe(const APresented, AValidated: TArray<TBytes>;
  const AHostName: string): Boolean;
var
  LRetry: Boolean;
begin
  TArrayUtilities.Append<string>(FNames, AHostName);
  // a failed first check offers no 0-RTT, so the connection stays in the resume phase
  LRetry := (System.Length(FNames) > 1) and FRetryState and (not FRejectResume);
  if LRetry then
  begin
    FRetryRejected := FRejectRetry;
    Result := not FRejectRetry;
  end
  else
    Result := not FRejectResume;
end;

function TInteropRejectingVerifier.Reject(const APresented, AValidated: TArray<TBytes>;
  const AHostName: string): Boolean;
begin
  Result := False;
end;

function TInteropAcceptAnyVerifier.VerifyServerCertificate(const AChain: TArray<TBytes>;
  const AServerName: TServerName; const AOcspStaple: TBytes;
  out AVerified: TVerifiedChain;
  out AAlert: TTlsAlertDescription): Boolean;
begin
  AVerified := Default(TVerifiedChain);
  AAlert := TTlsAlertDescription.CertificateRequired;
  Result := System.Length(AChain) > 0;
  if Result then
  begin
    AVerified.Path := AChain;
    AVerified.Outcome := TVerificationOutcome.Trusted;
  end;
end;

function TInteropAcceptAnyVerifier.VerifyClientCertificate(const AChain: TArray<TBytes>;
  out AVerified: TVerifiedChain;
  out AAlert: TTlsAlertDescription): Boolean;
begin
  AVerified := Default(TVerifiedChain);
  AAlert := TTlsAlertDescription.CertificateRequired;
  Result := System.Length(AChain) > 0;
  if Result then
  begin
    AVerified.Path := AChain;
    AVerified.Outcome := TVerificationOutcome.Trusted;
  end;
end;

{ TInteropEngine }

class function TInteropEngine.OnlyPostQuantumGroups(const ACryptoProvider: ICryptoProvider;
  const ACodes: TArray<UInt16>): Boolean;
var
  LRegistry: INamedGroupRegistry;
  LGroup: INamedGroup;
  LCode: UInt16;
begin
  Result := System.Length(ACodes) > 0;
  if not Result then
    Exit;
  LRegistry := TNamedGroups.CreateDefaultRegistry(ACryptoProvider);
  for LCode in ACodes do
    if LRegistry.TryGet(LCode, LGroup) and (LGroup.Kind = TNamedGroupKind.Ecdhe) then
      Exit(False);
end;

class function TInteropEngine.ClientEchMode(const ACryptoProvider: ICryptoProvider;
  const AOptions: TInteropEngineOptions): IEchClientMode;
var
  LConfig: TEchConfig;
  LSuite: IHpkeSuite;
begin
  Result := nil;
  if System.Length(AOptions.EchConfigList) > 0 then
  begin
    // an unusable list degrades to GREASE only on request; otherwise Build refuses it
    if AOptions.EchGrease and not TEchConfigList.TrySelect(
      TEchConfigList.Parse(AOptions.EchConfigList), ACryptoProvider, LConfig, LSuite) then
      Result := TEchClientModes.Grease
    else
      Result := TEchClientModes.Enable(AOptions.EchConfigList);
  end
  else if AOptions.EchGrease then
    Result := TEchClientModes.Grease;
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

class function TInteropEngine.Offers13(const AVersions: TArray<UInt16>): Boolean;
var
  LVersion: UInt16;
begin
  if System.Length(AVersions) = 0 then
    Exit(True);
  for LVersion in AVersions do
    if LVersion = TlsWireVersionTls13 then
      Exit(True);
  Result := False;
end;

class function TInteropEngine.Offers12(const AVersions: TArray<UInt16>): Boolean;
var
  LVersion: UInt16;
begin
  if System.Length(AVersions) = 0 then
    Exit(True);
  for LVersion in AVersions do
    if LVersion = TlsWireVersionTls12 then
      Exit(True);
  Result := False;
end;

class function TInteropEngine.SignatureSchemesFromCodes(
  const ACodes: TArray<UInt16>): ISignatureSchemeRegistry;
var
  LBuilder: ISignatureSchemeRegistryBuilder;
  LCode: UInt16;
  LScheme: TSignatureScheme;
begin
  LBuilder := TSignatureSchemeRegistryBuilder.Create as ISignatureSchemeRegistryBuilder;
  for LCode in ACodes do
    if TSignatureScheme.TryFromCode(LCode, LScheme) then
      LBuilder.Add(LScheme);
  Result := LBuilder.Build;
end;

class function TInteropEngine.Build(const ACryptoProvider: ICryptoProvider;
  const AOptions: TInteropEngineOptions): ITlsEngine;
var
  LBuilder: ITlsConfigBuilder;
  LClient: ITlsClientConfigBuilder;
  LServer: ITlsServerConfigBuilder;
  LVersions: TArray<UInt16>;
  LCredential: TTlsCredential;
  LResumptionOff: Boolean;
  LPosture: TRevocationPosture;
  LEchMode: IEchClientMode;
  LCertPath, LRequestsCert: Boolean;
begin
  // Compatible seeds the suites, signature schemes, named-group registry and the
  // TLS 1.3 + hardened 1.2 version offer; the harness only overrides what a test dictates
  LBuilder := TTlsPresets.Compatible(ACryptoProvider, TTlsLibTestProviders.Pkix);
  // a curve restriction to post-quantum-only groups, and a certificate-less PSK server (external
  // PSKs are TLS 1.3-only), are implicitly 1.3-only; drop the 1.2 offer so the version pair stays
  // consistent (the preset default offers 1.2)
  LVersions := AOptions.SupportedVersions;
  if OnlyPostQuantumGroups(ACryptoProvider, AOptions.OfferedGroups) or
    ((AOptions.Role = TInteropRole.Server) and (not AOptions.HasCredential) and
    (System.Length(AOptions.ExternalPsks) > 0) and (System.Length(AOptions.Tls12Psks) = 0)) then
    if System.Length(LVersions) = 0 then
      LVersions := TArray<UInt16>.Create(TlsWireVersionTls13)
    else
      LVersions := WithoutTls12(LVersions);
  // a certificate-less server holding only a TLS 1.2 PSK serves TLS 1.2 alone
  if (AOptions.Role = TInteropRole.Server) and (not AOptions.HasCredential) and
    (System.Length(AOptions.Tls12Psks) > 0) and (System.Length(AOptions.ExternalPsks) = 0) then
    LVersions := TArray<UInt16>.Create(TlsWireVersionTls12);

  if AOptions.Role = TInteropRole.Client then
  begin
    LClient := LBuilder.Client;
    LEchMode := ClientEchMode(ACryptoProvider, AOptions);
    // a real ECH offer is TLS 1.3-only; the runner's version pair is narrowed to match
    if (LEchMode <> nil) and (not LEchMode.IsGrease) then
      LVersions := TArray<UInt16>.Create(TlsWireVersionTls13);
    if System.Length(AOptions.OfferedGroups) > 0 then
      LClient.WithPreferredGroups(AOptions.OfferedGroups);
    if System.Length(AOptions.VerifySchemes) > 0 then
      LClient.WithSignatureSchemes(SignatureSchemesFromCodes(AOptions.VerifySchemes));
    if System.Length(LVersions) > 0 then
      LClient.WithSupportedVersions(LVersions);
    if System.Length(AOptions.CipherSuites) > 0 then
      LClient.WithCipherSuiteList(AOptions.CipherSuites);
    if System.Length(AOptions.AlpnProtocols) > 0 then
      LClient.WithAlpnProtocols(AOptions.AlpnProtocols);
    // verify the server chain against the supplied trust anchor, or accept any chain when
    // the test supplies none (the leaf-parse and signature checks still run first)
    // a PSK-only client verifies no certificate, so the settings that act on one are left off it
    LCertPath := (AOptions.Trust <> nil) or AOptions.AcceptAnyPeerCert;
    LPosture := TRevocationPosture.Soft;
    if AOptions.ApplyRevocation then
      LPosture := AOptions.RevocationPosture;
    if AOptions.AcceptAnyPeerCert and (AOptions.Trust = nil) then
      LClient.WithServerVerification(TServerVerification.Custom(
        TInteropAcceptAnyVerifier.Create as IServerCertificateVerifier, LPosture))
    else if AOptions.Trust <> nil then
      LClient.WithServerVerification(
        TServerVerification.WebPki(AOptions.Trust).WithRevocation(LPosture).Build);
    // name checking is on by default; the shim disables the RFC 9525 match when the runner
    // did not ask for it (BoGo drives host identity via -expect-* assertions, not the match)
    if LCertPath and (not AOptions.CheckServerName) then
      LClient.WithDangerousDisableServerNameCheck;
    // GREASE (RFC 8701) is optional; the shim keeps it off unless the runner enables it, so
    // deterministic assertions (e.g. exact key_share counts) are not perturbed
    LClient.WithGrease(AOptions.Grease);
    LClient.WithOcspStaplingRequest(AOptions.RequestOcsp);
    // async verdict (-async): park after the pipeline accepts and let the driver resolve the
    // verdict out-of-band. Otherwise -verify-fail installs an augment hook that rejects inline.
    if LCertPath and AOptions.AsyncVerify then
      LClient.WithAsyncCertificateVerdict(0)
    else if LCertPath and (AOptions.VerifyNameRecorder <> nil) then
      LClient.WithCertificateVerifyCallback(AOptions.VerifyNameRecorder.Observe)
    else if LCertPath and AOptions.VerifyFail then
      LClient.WithCertificateVerifyCallback(GRejecter.Reject);
    // a mutual-TLS client presents its own credential when the server requests one
    if LCertPath and AOptions.HasCredential then
      LClient.WithCredential(AOptions.Credential);
    // out-of-band external PSKs (RFC 9258): imported and offered alongside a cached session
    if System.Length(AOptions.ExternalPsks) > 0 then
    begin
      LClient.Tls13.WithExternalPreSharedKeys(AOptions.ExternalPsks);
      LClient.Tls13.WithExternalPskRequired(AOptions.ExternalPskRequired);
    end;
    // a TLS 1.2 PSK (RFC 5489) is presented when the server selects a PSK suite
    if (System.Length(AOptions.Tls12Psks) > 0) and Offers12(LVersions) then
    begin
      LClient.Tls12.WithPreSharedKey(AOptions.Tls12Psks[0]);
      LClient.Tls12.WithPreSharedKeyRequired(AOptions.Tls12PskRequired);
    end;
    // resumption: the shared cache carries a ticket from an earlier connection; 0-RTT is
    // a separate opt-in on the 1.3 facet
    if AOptions.SessionCache <> nil then
    begin
      // a per-connection rebuild without a shared scope would silently never resume; make the
      // omission a loud harness error rather than an unexplained interop mismatch
      if System.Length(AOptions.SessionScope) = 0 then
        raise Exception.Create('a shared interop session cache requires a shared scope');
      LClient.WithSessionCache(AOptions.SessionCache);
      LClient.WithResumptionScope(AOptions.SessionScope);
    end;
    if LCertPath and AOptions.ReverifyOnResume then
      LClient.WithResumeVerification(TResumeVerification.Reverify);
    if AOptions.Clock <> nil then
      LClient.WithClock(AOptions.Clock);
    if AOptions.OfferEarlyData then
      LClient.Tls13.WithEarlyData(True);
    if LEchMode <> nil then
      LClient.Tls13.WithEch(LEchMode);
    // the client compresses only a certificate it sends, and decompresses only a server's
    if AOptions.OverrideCertCompression and LCertPath then
    begin
      LClient.Tls13.WithCertificateDecompressors(AOptions.CertificateDecompressors);
      if AOptions.HasCredential then
        LClient.Tls13.WithCertificateCompressors(AOptions.CertificateCompressors);
    end;
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
    if System.Length(AOptions.CipherSuites) > 0 then
      LServer.WithCipherSuiteList(AOptions.CipherSuites);
    if System.Length(AOptions.AlpnProtocols) > 0 then
      LServer.WithAlpnProtocols(AOptions.AlpnProtocols);
    if AOptions.AlpnReject then
      LServer.WithAlpnRejection(True);
    if System.Length(AOptions.ClientCertificateAuthorities) > 0 then
      LServer.WithClientCertificateAuthorities(
        AOptions.ClientCertificateAuthorities);
    if AOptions.SuppressServerNameAck then
      LServer.WithServerNameAcknowledgement(False);
    // a certificate-less (PSK-only) server requests no client certificate and sends none
    LRequestsCert := (AOptions.ClientAuth <> TClientAuthMode.None) and AOptions.HasCredential;
    // the server compresses only a certificate it sends, and decompresses only a client's
    if AOptions.OverrideCertCompression then
    begin
      if AOptions.HasCredential then
        LServer.Tls13.WithCertificateCompressors(AOptions.CertificateCompressors);
      if LRequestsCert then
        LServer.Tls13.WithCertificateDecompressors(AOptions.CertificateDecompressors);
    end;
    // with neither ticket keys nor a store nor early data the server runs with resumption off,
    // where a non-EMS resumption mode has nothing to act on
    LResumptionOff := (AOptions.SessionTicketKeys = nil) and (AOptions.SessionStore = nil) and
      (AOptions.MaxEarlyData = 0);
    if Offers12(LVersions) and (AOptions.NonEmsResumption <> TNonEmsResumption.Decline) and
      not LResumptionOff then
      LServer.Tls12.WithNonEmsResumption(AOptions.NonEmsResumption);
    // the stapled OCSP rides on the credential; the server sends it when the client
    // offers status_request
    LCredential := AOptions.Credential;
    if System.Length(AOptions.OcspStaple) > 0 then
      LCredential.OcspStaple := AOptions.OcspStaple;
    // a PSK-only server presents no certificate; only set a credential when one was supplied
    if AOptions.HasCredential then
    begin
      if AOptions.ClientHelloObserver <> nil then
        LServer.WithCredentialResolver(TInteropObservingResolver.Create(LCredential,
          AOptions.ClientHelloObserver) as ITlsServerCredentialResolver)
      else
        LServer.WithCredential(LCredential);
    end;
    // out-of-band external PSKs (RFC 9258): imported and matched against the ClientHello,
    // preferred over the certificate
    if System.Length(AOptions.ExternalPsks) > 0 then
      LServer.Tls13.WithExternalPreSharedKeys(AOptions.ExternalPsks);
    if (System.Length(AOptions.Tls12Psks) > 0) and Offers12(LVersions) then
    begin
      LServer.Tls12.WithPreSharedKeys(AOptions.Tls12Psks);
      if System.Length(AOptions.Tls12PskIdentityHint) > 0 then
        LServer.Tls12.WithPreSharedKeyIdentityHint(AOptions.Tls12PskIdentityHint);
    end;
    // mutual TLS: request the client certificate and either verify it against the trust
    // store or, for -require-any-client-certificate, accept any chain via a whole-verifier
    if LRequestsCert then
    begin
      LServer.WithPeerAuth(AOptions.ClientAuth);
      if AOptions.AcceptAnyPeerCert and (AOptions.Trust = nil) then
        LServer.WithClientVerification(TClientVerification.Custom(
          TInteropAcceptAnyVerifier.Create as IClientCertificateVerifier))
      else if AOptions.Trust <> nil then
        LServer.WithClientVerification(TClientVerification.WebPki(AOptions.Trust).Build);
      // async verdict (-async) parks after the pipeline accepts the client chain; otherwise
      // -verify-fail rejects it inline through the augment hook
      if AOptions.AsyncVerify then
        LServer.WithAsyncCertificateVerdict(0)
      else if AOptions.VerifyFail then
        LServer.WithCertificateVerifyCallback(GRejecter.Reject);
    end;
    // resumption: the shared STEK issues and re-opens tickets across the resume-count loop;
    // 0-RTT authorizes early data on the 1.3 facet. With neither ticket keys nor a session store
    // the harness is driving a non-resumption scenario: opt out of resumption explicitly so the
    // engine issues no NewSessionTicket. The harness is exact about ticket presence and does not
    // lean on the engine's resume-by-default (which mints a STEK when resumption is left on).
    // Early data is the exception: it is offered only on a resumed session, so a server authorizing
    // it keeps resumption on (minting the default STEK) to issue an early-data-capable ticket.
    if LResumptionOff then
      LServer.WithResumption(False);
    if AOptions.SessionTicketKeys <> nil then
      LServer.WithSessionTicketKeys(AOptions.SessionTicketKeys);
    if AOptions.SessionStore <> nil then
      LServer.WithSessionStore(AOptions.SessionStore);
    // a scope partitions tickets, so it means nothing with resumption off
    if (System.Length(AOptions.ResumptionScope) > 0) and not LResumptionOff then
      LServer.WithResumptionScope(AOptions.ResumptionScope);
    // the injected clock drives the server's ticket-issue time and the 0-RTT ticket-age
    // freshness window (RFC 9846 8.3), advanced between connections by -resumption-delay
    if AOptions.Clock <> nil then
      LServer.WithClock(AOptions.Clock);
    if AOptions.MaxEarlyData > 0 then
      LServer.Tls13.WithEarlyData(AOptions.MaxEarlyData);
    // Encrypted Client Hello (RFC 9849): the key store holds a config + private key per
    // config id; trial decryption lets the server match a client that hid the config id
    if AOptions.EchKeyStore <> nil then
      LServer.Tls13.WithEchKeyStore(AOptions.EchKeyStore, True)
    // the peer's ECH tests drive a keyless server that must confirm a forwarded inner-type ech
    // (split-mode backend, RFC 9849 sec. 7.2); opt in so those cases behave as the peer expects.
    // Only when 1.3 is offered - the backend role is 1.3-only, and forcing it on a 1.2-capped
    // server would fail the build
    else if Offers13(LVersions) then
      LServer.Tls13.WithEchBackend;
    Result := TTlsEngineFactory.CreateServerEngine(LServer.Build);
  end;
end;

initialization
  GRejecter := TInteropRejectingVerifier.Create;

finalization
  GRejecter.Free;

end.
