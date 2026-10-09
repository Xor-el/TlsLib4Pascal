{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

/// <summary>
/// The host-neutral core the framework integration adapters share: a value snapshot of everything a
/// host maps onto a TLS configuration, the single config-composition site that turns it into a
/// frozen client/server config (with the build-once memo and the config-in conflict guard), a timed
/// transport base that bounds the handshake read, and a session that drives one connection and
/// surfaces its negotiated facts. No host-library type appears here, and the trust composition
/// reaches the OS system-trust source only through ISystemTrustInstaller, so this unit never depends
/// on the system-trust package.
/// </summary>
unit TlpTlsConnection;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  Classes,
  TlpIClock,
  TlpClock,
  TlpTlsAlert,
  TlpTlsVersion,
  TlpArrayUtilities,
  TlpNegotiationTypes,
  TlpCipherSuiteCatalog,
  TlpEchConfig,
  TlpServerName,
  TlpICryptoProvider,
  TlpDefaultCryptoProvider,
  TlpIPkixProvider,
  TlpDefaultPkixProvider,
  TlpICertificateTrust,
  TlpITrustAnchorStore,
  TlpTrustPolicy,
  TlpTrustTypes,
  TlpTlsCredential,
  TlpITlsConfig,
  TlpITlsConfigBuilder,
  TlpISystemTrustInstaller,
  TlpTlsPresets,
  TlpITlsEngine,
  TlpTlsEngineFactory,
  TlpITlsConfigMemo,
  TlpTlsSignatureBuilder,
  TlpISession,
  TlpInMemorySessionCache,
  TlpITlsTransport,
  TlpTlsConnectionInfo,
  TlpTlsLibExceptions,
  TlpTlsStream;

type
  /// <summary>Where a certificate, key or anchor bundle comes from: inline bytes, or a file read
  /// when the config is built. Empty when neither is set. Signed by digest (bytes) or by path+stat
  /// (file) for the build-once config identity, so a rotated file rebuilds and unchanged bytes
  /// reuse.</summary>
  TTlsBlobSource = record
    FileName: string;
    Data: TBytes;
    class function FromFile(const APath: string): TTlsBlobSource; static;
    class function FromBytes(const AData: TBytes): TTlsBlobSource; static;
    function IsEmpty: Boolean;
  end;

  /// <summary>Everything a host integration maps onto the TLS configuration, in host-neutral form:
  /// the providers, the credential and trust sources, the verify posture, the neutral hooks and the
  /// two role-specific verdict resolvers, ALPN, resumption, the handshake read cap, and the
  /// fully-built config that replaces the whole options-driven build. A value: an adapter fills one
  /// snapshot per handshake, so a concurrent change to a process-wide setter is never seen
  /// half-applied.</summary>
  TTlsOptions = record
    Crypto: ICryptoProvider;                     // nil = TDefaultCryptoProvider.Shared
    Pkix: IPkixProvider;                         // nil = TDefaultPkixProvider.Shared
    Certificate: TTlsBlobSource;          // own chain (server: required; client: mTLS)
    PrivateKey: TTlsBlobSource;
    KeyPassword: string;
    TrustAnchors: TArray<TTlsBlobSource>; // each -> WithTrustAnchors (union)
    // client role: opt into the OS store (union); a server never reads it (system trust is not a client-CA)
    SystemTrust: ISystemTrustInstaller;
    CustomTrustStore: ITrustAnchorStore;         // WithTrustStore (union)
    ServerCertificateVerifier: IServerCertificateVerifier;   // client role; replaces the pipeline
    ClientCertificateVerifier: IClientCertificateVerifier;   // server role; replaces the pipeline
    VerifyPeer: Boolean;                         // default True
    InsecureSkipVerify: Boolean;                 // default False
    CheckHostName: Boolean;                      // default True
    ServerNameIndication: TServerNameIndication; // client: Omit sends no SNI; the host is still verified
    ClientAuth: TClientAuthMode;                 // server: None never requests; a mode needs a client-trust source
    AlpnProtocols: TArray<string>;
    VerifyCallback: TTlsCertificateVerifyCallback;
    ClientVerdictResolver: TCertificateVerdictResolver;
    ClientVerdictDeadlineMs: Cardinal;
    ServerVerdictResolver: TCertificateVerdictResolver;
    ServerVerdictDeadlineMs: Cardinal;
    SessionResumption: Boolean;                  // default True
    HandshakeTimeoutMs: Int32;                   // 0 = the library default (30 000 ms)
    SupportedVersions: TArray<UInt16>;           // wire codes in preference order; empty = TLS 1.3 + 1.2
    CipherSuites: TArray<UInt16>;                // host cipher list, wire codes in preference order; empty = the preset
    ClientConfig: ITlsClientConfig;              // config-in: replaces the client build
    ServerConfig: ITlsServerConfig;              // config-in: replaces the server build
    TrustSourceHint: string;                     // client-role host knob names, spliced into the no-source message
    ClientAuthSourceHint: string;                // server-role client-CA host knob names, same use
    CipherSuitesHint: string;                    // the host property CipherSuites came from, spliced into build-time messages
    /// <summary>A value with the composable defaults: VerifyPeer / CheckHostName / SessionResumption
    /// on, SNI sent, client authentication opt-in (ClientAuth None). Assign it at snapshot
    /// time.</summary>
    class function Default: TTlsOptions; static;
  end;

  /// <summary>Maps a host's cipher-list string onto catalog suites: exact IANA or traditional
  /// cipher-list names separated by ':', ',', ';', spaces or tabs, in preference order, matched
  /// without regard to case and de-duplicated (the first position wins). Empty or HostDefault alone is the host default (an
  /// empty result: the preset applies). Any other token - a cipher-string expression or a suite
  /// this library does not implement - is refused, never skipped; so is HostDefault combined with
  /// names.</summary>
  THostCipherList = class sealed(TObject)
  public const
    /// <summary>The cipher-list value hosts ship as their own default; a no-op here.</summary>
    HostDefault = 'DEFAULT';
  public
    /// <summary>The wire codes AText names, in order. APropertyName is the host property the string
    /// came from, named in the refusal.</summary>
    class function Parse(const AText, APropertyName: string): TArray<UInt16>; static;
  end;

  /// <summary>The single site that composes an adapter's TLS configuration from its options, memoises
  /// it, and guards a supplied config against the options it would silently replace. Every method is
  /// static: the composer holds no state.</summary>
  TTlsConfigComposer = class sealed(TObject)
  strict private
    class function Load(const ASource: TTlsBlobSource): TBytes; static;
    class procedure Sign(var ASig: TTlsSignatureBuilder; const AName: string;
      const ASource: TTlsBlobSource); static;
    class function HasTrustAnchor(const AOptions: TTlsOptions): Boolean; static;
    class function HasClientTrustSource(const AOptions: TTlsOptions): Boolean; static;
    class function HasClientAuthTrustSource(const AOptions: TTlsOptions): Boolean; static;
    /// <summary>The versions left once TLS 1.2 is dropped for a host cipher list that names no TLS
    /// 1.2 suite; TLS 1.3 stays because a host cipher list never governed it. Raises when none
    /// remains.</summary>
    class function HostListVersions(const AOptions: TTlsOptions): TArray<UInt16>; static;
  public
    class function EffectiveCrypto(const AOptions: TTlsOptions): ICryptoProvider; static;
    class function EffectivePkix(const AOptions: TTlsOptions): IPkixProvider; static;
    /// <summary>The options-driven client config (the build the memo caches). Raises
    /// ETlsStreamError(internal_error) when verification is on and no trust source is named.</summary>
    class function BuildClientConfig(const AOptions: TTlsOptions): ITlsClientConfig; static;
    /// <summary>The options-driven server config. Raises without a certificate. Requests client
    /// authentication only when AOptions.ClientAuth is not None, and arms the live-revocation verdict
    /// park for the server-role resolver only then. A mode without a client-CA, with peer
    /// verification off, or a client-cert verifier supplied with mode None, all raise. System trust
    /// is a client-role source and is not read here (a server's client-CA is always caller-supplied).</summary>
    class function BuildServerConfig(const AOptions: TTlsOptions): ITlsServerConfig; static;
    class function ClientSignature(const AOptions: TTlsOptions): string; static;
    class function ServerSignature(const AOptions: TTlsOptions): string; static;
    /// <summary>Raises when a fully-built config is supplied together with an option the same role's
    /// options-driven build would consume and the config therefore silently replaces (APropertyName
    /// names the config property in the message). Role-aware: only the client build reads the augment
    /// callback, the server-cert verifier, peer verification, the skip-verify bypass, the
    /// host-name check and server-name indication; only the server build reads the client-cert
    /// verifier; resumption is read by both. A security toggle conflicts only when set away from
    /// its default - a host that both changed a toggle and supplied a config that ignores it. The
    /// verdict resolvers and the handshake timeout are runtime hooks and never conflict.</summary>
    class procedure GuardNoConflict(const AOptions: TTlsOptions;
      AIsClient: Boolean; const APropertyName: string); static;
    /// <summary>The client config for one handshake: the supplied ClientConfig (after the conflict
    /// guard, and refused when a verdict resolver is set but the config never defers), else the
    /// memoised options-driven build.</summary>
    class function ResolveClientConfig(const AOptions: TTlsOptions;
      const AMemo: ITlsClientConfigMemo;
      const AConfigPropertyName: string): ITlsClientConfig; static;
    class function ResolveServerConfig(const AOptions: TTlsOptions;
      const AMemo: ITlsServerConfigMemo;
      const AConfigPropertyName: string): ITlsServerConfig; static;
  end;

  /// <summary>An ITlsTransport over a host socket whose reads can be bounded for the handshake phase:
  /// with a cap armed, the reads that follow share one deadline, and a read past it raises
  /// ETlsHandshakeTimeout (a silent, dead or trickling peer is reaped rather than parking the
  /// thread); with the cap cleared reads block, as application reads must. A host supplies the
  /// readiness wait and the raw receive/send.</summary>
  TTlsTimedTransportBase = class abstract(TInterfacedObject, ITlsTransport)
  strict private
  var
    FReadTimeoutMs: Int32;
    FDeadlineMs: Int64; // monotonic ms the armed cap expires at
    FApplicationRead: Boolean; // the armed cap bounds an application read, not the handshake
    FClock: ITlsMonotonicClock;
    procedure RaiseCapElapsed;
  strict protected
    /// <summary>True when at least one byte can be read within AMs ms. The default waits nowhere and
    /// returns True, for a host that bounds the socket itself (a receive timeout on the handle) and
    /// reports the elapsed cap from ReceiveRaw.</summary>
    function WaitReadable(AMs: Int32): Boolean; virtual;
    /// <summary>One blocking receive: the count, 0 on an orderly close, a negative value for a host
    /// receive error (which the base surfaces as ETlsStreamError, never as end of stream). A host
    /// whose socket bounds its own receives raises the elapsed cap itself: ETlsHandshakeTimeout
    /// while ReadTimeoutMs is armed, else the retryable ETlsReadTimeout (an idle application read
    /// is never end of stream).</summary>
    function ReceiveRaw(var ABuffer: TBytes; AOffset, AMaxLength: Int32): Int32; virtual; abstract;
    /// <summary>One send of up to ALength bytes; returns the count sent (> 0) or raises.</summary>
    function SendRaw(const ABuffer: TBytes; AOffset, ALength: Int32): Int32; virtual; abstract;
    /// <summary>Raises the elapsed-cap error when an armed cap has run out, and does nothing
    /// otherwise. A host that retries a receive inside ReceiveRaw calls it between attempts, so the
    /// retries cannot outlive the deadline the base only checks before each Read.</summary>
    procedure CheckReadCap;
    property ReadTimeoutMs: Int32 read FReadTimeoutMs;
  public
    /// <summary>Measures the handshake deadline on the system monotonic clock.</summary>
    constructor Create;
    /// <summary>Measures the handshake deadline on AClock instead (required; nil raises). Call it
    /// before SetReadTimeout: it clears any armed cap, whose deadline belongs to the old clock.</summary>
    procedure UseClock(const AClock: ITlsMonotonicClock);
    /// <summary>Bounds the reads that follow to AMs ms in total, as a deadline from this call
    /// (0 = block). A host that bounds its own socket (WaitReadable not overridden) can let a
    /// receive already in progress run one full receive bound past the deadline.</summary>
    procedure SetReadTimeout(AMs: Int32);
    /// <summary>Bounds the reads that follow to AMs ms in total, as SetReadTimeout does, for a host
    /// whose own socket wait cannot see that bytes which yield no application data (a ticket, a key
    /// update, part of a record) keep a read going. A read past the deadline raises the retryable
    /// ETlsReadTimeout instead of ETlsHandshakeTimeout. SetReadTimeout(0) clears it.</summary>
    procedure SetApplicationReadTimeout(AMs: Int32);
    function Read(var ABuffer: TBytes; AOffset, AMaxLength: Int32): Int32;
    procedure Write(const ABuffer: TBytes; AOffset, ALength: Int32);
  end;

  /// <summary>One TLS connection as an adapter drives it: the stream over a timed transport and a
  /// ready engine, the role-correct parked-verdict resolver, the handshake with its read cap armed
  /// and then cleared, application reads and writes, and the negotiated facts (zero values before
  /// the handshake). Host-owned; freeing it frees the stream and releases the transport and engine
  /// without sending close_notify (a host calls CloseNotify at its own close hook). Not thread-safe:
  /// a connection must not be read and written from two threads at once, so a host that broadcasts
  /// from another thread serializes its access.</summary>
  TTlsConnection = class sealed(TObject)
  public const
    /// <summary>The handshake read-timeout the connection applies when the host passes 0 (30 s).
    /// Exported so an adapter can share the one default rather than repeat the literal.</summary>
    DefaultHandshakeTimeoutMs = Int32(30000);
  strict private
  var
    FStream: TTlsStream;
    FTransport: ITlsTransport;
    FTimed: TTlsTimedTransportBase;          // the same object, typed for the cap
    FEngine: ITlsEngine;
    FIsClient: Boolean;
    FServerName: string;
    function Info: TTlsConnectionInfo;       // Default(...) when FStream = nil
  public
    constructor Create(const AEngine: ITlsEngine; const ATransport: TTlsTimedTransportBase;
      AIsClient: Boolean; const AServerName: string;
      const AResolver: TCertificateVerdictResolver); overload;
    /// <summary>As above, giving the resolver ADeadlineMs as its time budget (0 = none set).</summary>
    constructor Create(const AEngine: ITlsEngine; const ATransport: TTlsTimedTransportBase;
      AIsClient: Boolean; const AServerName: string;
      const AResolver: TCertificateVerdictResolver; AVerdictDeadlineMs: Cardinal); overload;
    /// <summary>Builds the client engine from AConfig and measures the transport's deadlines on
    /// the config's monotonic clock; AVerdictDeadlineMs is the resolver's budget (0 = none).</summary>
    constructor CreateClient(const AConfig: ITlsClientConfig; const AServerName: string;
      const ATransport: TTlsTimedTransportBase; const AResolver: TCertificateVerdictResolver;
      AVerdictDeadlineMs: Cardinal);
    /// <summary>The server counterpart of <see cref="CreateClient" />.</summary>
    constructor CreateServer(const AConfig: ITlsServerConfig;
      const ATransport: TTlsTimedTransportBase; const AResolver: TCertificateVerdictResolver;
      AVerdictDeadlineMs: Cardinal);
    destructor Destroy; override;
    /// <summary>Runs the handshake with reads bounded by AHandshakeTimeoutMs (0 = the 30 s library
    /// default); the cap is cleared afterwards even when the handshake raised.</summary>
    procedure Handshake(AHandshakeTimeoutMs: Int32);
    function IsHandshakeComplete: Boolean;
    function Read(var ABuffer; ACount: Longint): Longint; overload;
    /// <summary>A read that gives up with ETlsReadTimeout when no application data has arrived
    /// within AReadTimeoutMs in total (0 or less = block), however many bytes that wait takes in
    /// that do not yield any. The cap is cleared afterwards.</summary>
    function Read(var ABuffer; ACount: Longint; AReadTimeoutMs: Int32): Longint; overload;
    function Write(const ABuffer; ACount: Longint): Longint;
    function PendingReadBytes: Int32;
    /// <summary>Sends close_notify; raises like the stream does.</summary>
    procedure CloseNotify;
    /// <summary>Sends close_notify, swallowing a write to an already-dead peer.</summary>
    procedure CloseNotifyQuietly;
    /// <summary>Refuses the connection with a fatal alert (see TTlsStream.SendAlert): the host
    /// rejected the peer after the handshake completed.</summary>
    procedure SendAlert(ADescription: TTlsAlertDescription);
    function NegotiatedVersion: TTlsVersion;
    function NegotiatedCipherSuite: UInt16;
    function NegotiatedGroup: UInt16;
    function PeerServerName: string;
    function EchStatus: TEchStatus;
    function Resumed: Boolean;
    /// <summary>The peer leaf certificate (DER), or empty when the peer presented none.</summary>
    function PeerLeaf: TBytes;
    /// <summary>'TLSv1.3' / 'TLSv1.2' / '' - the negotiated version as a display string.</summary>
    function VersionName: string;
    /// <summary>The negotiated-facts snapshot for a possibly-nil connection: the connection's own
    /// snapshot, or the zero values when AConn is nil (an adapter that has not built one yet). Lets
    /// a host wrapper read the facts without repeating the nil guard per field.</summary>
    class function InfoOf(const AConn: TTlsConnection): TTlsConnectionInfo; static;
  end;

implementation

resourcestring
  SNilTransportClock =
    'a clock is required (pass a clock, not nil)';
  SNoServerCredential =
    'no server certificate/private key was supplied';
  SNoClientAuthSource =
    'client authentication is requested but no client-CA was named; set %s, or turn client ' +
    'authentication off';
  SSystemTrustIsNotClientAuthSource =
    'client authentication is requested but the only trust source named is system trust, which ' +
    'verifies server certificates and never vouches for clients; name a private client-CA (%s), or ' +
    'turn client authentication off';
  SClientAuthWithoutVerify =
    'client authentication is requested but peer verification is off; turn verification on, or ' +
    'set client authentication to None';
  SSystemTrustIdentityEmpty =
    'the system-trust installer must name what it installs (Identity is empty)';
  SVerifierWithoutVerify =
    'a custom server-certificate verifier replaces verification, so it cannot be combined with ' +
    'peer verification switched off; keep verification on, or drop the verifier';
  SClientVerifierNeedsClientAuth =
    'a client-certificate verifier is set but client authentication is None; set a ' +
    'client-authentication mode, or drop the verifier';
  SNoClientTrust =
    'peer verification is on but no trust source was named; set %s (system trust is never ' +
    'implicit), or turn peer verification off to skip verification';
  SConfigAndOptionsConflict =
    '%s is set together with cert/trust/ALPN/provider options or a non-default security toggle ' +
    'that a fully-built config replaces; supply either the config or those options, not both';
  SVerdictResolverWithoutDeferral =
    'a verdict resolver is set together with %s, but that config never defers the certificate ' +
    'verdict, so the resolver would never run; enable WithLiveRevocationVerdict or ' +
    'WithAsyncCertificateVerdict on the config';
  SHostCipherListRefused =
    'the %s property names %s, which TlsLib4Pascal does not implement as cipher suites: list ' +
    'exact IANA or cipher-list suite names separated by '':'', '','' or spaces (cipher-string ' +
    'expressions such as HIGH or !aNULL are not supported), or leave it empty or %s for the ' +
    'default';
  SHostCipherListMixedDefault =
    'the %s property combines %s with suite names; list exact suite names, or %s alone for the ' +
    'default';
  SHostCipherListNoUsableSuite =
    'the %s property leaves no cipher suite for the enabled protocol versions: it names only ' +
    '%s suites';
  SHandshakeReadTimedOut = 'the handshake did not complete within %d ms';
  SApplicationReadTimedOut = 'no application data arrived within %d ms';
  SSendNoProgress = 'the host transport reported no send progress';
  STransportReceiveFailed = 'the host transport reported a receive error (%d)';

{ TTlsBlobSource }

class function TTlsBlobSource.FromFile(
  const APath: string): TTlsBlobSource;
begin
  Result.FileName := APath;
  Result.Data := nil;
end;

class function TTlsBlobSource.FromBytes(
  const AData: TBytes): TTlsBlobSource;
begin
  Result.FileName := '';
  Result.Data := AData;
end;

function TTlsBlobSource.IsEmpty: Boolean;
begin
  Result := (FileName = '') and (System.Length(Data) = 0);
end;

{ TTlsOptions }

class function TTlsOptions.Default: TTlsOptions;
begin
  Result := System.Default(TTlsOptions);
  Result.VerifyPeer := True;
  Result.CheckHostName := True;
  Result.ServerNameIndication := TServerNameIndication.Send;
  Result.SessionResumption := True;
  // client authentication is opt-in: a server requests a client certificate only under an explicit mode
  Result.ClientAuth := TClientAuthMode.None;
end;

{ THostCipherList }

class function THostCipherList.Parse(const AText, APropertyName: string): TArray<UInt16>;
var
  LI, LStart: Int32;
  LToken, LUnknown: string;
  LCode: UInt16;
  LHasDefault: Boolean;
begin
  Result := nil;
  LUnknown := '';
  LHasDefault := False;
  LI := 1;
  while LI <= System.Length(AText) do
  begin
    if CharInSet(AText[LI], [':', ',', ';', ' ', #9]) then
    begin
      Inc(LI);
      Continue;
    end;
    LStart := LI;
    while (LI <= System.Length(AText)) and not CharInSet(AText[LI], [':', ',', ';', ' ', #9]) do
      Inc(LI);
    LToken := System.Copy(AText, LStart, LI - LStart);
    if SameText(LToken, HostDefault) then
      LHasDefault := True
    else if TCipherSuiteCatalog.TryCode(LToken, LCode) then
    begin
      if TArrayUtilities.Contains<UInt16>(Result, LCode) = False then
        TArrayUtilities.Append<UInt16>(Result, LCode);
    end
    else
    begin
      if LUnknown <> '' then
        LUnknown := LUnknown + ', ';
      LUnknown := LUnknown + '''' + LToken + '''';
    end;
  end;
  if LUnknown <> '' then
    raise ETlsStreamError.CreateResFmt(TTlsAlertDescription.InternalError,
      @SHostCipherListRefused, [APropertyName, LUnknown, HostDefault]);
  if LHasDefault and (System.Length(Result) > 0) then
    raise ETlsStreamError.CreateResFmt(TTlsAlertDescription.InternalError,
      @SHostCipherListMixedDefault, [APropertyName, HostDefault, HostDefault]);
end;

{ TTlsConfigComposer }

class function TTlsConfigComposer.EffectiveCrypto(
  const AOptions: TTlsOptions): ICryptoProvider;
begin
  if AOptions.Crypto <> nil then
    Result := AOptions.Crypto
  else
    Result := TDefaultCryptoProvider.Shared;
end;

class function TTlsConfigComposer.EffectivePkix(
  const AOptions: TTlsOptions): IPkixProvider;
begin
  if AOptions.Pkix <> nil then
    Result := AOptions.Pkix
  else
    Result := TDefaultPkixProvider.Shared;
end;

class function TTlsConfigComposer.Load(
  const ASource: TTlsBlobSource): TBytes;
var
  LStream: TFileStream;
begin
  if System.Length(ASource.Data) > 0 then
    Exit(ASource.Data);
  Result := nil;
  if ASource.FileName = '' then
    Exit;
  LStream := TFileStream.Create(ASource.FileName, fmOpenRead or fmShareDenyWrite);
  try
    SetLength(Result, LStream.Size);
    if LStream.Size > 0 then
      LStream.ReadBuffer(Result[0], LStream.Size);
  finally
    LStream.Free;
  end;
end;

class procedure TTlsConfigComposer.Sign(var ASig: TTlsSignatureBuilder;
  const AName: string; const ASource: TTlsBlobSource);
begin
  if System.Length(ASource.Data) > 0 then
    ASig.AddBytesDigest(AName, ASource.Data)
  else
    ASig.AddFile(AName, ASource.FileName);
end;

class function TTlsConfigComposer.HasTrustAnchor(
  const AOptions: TTlsOptions): Boolean;
var
  LI: Int32;
begin
  for LI := 0 to System.High(AOptions.TrustAnchors) do
    if not AOptions.TrustAnchors[LI].IsEmpty then
      Exit(True);
  Result := False;
end;

class function TTlsConfigComposer.HasClientTrustSource(
  const AOptions: TTlsOptions): Boolean;
begin
  Result := (AOptions.ServerCertificateVerifier <> nil) or HasTrustAnchor(AOptions) or
    (AOptions.SystemTrust <> nil) or (AOptions.CustomTrustStore <> nil);
end;

class function TTlsConfigComposer.HasClientAuthTrustSource(
  const AOptions: TTlsOptions): Boolean;
begin
  // system trust is a server-CERTIFICATE source, never a client-CA (a server's client-CA is always
  // caller-supplied) - so it is deliberately not counted here
  Result := (AOptions.ClientCertificateVerifier <> nil) or HasTrustAnchor(AOptions) or
    (AOptions.CustomTrustStore <> nil);
end;

class function TTlsConfigComposer.HostListVersions(
  const AOptions: TTlsOptions): TArray<UInt16>;
var
  LVersions: TArray<UInt16>;
  LNames12: Boolean;
  LSuite: TTlsCipherSuite;
  LI: Int32;
begin
  LVersions := AOptions.SupportedVersions;
  if System.Length(LVersions) = 0 then
    LVersions := TArray<UInt16>.Create(TlsWireVersionTls13, TlsWireVersionTls12);
  LNames12 := False;
  for LI := 0 to System.High(AOptions.CipherSuites) do
    if TCipherSuiteCatalog.TryGet(AOptions.CipherSuites[LI], LSuite) and
      (LSuite.Protocol = TSuiteProtocol.Tls12) then
      LNames12 := True;
  Result := nil;
  for LI := 0 to System.High(LVersions) do
    if LNames12 or (LVersions[LI] = TlsWireVersionTls13) then
      TArrayUtilities.Append<UInt16>(Result, LVersions[LI]);
  if System.Length(Result) = 0 then
    raise ETlsStreamError.CreateResFmt(TTlsAlertDescription.InternalError,
      @SHostCipherListNoUsableSuite, [AOptions.CipherSuitesHint, 'TLS 1.3']);
end;

class function TTlsConfigComposer.BuildClientConfig(
  const AOptions: TTlsOptions): ITlsClientConfig;
var
  LCrypto: ICryptoProvider;
  LPkix: IPkixProvider;
  LClient: ITlsClientConfigBuilder;
  LI: Int32;
begin
  // the verifier is the whole decision, so a switched-off verification beside it is a contradiction
  // the host should see in its own terms rather than as a builder conflict
  if (AOptions.ServerCertificateVerifier <> nil) and
    (AOptions.InsecureSkipVerify or (not AOptions.VerifyPeer)) then
    raise ETlsStreamError.CreateRes(TTlsAlertDescription.InternalError, @SVerifierWithoutVerify);
  LCrypto := EffectiveCrypto(AOptions);
  LPkix := EffectivePkix(AOptions);
  LClient := TTlsPresets.Compatible(LCrypto, LPkix).Client;
  if System.Length(AOptions.CipherSuites) > 0 then
  begin
    LClient.WithCipherSuiteList(AOptions.CipherSuites);
    LClient.WithSupportedVersions(HostListVersions(AOptions));
  end
  else if System.Length(AOptions.SupportedVersions) > 0 then
    LClient.WithSupportedVersions(AOptions.SupportedVersions);
  // compose peer trust from orthogonal sources: a whole-verifier REPLACES the pipeline, else the
  // anchors + the OS store + a custom store all UNION. Adding both a verifier and an anchor source
  // is left to fail as the builder's typed conflict. System trust is never implicit.
  if AOptions.ServerCertificateVerifier <> nil then
    LClient.WithDangerousCertificateVerifier(AOptions.ServerCertificateVerifier);
  for LI := 0 to System.High(AOptions.TrustAnchors) do
    if not AOptions.TrustAnchors[LI].IsEmpty then
      LClient.WithTrustAnchors(Load(AOptions.TrustAnchors[LI]));
  if AOptions.SystemTrust <> nil then
    AOptions.SystemTrust.InstallClientTrust(LClient, LPkix);
  if AOptions.CustomTrustStore <> nil then
    LClient.WithTrustStore(AOptions.CustomTrustStore);
  // no trust source composed: demand an explicit decision - real trust, or the loud skip toggle
  // below (which is itself the trust decision, so no placeholder store is needed to build)
  if (not HasClientTrustSource(AOptions)) and AOptions.VerifyPeer and
    (not AOptions.InsecureSkipVerify) then
    raise ETlsStreamError.CreateResFmt(TTlsAlertDescription.InternalError,
      @SNoClientTrust, [AOptions.TrustSourceHint]);
  if AOptions.InsecureSkipVerify or (not AOptions.VerifyPeer) then
    LClient.WithDangerousInsecureSkipVerify;
  if not AOptions.CheckHostName then
    LClient.WithDangerousDisableServerNameCheck;
  LClient.WithServerNameIndication(AOptions.ServerNameIndication);
  if System.Length(AOptions.AlpnProtocols) > 0 then
    LClient.WithAlpnProtocols(AOptions.AlpnProtocols);
  if not AOptions.Certificate.IsEmpty then
    LClient.WithCredential(TTlsCredential.Load(LCrypto, LPkix,
      Load(AOptions.Certificate), Load(AOptions.PrivateKey), AOptions.KeyPassword));
  // an app's augment-only verify rule, and the live-revocation verdict flag (the resolver itself is
  // a runtime stream hook attached at the session, not part of the frozen config)
  if Assigned(AOptions.VerifyCallback) then
    LClient.WithCertificateVerifyCallback(AOptions.VerifyCallback);
  if Assigned(AOptions.ClientVerdictResolver) then
    LClient.WithLiveRevocationVerdict(AOptions.ClientVerdictDeadlineMs);
  if AOptions.SessionResumption then
  begin
    LClient.WithResumption(True);
    LClient.WithSessionCache(TInMemorySessionCache.Create as ISessionCache);
  end
  else
    LClient.WithResumption(False);
  Result := LClient.Build;
end;

class function TTlsConfigComposer.BuildServerConfig(
  const AOptions: TTlsOptions): ITlsServerConfig;
var
  LCrypto: ICryptoProvider;
  LPkix: IPkixProvider;
  LServer: ITlsServerConfigBuilder;
  LI: Int32;
begin
  if AOptions.Certificate.IsEmpty then
    raise ETlsStreamError.CreateRes(TTlsAlertDescription.InternalError, @SNoServerCredential);
  if AOptions.ClientAuth <> TClientAuthMode.None then
  begin
    // an explicit client-auth mode with peer verification switched off, or with nothing to verify a
    // presented chain against, is a contradiction: fail loud, never a server that quietly accepts any
    // certificate or asks for none. Verification first: an adapter that names its trust only when
    // verifying (Synapse) then reports the true cause, not a spurious no-source.
    if (not AOptions.VerifyPeer) or AOptions.InsecureSkipVerify then
      raise ETlsStreamError.CreateRes(TTlsAlertDescription.InternalError,
        @SClientAuthWithoutVerify);
    if not HasClientAuthTrustSource(AOptions) then
    begin
      // system trust verifies server certificates, so naming it as the only client-CA is the one
      // misconfiguration worth its own message: the fix is a private CA, not "more" system trust
      if AOptions.SystemTrust <> nil then
        raise ETlsStreamError.CreateResFmt(TTlsAlertDescription.InternalError,
          @SSystemTrustIsNotClientAuthSource, [AOptions.ClientAuthSourceHint]);
      raise ETlsStreamError.CreateResFmt(TTlsAlertDescription.InternalError,
        @SNoClientAuthSource, [AOptions.ClientAuthSourceHint]);
    end;
  end
  else if AOptions.ClientCertificateVerifier <> nil then
    // a server-role client-certificate verifier can only ever vet a requested client chain: it is
    // inert without a mode, so its presence with None is a configuration mistake
    raise ETlsStreamError.CreateRes(TTlsAlertDescription.InternalError,
      @SClientVerifierNeedsClientAuth);
  LCrypto := EffectiveCrypto(AOptions);
  LPkix := EffectivePkix(AOptions);
  LServer := TTlsPresets.Compatible(LCrypto, LPkix).Server
    .WithCredential(TTlsCredential.Load(LCrypto, LPkix,
    Load(AOptions.Certificate), Load(AOptions.PrivateKey), AOptions.KeyPassword));
  if System.Length(AOptions.CipherSuites) > 0 then
  begin
    LServer.WithCipherSuiteList(AOptions.CipherSuites);
    LServer.WithSupportedVersions(HostListVersions(AOptions));
  end
  else if System.Length(AOptions.SupportedVersions) > 0 then
    LServer.WithSupportedVersions(AOptions.SupportedVersions);
  if System.Length(AOptions.AlpnProtocols) > 0 then
    LServer.WithAlpnProtocols(AOptions.AlpnProtocols);
  // request + verify client certificates only under an explicit mode (a named client-CA alone never
  // triggers it; system trust is a server-cert source and is never a client-CA). The async
  // client-certificate verdict park is armed here (and only here) so the server-role resolver runs
  // server-side for live client-cert revocation.
  if AOptions.ClientAuth <> TClientAuthMode.None then
  begin
    LServer.WithPeerAuth(AOptions.ClientAuth);
    if AOptions.ClientCertificateVerifier <> nil then
      LServer.WithDangerousCertificateVerifier(AOptions.ClientCertificateVerifier);
    for LI := 0 to System.High(AOptions.TrustAnchors) do
      if not AOptions.TrustAnchors[LI].IsEmpty then
        LServer.WithTrustAnchors(Load(AOptions.TrustAnchors[LI]));
    if AOptions.CustomTrustStore <> nil then
      LServer.WithTrustStore(AOptions.CustomTrustStore);
    // the augment-only hook vets a presented client chain too, so an operator's allow-list runs
    if Assigned(AOptions.VerifyCallback) then
      LServer.WithCertificateVerifyCallback(AOptions.VerifyCallback);
    if Assigned(AOptions.ServerVerdictResolver) then
      LServer.WithLiveRevocationVerdict(AOptions.ServerVerdictDeadlineMs);
  end;
  LServer.WithResumption(AOptions.SessionResumption);
  Result := LServer.Build;
end;

class function TTlsConfigComposer.ClientSignature(
  const AOptions: TTlsOptions): string;
var
  LSig: TTlsSignatureBuilder;
  LCrypto: ICryptoProvider;
  LI: Int32;
begin
  LCrypto := EffectiveCrypto(AOptions);
  LSig := TTlsSignatureBuilder.Create(LCrypto);
  LSig.AddPointer('crypto', LCrypto);
  LSig.AddPointer('pkix', EffectivePkix(AOptions));
  LSig.AddFlag('resume', AOptions.SessionResumption);
  Sign(LSig, 'cert', AOptions.Certificate);
  Sign(LSig, 'key', AOptions.PrivateKey);
  LSig.AddSecret('keypw', AOptions.KeyPassword);
  for LI := 0 to System.High(AOptions.TrustAnchors) do
    Sign(LSig, 'anchor', AOptions.TrustAnchors[LI]);
  LSig.AddFlag('verifyPeer', AOptions.VerifyPeer);
  LSig.AddFlag('skipVerify', AOptions.InsecureSkipVerify);
  LSig.AddFlag('checkHost', AOptions.CheckHostName);
  LSig.AddCardinal('sni', Cardinal(Ord(AOptions.ServerNameIndication)));
  // by what the installer installs, not a bare present/absent flag: two installers that install
  // different roots must not collapse to the same memo signature and reuse each other's frozen
  // config. The built config does not retain the installer, so its address would not be stable.
  LSig.AddFlag('systemTrust', AOptions.SystemTrust <> nil);
  if AOptions.SystemTrust <> nil then
  begin
    // an unnamed installer would collide with another unnamed one and with the absence of one
    if AOptions.SystemTrust.Identity = '' then
      raise ETlsStreamError.CreateRes(TTlsAlertDescription.InternalError,
        @SSystemTrustIdentityEmpty);
    LSig.AddText('systemTrustId', AOptions.SystemTrust.Identity);
  end;
  LSig.AddPointer('customVerifier', AOptions.ServerCertificateVerifier);
  // a composed store keeps the stores it was built from, so this address stays live with the config
  LSig.AddPointer('customStore', AOptions.CustomTrustStore);
  for LI := 0 to System.High(AOptions.AlpnProtocols) do
    LSig.AddText('alpn', AOptions.AlpnProtocols[LI]);
  LSig.AddMethod('verifyCb', TMethod(AOptions.VerifyCallback));
  LSig.AddFlag('asyncVerdict', Assigned(AOptions.ClientVerdictResolver));
  LSig.AddCardinal('deadline', AOptions.ClientVerdictDeadlineMs);
  LSig.AddCardinal('versions', Cardinal(System.Length(AOptions.SupportedVersions)));
  for LI := 0 to System.High(AOptions.SupportedVersions) do
    LSig.AddCardinal('version', AOptions.SupportedVersions[LI]);
  LSig.AddCardinal('suites', Cardinal(System.Length(AOptions.CipherSuites)));
  for LI := 0 to System.High(AOptions.CipherSuites) do
    LSig.AddCardinal('suite', AOptions.CipherSuites[LI]);
  Result := LSig.Value;
end;

class function TTlsConfigComposer.ServerSignature(
  const AOptions: TTlsOptions): string;
var
  LSig: TTlsSignatureBuilder;
  LCrypto: ICryptoProvider;
  LI: Int32;
begin
  LCrypto := EffectiveCrypto(AOptions);
  LSig := TTlsSignatureBuilder.Create(LCrypto);
  LSig.AddPointer('crypto', LCrypto);
  LSig.AddPointer('pkix', EffectivePkix(AOptions));
  LSig.AddFlag('resume', AOptions.SessionResumption);
  Sign(LSig, 'cert', AOptions.Certificate);
  Sign(LSig, 'key', AOptions.PrivateKey);
  LSig.AddSecret('keypw', AOptions.KeyPassword);
  for LI := 0 to System.High(AOptions.TrustAnchors) do
    Sign(LSig, 'anchor', AOptions.TrustAnchors[LI]);
  LSig.AddFlag('verifyPeer', AOptions.VerifyPeer);
  // the server build reads skip-verify under a client-auth mode (the mode-vs-verify guard)
  LSig.AddFlag('skipVerify', AOptions.InsecureSkipVerify);
  // system trust is a client-role source the server build never reads, so it is not in this key
  LSig.AddPointer('customVerifier', AOptions.ClientCertificateVerifier);
  LSig.AddPointer('customStore', AOptions.CustomTrustStore);
  LSig.AddCardinal('clientAuth', Cardinal(Ord(AOptions.ClientAuth)));
  for LI := 0 to System.High(AOptions.AlpnProtocols) do
    LSig.AddText('alpn', AOptions.AlpnProtocols[LI]);
  LSig.AddMethod('verifyCb', TMethod(AOptions.VerifyCallback));
  LSig.AddFlag('asyncVerdict', Assigned(AOptions.ServerVerdictResolver));
  LSig.AddCardinal('deadline', AOptions.ServerVerdictDeadlineMs);
  LSig.AddCardinal('versions', Cardinal(System.Length(AOptions.SupportedVersions)));
  for LI := 0 to System.High(AOptions.SupportedVersions) do
    LSig.AddCardinal('version', AOptions.SupportedVersions[LI]);
  LSig.AddCardinal('suites', Cardinal(System.Length(AOptions.CipherSuites)));
  for LI := 0 to System.High(AOptions.CipherSuites) do
    LSig.AddCardinal('suite', AOptions.CipherSuites[LI]);
  Result := LSig.Value;
end;

class procedure TTlsConfigComposer.GuardNoConflict(
  const AOptions: TTlsOptions; AIsClient: Boolean; const APropertyName: string);
var
  LConflict: Boolean;
begin
  // a supplied config owns the frozen build entirely; naming an option the same role's own build
  // would consume alongside it silently drops it, so fail loud. Credential, trust anchors, ALPN,
  // providers, the supported-versions and cipher lists and the augment callback are read by both roles (the server reads the callback under
  // client auth); the server-cert verifier and system trust are client-only reads and the
  // client-cert verifier a server-only read, so flagging one on the other role would reject an
  // option that role never consumes. The verdict resolvers and the handshake timeout are runtime
  // hooks and never conflict.
  LConflict := (not AOptions.Certificate.IsEmpty) or (not AOptions.PrivateKey.IsEmpty) or
    HasTrustAnchor(AOptions) or
    (AOptions.CustomTrustStore <> nil) or (System.Length(AOptions.AlpnProtocols) > 0) or
    (AOptions.Crypto <> nil) or (AOptions.Pkix <> nil);
  // a security toggle always carries a value, so flag only a NON-DEFAULT one the host actively chose
  // that a supplied config then silently drops. Resumption is read by both role builds. The host-name
  // check and SNI are client-only reads; the server build reads peer verification and the
  // skip-verify bypass only under a client-auth mode, which already conflicts on its own below. A
  // non-default client-authentication mode is a server-only security decision the config would
  // replace.
  LConflict := LConflict or (not AOptions.SessionResumption) or
    (System.Length(AOptions.SupportedVersions) > 0) or (System.Length(AOptions.CipherSuites) > 0);
  if AIsClient then
    LConflict := LConflict or (AOptions.ServerCertificateVerifier <> nil) or
      (AOptions.SystemTrust <> nil) or
      Assigned(AOptions.VerifyCallback) or (not AOptions.VerifyPeer) or
      AOptions.InsecureSkipVerify or (not AOptions.CheckHostName) or
      (AOptions.ServerNameIndication <> TServerNameIndication.Send)
  else
    LConflict := LConflict or (AOptions.ClientCertificateVerifier <> nil) or
      (AOptions.ClientAuth <> TClientAuthMode.None) or Assigned(AOptions.VerifyCallback);
  if LConflict then
    raise ETlsStreamError.CreateResFmt(TTlsAlertDescription.InternalError,
      @SConfigAndOptionsConflict, [APropertyName]);
end;

class function TTlsConfigComposer.ResolveClientConfig(
  const AOptions: TTlsOptions; const AMemo: ITlsClientConfigMemo;
  const AConfigPropertyName: string): ITlsClientConfig;
var
  LSig: string;
  LConfig: ITlsClientConfig;
begin
  // a fully-built config supplied by the host REPLACES the options-driven build outright; naming
  // cert/trust options alongside it fails loud rather than dropping them silently
  if AOptions.ClientConfig <> nil then
  begin
    GuardNoConflict(AOptions, True, AConfigPropertyName);
    // the resolver only runs when the handshake parks for a verdict; a config that never parks
    // would leave it silently unused (live revocation off)
    if Assigned(AOptions.ClientVerdictResolver) and
      (AOptions.ClientConfig.AsyncCertificateVerdict.Deferral = TVerdictDeferral.None) then
      raise ETlsStreamError.CreateResFmt(TTlsAlertDescription.InternalError,
        @SVerdictResolverWithoutDeferral, [AConfigPropertyName]);
    Exit(AOptions.ClientConfig);
  end;
  LSig := ClientSignature(AOptions);
  if not AMemo.TryGet(LSig, LConfig) then
    LConfig := AMemo.StoreOrAdopt(LSig, BuildClientConfig(AOptions));
  Result := LConfig;
end;

class function TTlsConfigComposer.ResolveServerConfig(
  const AOptions: TTlsOptions; const AMemo: ITlsServerConfigMemo;
  const AConfigPropertyName: string): ITlsServerConfig;
var
  LSig: string;
  LConfig: ITlsServerConfig;
begin
  if AOptions.ServerConfig <> nil then
  begin
    GuardNoConflict(AOptions, False, AConfigPropertyName);
    if Assigned(AOptions.ServerVerdictResolver) and
      (AOptions.ServerConfig.ClientAuth <> TClientAuthMode.None) and
      (AOptions.ServerConfig.AsyncCertificateVerdict.Deferral = TVerdictDeferral.None) then
      raise ETlsStreamError.CreateResFmt(TTlsAlertDescription.InternalError,
        @SVerdictResolverWithoutDeferral, [AConfigPropertyName]);
    Exit(AOptions.ServerConfig);
  end;
  LSig := ServerSignature(AOptions);
  if not AMemo.TryGet(LSig, LConfig) then
    LConfig := AMemo.StoreOrAdopt(LSig, BuildServerConfig(AOptions));
  Result := LConfig;
end;

{ TTlsTimedTransportBase }

procedure TTlsTimedTransportBase.SetReadTimeout(AMs: Int32);
begin
  FApplicationRead := False;
  FReadTimeoutMs := AMs;
  if AMs > 0 then
    FDeadlineMs := FClock.NowMonotonicMillis + AMs;
end;

procedure TTlsTimedTransportBase.SetApplicationReadTimeout(AMs: Int32);
begin
  SetReadTimeout(AMs);
  FApplicationRead := AMs > 0;
end;

constructor TTlsTimedTransportBase.Create;
begin
  inherited Create;
  FClock := TSystemMonotonicClock.Create;
end;

procedure TTlsTimedTransportBase.UseClock(const AClock: ITlsMonotonicClock);
begin
  if AClock = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilTransportClock);
  FClock := AClock;
  FReadTimeoutMs := 0;
end;

function TTlsTimedTransportBase.WaitReadable(AMs: Int32): Boolean;
begin
  // a host that bounds the socket itself (a receive timeout on the handle) keeps this default and
  // reports the elapsed cap from ReceiveRaw
  Result := True;
end;

procedure TTlsTimedTransportBase.RaiseCapElapsed;
begin
  if FApplicationRead then
    raise ETlsReadTimeout.Create(Format(SApplicationReadTimedOut, [FReadTimeoutMs]))
  else
    raise ETlsHandshakeTimeout.Create(Format(SHandshakeReadTimedOut, [FReadTimeoutMs]));
end;

procedure TTlsTimedTransportBase.CheckReadCap;
begin
  if (FReadTimeoutMs > 0) and (FDeadlineMs - FClock.NowMonotonicMillis <= 0) then
    RaiseCapElapsed;
end;

function TTlsTimedTransportBase.Read(var ABuffer: TBytes; AOffset,
  AMaxLength: Int32): Int32;
var
  LRemaining: Int64;
begin
  // bounded during the handshake; distinct from a peer close (which returns 0 below). The cap is a
  // deadline over the whole handshake, so a peer trickling bytes just inside each read is reaped too
  if FReadTimeoutMs > 0 then
  begin
    LRemaining := FDeadlineMs - FClock.NowMonotonicMillis;
    if (LRemaining <= 0) or (not WaitReadable(Int32(LRemaining))) then
      RaiseCapElapsed;
  end;
  Result := ReceiveRaw(ABuffer, AOffset, AMaxLength);
  // a negative return is a genuine receive error (a reset, a broken pipe), never a peer close
  // (EOF = 0); surface it instead of masking it as a clean end that reads upstream as a truncation
  if Result < 0 then
    raise ETlsStreamError.Create(Format(STransportReceiveFailed, [Result]));
end;

procedure TTlsTimedTransportBase.Write(const ABuffer: TBytes; AOffset,
  ALength: Int32);
var
  LOff, LRemain, LN: Int32;
begin
  LOff := AOffset;
  LRemain := ALength;
  while LRemain > 0 do
  begin
    LN := SendRaw(ABuffer, LOff, LRemain);
    if LN <= 0 then
      raise ETlsStreamError.Create(SSendNoProgress);
    Inc(LOff, LN);
    Dec(LRemain, LN);
  end;
end;

{ TTlsConnection }

constructor TTlsConnection.Create(const AEngine: ITlsEngine;
  const ATransport: TTlsTimedTransportBase; AIsClient: Boolean;
  const AServerName: string; const AResolver: TCertificateVerdictResolver);
begin
  Create(AEngine, ATransport, AIsClient, AServerName, AResolver, 0);
end;

constructor TTlsConnection.Create(const AEngine: ITlsEngine;
  const ATransport: TTlsTimedTransportBase; AIsClient: Boolean;
  const AServerName: string; const AResolver: TCertificateVerdictResolver;
  AVerdictDeadlineMs: Cardinal);
begin
  inherited Create;
  FEngine := AEngine;
  FTimed := ATransport;
  FTransport := ATransport as ITlsTransport;
  FIsClient := AIsClient;
  FServerName := AServerName;
  FStream := TTlsStream.Create(FTransport, FEngine, AIsClient, AServerName);
  // the caller already chose the role-correct resolver (a client parks on the server's chain, a
  // server on the mTLS client's); the session never guesses the role
  if Assigned(AResolver) then
    FStream.SetCertificateVerdictResolver(AResolver, AVerdictDeadlineMs);
end;

constructor TTlsConnection.CreateClient(const AConfig: ITlsClientConfig;
  const AServerName: string; const ATransport: TTlsTimedTransportBase;
  const AResolver: TCertificateVerdictResolver; AVerdictDeadlineMs: Cardinal);
begin
  // own the transport first, so a refused engine build releases it with this instance
  FTransport := ATransport as ITlsTransport;
  ATransport.UseClock(AConfig.MonotonicClock);
  Create(TTlsEngineFactory.CreateClientEngine(AConfig, AServerName), ATransport, True,
    AServerName, AResolver, AVerdictDeadlineMs);
end;

constructor TTlsConnection.CreateServer(const AConfig: ITlsServerConfig;
  const ATransport: TTlsTimedTransportBase; const AResolver: TCertificateVerdictResolver;
  AVerdictDeadlineMs: Cardinal);
begin
  FTransport := ATransport as ITlsTransport;
  ATransport.UseClock(AConfig.MonotonicClock);
  Create(TTlsEngineFactory.CreateServerEngine(AConfig), ATransport, False, '', AResolver,
    AVerdictDeadlineMs);
end;

destructor TTlsConnection.Destroy;
begin
  FStream.Free;
  FStream := nil;
  FTransport := nil;
  FTimed := nil;
  FEngine := nil;
  inherited Destroy;
end;

function TTlsConnection.Info: TTlsConnectionInfo;
begin
  if FStream <> nil then
    Result := FStream.ConnectionInfo
  else
    Result := Default(TTlsConnectionInfo);
end;

class function TTlsConnection.InfoOf(
  const AConn: TTlsConnection): TTlsConnectionInfo;
begin
  if AConn <> nil then
    Result := AConn.Info
  else
    Result := Default(TTlsConnectionInfo);
end;

procedure TTlsConnection.Handshake(AHandshakeTimeoutMs: Int32);
var
  LMs: Int32;
begin
  LMs := AHandshakeTimeoutMs;
  if LMs <= 0 then
    LMs := DefaultHandshakeTimeoutMs;
  FTimed.SetReadTimeout(LMs);
  try
    FStream.Handshake;
  finally
    // clear the cap even if the handshake raised, so a retried app read is not left bounded
    FTimed.SetReadTimeout(0);
  end;
end;

function TTlsConnection.Read(var ABuffer; ACount: Longint;
  AReadTimeoutMs: Int32): Longint;
begin
  FTimed.SetApplicationReadTimeout(AReadTimeoutMs);
  try
    Result := Read(ABuffer, ACount);
  finally
    FTimed.SetReadTimeout(0);
  end;
end;

function TTlsConnection.IsHandshakeComplete: Boolean;
begin
  Result := (FStream <> nil) and FStream.IsHandshakeComplete;
end;

function TTlsConnection.Read(var ABuffer; ACount: Longint): Longint;
begin
  Result := FStream.Read(ABuffer, ACount);
end;

function TTlsConnection.Write(const ABuffer; ACount: Longint): Longint;
begin
  Result := FStream.Write(ABuffer, ACount);
end;

function TTlsConnection.PendingReadBytes: Int32;
begin
  if FStream <> nil then
    Result := FStream.PendingReadBytes
  else
    Result := 0;
end;

procedure TTlsConnection.CloseNotify;
begin
  if FStream <> nil then
    FStream.CloseNotify;
end;

procedure TTlsConnection.SendAlert(ADescription: TTlsAlertDescription);
begin
  if FStream <> nil then
    FStream.SendAlert(ADescription);
end;

procedure TTlsConnection.CloseNotifyQuietly;
begin
  if FStream <> nil then
    try
      FStream.CloseNotify;
    except
    end;
end;

function TTlsConnection.NegotiatedVersion: TTlsVersion;
begin
  Result := Info.NegotiatedVersion;
end;

function TTlsConnection.NegotiatedCipherSuite: UInt16;
begin
  Result := Info.CipherSuite;
end;

function TTlsConnection.NegotiatedGroup: UInt16;
begin
  Result := Info.NamedGroup;
end;

function TTlsConnection.PeerServerName: string;
begin
  Result := Info.ServerName;
end;

function TTlsConnection.EchStatus: TEchStatus;
begin
  Result := Info.EchStatus;
end;

function TTlsConnection.Resumed: Boolean;
begin
  Result := Info.Resumed;
end;

function TTlsConnection.PeerLeaf: TBytes;
var
  LChain: TArray<TBytes>;
begin
  Result := nil;
  LChain := Info.PeerCertificates;
  if System.Length(LChain) > 0 then
    Result := LChain[0];
end;

function TTlsConnection.VersionName: string;
begin
  case Info.NegotiatedVersion.WireValue of
    TlsWireVersionTls13:
      Result := 'TLSv1.3';
    TlsWireVersionTls12:
      Result := 'TLSv1.2';
  else
    Result := '';
  end;
end;

end.
