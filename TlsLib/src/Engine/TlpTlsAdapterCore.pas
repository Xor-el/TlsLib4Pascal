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
unit TlpTlsAdapterCore;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  Classes,
  TlpTlsAlert,
  TlpTlsVersion,
  TlpEchConfig,
  TlpICryptoProvider,
  TlpDefaultCryptoProvider,
  TlpIPkixProvider,
  TlpDefaultPkixProvider,
  TlpICertificateTrust,
  TlpCertificateVerifier,
  TlpTrustPolicy,
  TlpTlsCredential,
  TlpITlsConfig,
  TlpITlsConfigBuilder,
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
  TTlsAdapterBlobSource = record
    FileName: string;
    Data: TBytes;
    class function FromFile(const APath: string): TTlsAdapterBlobSource; static;
    class function FromBytes(const AData: TBytes): TTlsAdapterBlobSource; static;
    function IsEmpty: Boolean;
  end;

  /// <summary>Everything a host integration maps onto the TLS configuration, in host-neutral form:
  /// the providers, the credential and trust sources, the verify posture, the neutral hooks and the
  /// two role-specific verdict resolvers, ALPN, resumption, the handshake read cap, and the
  /// fully-built config that replaces the whole options-driven build. A value: an adapter fills one
  /// snapshot per handshake, so a concurrent change to a process-wide setter is never seen
  /// half-applied.</summary>
  TTlsAdapterOptions = record
    Crypto: ICryptoProvider;                     // nil = TDefaultCryptoProvider.Shared
    Pkix: IPkixProvider;                         // nil = TDefaultPkixProvider.Shared
    Certificate: TTlsAdapterBlobSource;          // own chain (server: required; client: mTLS)
    PrivateKey: TTlsAdapterBlobSource;
    KeyPassword: string;
    TrustAnchors: TArray<TTlsAdapterBlobSource>; // each -> WithTrustAnchors (union)
    SystemTrust: ISystemTrustInstaller;          // non-nil = opt into the OS store (union)
    CustomTrustStore: ITrustAnchorStore;         // WithTrustStore (union)
    ServerCertificateVerifier: IServerCertificateVerifier;   // client role; replaces the pipeline
    ClientCertificateVerifier: IClientCertificateVerifier;   // server role; replaces the pipeline
    VerifyPeer: Boolean;                         // default True
    InsecureSkipVerify: Boolean;                 // default False
    CheckHostName: Boolean;                      // default True
    ClientAuth: TClientAuthMode;                 // applied when a client-trust source is named
    AlpnProtocols: TArray<string>;
    VerifyCallback: TTlsCertificateVerifyCallback;
    ClientVerdictResolver: TCertificateVerdictResolver;
    ClientVerdictDeadlineMs: Cardinal;
    ServerVerdictResolver: TCertificateVerdictResolver;
    ServerVerdictDeadlineMs: Cardinal;
    SessionResumption: Boolean;                  // default True
    HandshakeTimeoutMs: Int32;                   // 0 = the library default (30 000 ms)
    ClientConfig: ITlsClientConfig;              // config-in: replaces the client build
    ServerConfig: ITlsServerConfig;              // config-in: replaces the server build
    TrustSourceHint: string;                     // host knob names, spliced into the no-source message
    /// <summary>A value with the composable defaults: VerifyPeer / CheckHostName / SessionResumption
    /// on, ClientAuth Required. Assign it at snapshot time (no class operator Initialize, to dodge
    /// the Delphi nested-managed-record leak trap).</summary>
    class function Default: TTlsAdapterOptions; static;
  end;

  /// <summary>The single site that composes an adapter's TLS configuration from its options, memoises
  /// it, and guards a supplied config against the options it would silently replace. Every method is
  /// static: the composer holds no state.</summary>
  TTlsAdapterConfigComposer = class sealed(TObject)
  strict private
    class function Load(const ASource: TTlsAdapterBlobSource): TBytes; static;
    class procedure Sign(var ASig: TTlsSignatureBuilder; const AName: string;
      const ASource: TTlsAdapterBlobSource); static;
    class function HasClientTrustSource(const AOptions: TTlsAdapterOptions): Boolean; static;
    class function HasClientAuthTrustSource(const AOptions: TTlsAdapterOptions): Boolean; static;
  public
    class function EffectiveCrypto(const AOptions: TTlsAdapterOptions): ICryptoProvider; static;
    class function EffectivePkix(const AOptions: TTlsAdapterOptions): IPkixProvider; static;
    /// <summary>The options-driven client config (the build the memo caches). Raises
    /// ETlsStreamError(internal_error) when verification is on and no trust source is named.</summary>
    class function BuildClientConfig(const AOptions: TTlsAdapterOptions): ITlsClientConfig; static;
    /// <summary>The options-driven server config. Raises without a certificate. Requests client
    /// authentication (at AOptions.ClientAuth) only when a client-trust source is named, and arms the
    /// live-revocation verdict park for the server-role resolver only then.</summary>
    class function BuildServerConfig(const AOptions: TTlsAdapterOptions): ITlsServerConfig; static;
    class function ClientSignature(const AOptions: TTlsAdapterOptions): string; static;
    class function ServerSignature(const AOptions: TTlsAdapterOptions): string; static;
    /// <summary>Raises when a fully-built config is supplied together with options it would silently
    /// replace (APropertyName names the config property in the message). The verdict resolvers and
    /// the handshake timeout are runtime hooks and never conflict.</summary>
    class procedure GuardNoConflict(const AOptions: TTlsAdapterOptions;
      const APropertyName: string); static;
    /// <summary>The client config for one handshake: the supplied ClientConfig (after the conflict
    /// guard), else the memoised options-driven build.</summary>
    class function ResolveClientConfig(const AOptions: TTlsAdapterOptions;
      const AMemo: ITlsClientConfigMemo;
      const AConfigPropertyName: string): ITlsClientConfig; static;
    class function ResolveServerConfig(const AOptions: TTlsAdapterOptions;
      const AMemo: ITlsServerConfigMemo;
      const AConfigPropertyName: string): ITlsServerConfig; static;
  end;

  /// <summary>An ITlsTransport over a host socket whose reads can be bounded for the handshake phase:
  /// with a cap armed, a read that sees no data within the cap raises ETlsHandshakeTimeout (a silent
  /// or dead peer is reaped rather than parking the thread); with the cap cleared reads block, as
  /// application reads must. A host supplies the readiness wait and the raw receive/send.</summary>
  TTlsTimedTransportBase = class abstract(TInterfacedObject, ITlsTransport)
  strict private
  var
    FReadTimeoutMs: Int32;
  strict protected
    /// <summary>True when at least one byte can be read within AMs ms. The default waits nowhere and
    /// returns True, for a host that bounds the socket itself (a receive timeout on the handle) and
    /// reports the elapsed cap from ReceiveRaw.</summary>
    function WaitReadable(AMs: Int32): Boolean; virtual;
    /// <summary>One blocking receive: the count, 0 on an orderly close, a negative value for a host
    /// error the caller treats as end of stream; raises ETlsHandshakeTimeout itself only for a host
    /// whose receive timeout fired (see ReadTimeoutMs).</summary>
    function ReceiveRaw(var ABuffer: TBytes; AOffset, AMaxLength: Int32): Int32; virtual; abstract;
    /// <summary>One send of up to ALength bytes; returns the count sent (> 0) or raises.</summary>
    function SendRaw(const ABuffer: TBytes; AOffset, ALength: Int32): Int32; virtual; abstract;
    property ReadTimeoutMs: Int32 read FReadTimeoutMs;
  public
    /// <summary>Bounds each Read to AMs ms (0 = block).</summary>
    procedure SetReadTimeout(AMs: Int32);
    function Read(var ABuffer: TBytes; AOffset, AMaxLength: Int32): Int32;
    procedure Write(const ABuffer: TBytes; AOffset, ALength: Int32);
  end;

  /// <summary>One TLS connection as an adapter drives it: the stream over a timed transport and a
  /// ready engine, the role-correct parked-verdict resolver, the handshake with its read cap armed
  /// and then cleared, application reads and writes, and the negotiated facts (zero values before
  /// the handshake). Host-owned; freeing it frees the stream and releases the transport and engine
  /// without sending close_notify (a host calls CloseNotify at its own close hook).</summary>
  TTlsAdapterSession = class sealed(TObject)
  strict private
  var
    FStream: TTlsStream;
    FTransport: ITlsTransport;               // keeps the transport alive
    FTimed: TTlsTimedTransportBase;          // the same object, typed for the cap
    FEngine: ITlsEngine;
    FIsClient: Boolean;
    FServerName: string;
    function Info: TTlsConnectionInfo;       // Default(...) when FStream = nil
  public
    constructor Create(const AEngine: ITlsEngine; const ATransport: TTlsTimedTransportBase;
      AIsClient: Boolean; const AServerName: string;
      const AResolver: TCertificateVerdictResolver);
    destructor Destroy; override;
    /// <summary>Runs the handshake with reads bounded by AHandshakeTimeoutMs (0 = the 30 s library
    /// default); the cap is cleared afterwards even when the handshake raised.</summary>
    procedure Handshake(AHandshakeTimeoutMs: Int32);
    function IsHandshakeComplete: Boolean;
    function Read(var ABuffer; ACount: Longint): Longint;
    function Write(const ABuffer; ACount: Longint): Longint;
    function PendingReadBytes: Int32;
    /// <summary>Sends close_notify; raises like the stream does.</summary>
    procedure CloseNotify;
    /// <summary>Sends close_notify, swallowing a write to an already-dead peer.</summary>
    procedure CloseNotifyQuietly;
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
    property Engine: ITlsEngine read FEngine;
    property Stream: TTlsStream read FStream;
  end;

implementation

const
  DefaultHandshakeTimeoutMs = Int32(30000); // when the host leaves the handshake timeout 0

resourcestring
  SNoServerCredential =
    'no server certificate/private key was supplied';
  SNoClientTrust =
    'peer verification is on but no trust source was named; set %s (system trust is never ' +
    'implicit), or turn peer verification off to skip verification';
  SConfigAndOptionsConflict =
    '%s is set together with cert/trust options that a fully-built config replaces; supply either ' +
    'the config or the cert/trust options, not both';
  SHandshakeReadTimedOut = 'the peer sent no handshake data within %d ms';

{ TTlsAdapterBlobSource }

class function TTlsAdapterBlobSource.FromFile(
  const APath: string): TTlsAdapterBlobSource;
begin
  Result.FileName := APath;
  Result.Data := nil;
end;

class function TTlsAdapterBlobSource.FromBytes(
  const AData: TBytes): TTlsAdapterBlobSource;
begin
  Result.FileName := '';
  Result.Data := AData;
end;

function TTlsAdapterBlobSource.IsEmpty: Boolean;
begin
  Result := (FileName = '') and (System.Length(Data) = 0);
end;

{ TTlsAdapterOptions }

class function TTlsAdapterOptions.Default: TTlsAdapterOptions;
begin
  Result := System.Default(TTlsAdapterOptions);
  Result.VerifyPeer := True;
  Result.CheckHostName := True;
  Result.SessionResumption := True;
  Result.ClientAuth := TClientAuthMode.Required;
end;

{ TTlsAdapterConfigComposer }

class function TTlsAdapterConfigComposer.EffectiveCrypto(
  const AOptions: TTlsAdapterOptions): ICryptoProvider;
begin
  if AOptions.Crypto <> nil then
    Result := AOptions.Crypto
  else
    Result := TDefaultCryptoProvider.Shared;
end;

class function TTlsAdapterConfigComposer.EffectivePkix(
  const AOptions: TTlsAdapterOptions): IPkixProvider;
begin
  if AOptions.Pkix <> nil then
    Result := AOptions.Pkix
  else
    Result := TDefaultPkixProvider.Shared;
end;

class function TTlsAdapterConfigComposer.Load(
  const ASource: TTlsAdapterBlobSource): TBytes;
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

class procedure TTlsAdapterConfigComposer.Sign(var ASig: TTlsSignatureBuilder;
  const AName: string; const ASource: TTlsAdapterBlobSource);
begin
  if System.Length(ASource.Data) > 0 then
    ASig.AddBytesDigest(AName, ASource.Data)
  else
    ASig.AddFile(AName, ASource.FileName);
end;

class function TTlsAdapterConfigComposer.HasClientTrustSource(
  const AOptions: TTlsAdapterOptions): Boolean;
begin
  Result := (AOptions.ServerCertificateVerifier <> nil) or (System.Length(AOptions.TrustAnchors) > 0) or
    (AOptions.SystemTrust <> nil) or (AOptions.CustomTrustStore <> nil);
end;

class function TTlsAdapterConfigComposer.HasClientAuthTrustSource(
  const AOptions: TTlsAdapterOptions): Boolean;
begin
  Result := (AOptions.ClientCertificateVerifier <> nil) or (System.Length(AOptions.TrustAnchors) > 0) or
    (AOptions.SystemTrust <> nil) or (AOptions.CustomTrustStore <> nil);
end;

class function TTlsAdapterConfigComposer.BuildClientConfig(
  const AOptions: TTlsAdapterOptions): ITlsClientConfig;
var
  LPkix: IPkixProvider;
  LClient: ITlsClientConfigBuilder;
  LI: Int32;
begin
  LPkix := EffectivePkix(AOptions);
  LClient := TTlsPresets.Compatible(EffectiveCrypto(AOptions), LPkix).Client;
  // compose peer trust from orthogonal sources: a whole-verifier REPLACES the pipeline, else the
  // anchors + the OS store + a custom store all UNION. Adding both a verifier and an anchor source
  // is left to fail as the builder's typed conflict. System trust is never implicit.
  if AOptions.ServerCertificateVerifier <> nil then
    LClient.WithCertificateVerifier(AOptions.ServerCertificateVerifier);
  for LI := 0 to System.High(AOptions.TrustAnchors) do
    if not AOptions.TrustAnchors[LI].IsEmpty then
      LClient.WithTrustAnchors(Load(AOptions.TrustAnchors[LI]));
  if AOptions.SystemTrust <> nil then
    AOptions.SystemTrust.InstallClientTrust(LClient, LPkix);
  if AOptions.CustomTrustStore <> nil then
    LClient.WithTrustStore(AOptions.CustomTrustStore);
  if not HasClientTrustSource(AOptions) then
  begin
    if AOptions.VerifyPeer and (not AOptions.InsecureSkipVerify) then
      raise ETlsStreamError.Create(TTlsAlertDescription.InternalError,
        Format(SNoClientTrust, [AOptions.TrustSourceHint]));
    // skipping verification still needs a source to satisfy the builder
    LClient.WithTrustStore(TTrustAnchorStore.Create(nil) as ITrustAnchorStore);
  end;
  if AOptions.InsecureSkipVerify or (not AOptions.VerifyPeer) then
    LClient.WithDangerousInsecureSkipVerify(True);
  if not AOptions.CheckHostName then
    LClient.WithDangerousDisableServerNameCheck;
  if System.Length(AOptions.AlpnProtocols) > 0 then
    LClient.WithAlpnProtocols(AOptions.AlpnProtocols);
  if not AOptions.Certificate.IsEmpty then
    LClient.WithCredential(Load(AOptions.Certificate), Load(AOptions.PrivateKey), AOptions.KeyPassword);
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

class function TTlsAdapterConfigComposer.BuildServerConfig(
  const AOptions: TTlsAdapterOptions): ITlsServerConfig;
var
  LPkix: IPkixProvider;
  LServer: ITlsServerConfigBuilder;
  LI: Int32;
begin
  if AOptions.Certificate.IsEmpty then
    raise ETlsStreamError.Create(TTlsAlertDescription.InternalError, SNoServerCredential);
  LPkix := EffectivePkix(AOptions);
  LServer := TTlsPresets.Compatible(EffectiveCrypto(AOptions), LPkix).Server
    .WithCredential(Load(AOptions.Certificate), Load(AOptions.PrivateKey), AOptions.KeyPassword);
  if System.Length(AOptions.AlpnProtocols) > 0 then
    LServer.WithAlpnProtocols(AOptions.AlpnProtocols);
  // client-cert auth is optional: request + verify only when a client-trust source is named. The
  // async client-certificate verdict park is armed here (and only here) so the server-role resolver
  // runs server-side for live client-cert revocation.
  if AOptions.VerifyPeer and HasClientAuthTrustSource(AOptions) then
  begin
    LServer.WithPeerAuth(AOptions.ClientAuth);
    if AOptions.ClientCertificateVerifier <> nil then
      LServer.WithCertificateVerifier(AOptions.ClientCertificateVerifier);
    for LI := 0 to System.High(AOptions.TrustAnchors) do
      if not AOptions.TrustAnchors[LI].IsEmpty then
        LServer.WithTrustAnchors(Load(AOptions.TrustAnchors[LI]));
    if AOptions.SystemTrust <> nil then
      AOptions.SystemTrust.InstallClientAuthTrust(LServer, LPkix);
    if AOptions.CustomTrustStore <> nil then
      LServer.WithTrustStore(AOptions.CustomTrustStore);
    if Assigned(AOptions.ServerVerdictResolver) then
      LServer.WithLiveRevocationVerdict(AOptions.ServerVerdictDeadlineMs);
  end;
  if AOptions.SessionResumption then
  begin
    LServer.WithResumption(True);
    LServer.WithDefaultSessionTicketKeys;
  end
  else
    LServer.WithResumption(False);
  Result := LServer.Build;
end;

class function TTlsAdapterConfigComposer.ClientSignature(
  const AOptions: TTlsAdapterOptions): string;
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
  LSig.AddFlag('systemTrust', AOptions.SystemTrust <> nil);
  LSig.AddPointer('customVerifier', AOptions.ServerCertificateVerifier);
  LSig.AddPointer('customStore', AOptions.CustomTrustStore);
  for LI := 0 to System.High(AOptions.AlpnProtocols) do
    LSig.AddText('alpn', AOptions.AlpnProtocols[LI]);
  LSig.AddMethod('verifyCb', TMethod(AOptions.VerifyCallback));
  LSig.AddFlag('asyncVerdict', Assigned(AOptions.ClientVerdictResolver));
  LSig.AddCardinal('deadline', AOptions.ClientVerdictDeadlineMs);
  Result := LSig.Value;
end;

class function TTlsAdapterConfigComposer.ServerSignature(
  const AOptions: TTlsAdapterOptions): string;
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
  LSig.AddFlag('systemTrust', AOptions.SystemTrust <> nil);
  LSig.AddPointer('customVerifier', AOptions.ClientCertificateVerifier);
  LSig.AddPointer('customStore', AOptions.CustomTrustStore);
  LSig.AddCardinal('clientAuth', Cardinal(Ord(AOptions.ClientAuth)));
  for LI := 0 to System.High(AOptions.AlpnProtocols) do
    LSig.AddText('alpn', AOptions.AlpnProtocols[LI]);
  LSig.AddFlag('asyncVerdict', Assigned(AOptions.ServerVerdictResolver));
  LSig.AddCardinal('deadline', AOptions.ServerVerdictDeadlineMs);
  Result := LSig.Value;
end;

class procedure TTlsAdapterConfigComposer.GuardNoConflict(
  const AOptions: TTlsAdapterOptions; const APropertyName: string);
begin
  // a supplied config owns trust/credential entirely; naming these alongside it would be silently
  // dropped, so fail loud. The verdict resolvers and the handshake timeout are runtime hooks (not
  // part of the frozen config) and are deliberately excluded.
  if (not AOptions.Certificate.IsEmpty) or (not AOptions.PrivateKey.IsEmpty) or
    (System.Length(AOptions.TrustAnchors) > 0) or (AOptions.SystemTrust <> nil) or
    (AOptions.CustomTrustStore <> nil) or (AOptions.ServerCertificateVerifier <> nil) or
    (AOptions.ClientCertificateVerifier <> nil) or Assigned(AOptions.VerifyCallback) or
    (System.Length(AOptions.AlpnProtocols) > 0) or (AOptions.Crypto <> nil) or (AOptions.Pkix <> nil) then
    raise ETlsStreamError.Create(TTlsAlertDescription.InternalError,
      Format(SConfigAndOptionsConflict, [APropertyName]));
end;

class function TTlsAdapterConfigComposer.ResolveClientConfig(
  const AOptions: TTlsAdapterOptions; const AMemo: ITlsClientConfigMemo;
  const AConfigPropertyName: string): ITlsClientConfig;
var
  LSig: string;
  LConfig: ITlsClientConfig;
begin
  // a fully-built config supplied by the host REPLACES the options-driven build outright; naming
  // cert/trust options alongside it fails loud rather than dropping them silently
  if AOptions.ClientConfig <> nil then
  begin
    GuardNoConflict(AOptions, AConfigPropertyName);
    Exit(AOptions.ClientConfig);
  end;
  LSig := ClientSignature(AOptions);
  if not AMemo.TryGet(LSig, LConfig) then
    LConfig := AMemo.StoreOrAdopt(LSig, BuildClientConfig(AOptions));
  Result := LConfig;
end;

class function TTlsAdapterConfigComposer.ResolveServerConfig(
  const AOptions: TTlsAdapterOptions; const AMemo: ITlsServerConfigMemo;
  const AConfigPropertyName: string): ITlsServerConfig;
var
  LSig: string;
  LConfig: ITlsServerConfig;
begin
  if AOptions.ServerConfig <> nil then
  begin
    GuardNoConflict(AOptions, AConfigPropertyName);
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
  FReadTimeoutMs := AMs;
end;

function TTlsTimedTransportBase.WaitReadable(AMs: Int32): Boolean;
begin
  // a host that bounds the socket itself (a receive timeout on the handle) keeps this default and
  // reports the elapsed cap from ReceiveRaw
  Result := True;
end;

function TTlsTimedTransportBase.Read(var ABuffer: TBytes; AOffset,
  AMaxLength: Int32): Int32;
begin
  // bounded during the handshake; distinct from a peer close (which returns 0 below)
  if (FReadTimeoutMs > 0) and (not WaitReadable(FReadTimeoutMs)) then
    raise ETlsHandshakeTimeout.Create(Format(SHandshakeReadTimedOut, [FReadTimeoutMs]));
  Result := ReceiveRaw(ABuffer, AOffset, AMaxLength);
  if Result < 0 then
    Result := 0;
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
    Inc(LOff, LN);
    Dec(LRemain, LN);
  end;
end;

{ TTlsAdapterSession }

constructor TTlsAdapterSession.Create(const AEngine: ITlsEngine;
  const ATransport: TTlsTimedTransportBase; AIsClient: Boolean;
  const AServerName: string; const AResolver: TCertificateVerdictResolver);
begin
  inherited Create;
  FEngine := AEngine;
  FTimed := ATransport;
  // the one refcount holder: the caller passes a fresh instance straight in (const skips AddRef),
  // so this reference is what keeps the transport alive for the connection's lifetime
  FTransport := ATransport as ITlsTransport;
  FIsClient := AIsClient;
  FServerName := AServerName;
  FStream := TTlsStream.Create(FTransport, FEngine, AIsClient, AServerName);
  // the caller already chose the role-correct resolver (a client parks on the server's chain, a
  // server on the mTLS client's); the session never guesses the role
  if Assigned(AResolver) then
    FStream.SetCertificateVerdictResolver(AResolver);
end;

destructor TTlsAdapterSession.Destroy;
begin
  FStream.Free;
  FStream := nil;
  FTransport := nil;
  FTimed := nil;
  FEngine := nil;
  inherited Destroy;
end;

function TTlsAdapterSession.Info: TTlsConnectionInfo;
begin
  if FStream <> nil then
    Result := FStream.ConnectionInfo
  else
    Result := System.Default(TTlsConnectionInfo);
end;

procedure TTlsAdapterSession.Handshake(AHandshakeTimeoutMs: Int32);
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

function TTlsAdapterSession.IsHandshakeComplete: Boolean;
begin
  Result := (FStream <> nil) and FStream.IsHandshakeComplete;
end;

function TTlsAdapterSession.Read(var ABuffer; ACount: Longint): Longint;
begin
  Result := FStream.Read(ABuffer, ACount);
end;

function TTlsAdapterSession.Write(const ABuffer; ACount: Longint): Longint;
begin
  Result := FStream.Write(ABuffer, ACount);
end;

function TTlsAdapterSession.PendingReadBytes: Int32;
begin
  if FStream <> nil then
    Result := FStream.PendingReadBytes
  else
    Result := 0;
end;

procedure TTlsAdapterSession.CloseNotify;
begin
  if FStream <> nil then
    FStream.CloseNotify;
end;

procedure TTlsAdapterSession.CloseNotifyQuietly;
begin
  if FStream <> nil then
    try
      FStream.CloseNotify;
    except
    end;
end;

function TTlsAdapterSession.NegotiatedVersion: TTlsVersion;
begin
  Result := Info.NegotiatedVersion;
end;

function TTlsAdapterSession.NegotiatedCipherSuite: UInt16;
begin
  Result := Info.CipherSuite;
end;

function TTlsAdapterSession.NegotiatedGroup: UInt16;
begin
  Result := Info.NamedGroup;
end;

function TTlsAdapterSession.PeerServerName: string;
begin
  Result := Info.ServerName;
end;

function TTlsAdapterSession.EchStatus: TEchStatus;
begin
  Result := Info.EchStatus;
end;

function TTlsAdapterSession.Resumed: Boolean;
begin
  Result := Info.Resumed;
end;

function TTlsAdapterSession.PeerLeaf: TBytes;
var
  LChain: TArray<TBytes>;
begin
  Result := nil;
  LChain := Info.PeerCertificates;
  if System.Length(LChain) > 0 then
    Result := LChain[0];
end;

function TTlsAdapterSession.VersionName: string;
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
