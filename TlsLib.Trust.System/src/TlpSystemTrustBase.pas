{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpSystemTrustBase;

{$I ..\..\TlsLib\src\Include\TlsLib.inc}

interface

uses
  SysUtils,
  Generics.Collections,
  TlpTlsAlert,
  TlpIClock,
  TlpClock,
  TlpServerName,
  TlpEndpointIdentity,
  TlpTrustPolicy,
  TlpIPkixProvider,
  TlpICertificateTrust,
  TlpTrustTypes,
  TlpCertificateVerifier,
  TlpSystemTrustExceptions;

resourcestring
  SLiveNeedsLiveRevocationVerdict =
    'OS-native live revocation needs the live-revocation verdict enabled (it defers the live ' +
    'check to the out-of-band park); call WithLiveRevocationVerdict, or use cache-only trust';
  SHardNeedsLiveRevocationVerdict =
    'a Hard revocation posture on this platform needs the live-revocation verdict (the OS ' +
    'delegate is cache-only and cannot obtain a live revocation status); call ' +
    'WithLiveRevocationVerdict, or use a softer posture';
  SNoLiveRevocation =
    'this platform has no OS-native live revocation (only Windows and Apple do); keep cache-only ' +
    'trust and compose the portable live-revocation checker for a live check here';

type
  /// <summary>
  /// How the OS trust delegate performs revocation. CacheOnly (the default) evaluates against the
  /// OS revocation cache / the handshake staple with no socket, inline on the engine thread.
  /// Live re-runs the OS engine with network fetch enabled, off the engine thread in the async
  /// verdict park (the inline pass then defers an indeterminate revocation so the handshake parks).
  /// </summary>
  TSystemTrustFetch = (CacheOnly, Live);

  /// <summary>What a platform chain engine can do beyond building and trusting a path. LiveFetch: it
  /// can re-evaluate with network revocation fetch on (the async park's live check). CachedRevocation:
  /// it renders a revocation outcome of its own from its cache and the handshake staple, so the inline
  /// pass decides Hard from that; an engine without it renders none, and the staple is the only inline
  /// revocation source. DnsIdentity: it matches a DNS host itself, so the library only re-checks an
  /// IP-literal identity; an engine without it validates the chain only and the library matches the
  /// full RFC 6125 identity.</summary>
  TPlatformChainCapability = (LiveFetch, CachedRevocation, DnsIdentity);
  TPlatformChainCapabilities = set of TPlatformChainCapability;

  /// <summary>What the engine is asked to do about revocation, already resolved from the posture and
  /// the deferral by the caller: None (Off), BestEffort (Soft, or a Hard whose indeterminate case is
  /// deferred to the park), RequirePositive (Hard decided here, or every live re-check so an
  /// indeterminate surfaces distinctly).</summary>
  TPlatformRevocationCheck = (None, BestEffort, RequirePositive);

  /// <summary>One platform chain evaluation. Chain is the peer chain (leaf first, DER). Anchors is the
  /// exclusive trust root of a client-certificate evaluation (empty on the server path, where the OS
  /// roots apply). ServerName is the server-path identity (the engine reads AsDns or ToString as its
  /// platform requires; empty on the client path). OcspStaple is consumed as cached revocation data
  /// where the platform can. NetworkAllowed is False inline (no socket) and True only from the
  /// off-engine-thread park. Clock nil means platform time. DeadlineMs bounds a network fetch where the
  /// platform honours one.</summary>
  TPlatformChainRequest = record
    Chain: TArray<TBytes>;
    Anchors: TArray<TBytes>;
    ServerName: TServerName;
    OcspStaple: TBytes;
    Revocation: TPlatformRevocationCheck;
    NetworkAllowed: Boolean;
    Clock: ITlsClock;
    DeadlineMs: Cardinal;
  end;

  /// <summary>What the engine reports when the platform built a path: the revocation outcome it
  /// rendered (Indeterminate for an engine without CachedRevocation), the leaf-first path it built
  /// (empty where the platform reports none), and the certificates the strength policy skips (the OS
  /// anchor, or the configured client-CA anchors where the path is the presented chain).</summary>
  TPlatformChainResult = record
    Outcome: TLiveRevocationOutcome;
    Path: TArray<TBytes>;
    PolicyExempt: TArray<TBytes>;
  end;

  /// <summary>
  /// The post-checks every OS trust delegate applies once the OS engine has accepted the peer:
  /// they can only reject a peer or refuse a configuration, never turn an OS rejection into an
  /// acceptance. Centralized so the Windows, Apple and Android delegates decide these the same way:
  /// a definitive stapled Revoked always wins (RFC 6960), an IP-literal identity is matched in the
  /// library against iPAddress SANs (the OS name logic only ever sees a DNS host), and a cache-only
  /// delegate cannot satisfy a Hard posture without the live-revocation verdict.
  /// </summary>
  TDelegatePostChecks = class sealed(TObject)
  public
    /// <summary>True (with AAlert = certificate_revoked) when the handshake staple is a definitive,
    /// authenticated Revoked over the OS-validated path - honored under every posture. A missing,
    /// Good or indeterminate staple does not fire here (the posture governs those). AOsPath carries
    /// the OS-supplied issuer so a leaf-only peer's staple can be authenticated. A nil clock falls
    /// back to system time (a nil clock would otherwise render every staple indeterminate).</summary>
    class function RejectStapledRevoked(const APkix: IPkixProvider;
      const AClock: ITlsClock; const AOsPath: TArray<TBytes>; const AStaple: TBytes;
      out AAlert: TTlsAlertDescription): Boolean; static;
    /// <summary>True when AName is an IP literal that does not match an iPAddress SAN on the
    /// OS-validated leaf (RFC 6125 forbids matching an IP host against dNSName/wildcards). A DNS or
    /// empty name never fires (the OS did that name check). Fail-closed: a nil provider or empty
    /// path is a mismatch (internal_error); a genuine mismatch is bad_certificate.</summary>
    class function RejectIpMismatch(const AName: TServerName;
      const APkix: IPkixProvider; const AOsPath: TArray<TBytes>;
      out AAlert: TTlsAlertDescription): Boolean; static;
    /// <summary>Whether a Hard posture is unsatisfiable for a cache-only delegate: Hard with no
    /// live-revocation verdict (a client certificate is never stapled, so a cache-only delegate
    /// has no revocation status to act on).</summary>
    class function HardNeedsLiveRevocation(APosture: TRevocationPosture;
      ADeferral: TVerdictDeferral): Boolean; static;
    /// <summary>Whether a Live fetch source is unusable without the live-revocation verdict (the
    /// live check runs only in the park that verdict arms).</summary>
    class function LiveNeedsLiveRevocation(AFetch: TSystemTrustFetch;
      ADeferral: TVerdictDeferral): Boolean; static;
    /// <summary>The host to hand the OS name check: the DNS host, or '' for an IP literal (which
    /// the OS must never name-check - the library matches it against iPAddress SANs instead).</summary>
    class function OsHostName(const AHostName: string): string; static;
    /// <summary>True (with AAlert = bad_certificate) when a non-empty AName does not match the leaf's
    /// dNSName / iPAddress SANs (RFC 6125), for an engine that validates the chain but not the host.
    /// An empty name never fires. A nil provider or empty path cannot match and fails closed
    /// (bad_certificate).</summary>
    class function RejectNameMismatch(const AName: TServerName;
      const APkix: IPkixProvider; const AOsPath: TArray<TBytes>;
      out AAlert: TTlsAlertDescription): Boolean; static;
  end;
  /// <summary>
  /// Deduplicates harvested roots by exact bytes: a filesystem store walking
  /// hashed-symlink directories sees the same certificate under several names.
  /// </summary>
  TSystemRootAccumulator = class sealed(TObject)
  strict private
    FRoots: TList<TBytes>;
    FSeen: TDictionary<TBytes, Boolean>;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Add(const ADer: TBytes);
    function ToArray: TArray<TBytes>;
  end;

  /// <summary>
  /// Abstract platform trust-root SOURCE - it reads the OS trust store, it is not
  /// itself a trust store. Snapshot freezes the harvested roots into an immutable
  /// TTrustAnchorStore that the verifier consumes, so the anchors a config validates
  /// against are fixed at build time and never change under it; picking up OS changes
  /// means building a new snapshot. A source is a short-lived helper the caller owns
  /// and frees, and nothing is read until Harvest. Fail-closed: an empty or unreadable
  /// harvest raises rather than yielding an empty anchor set. Subclasses override
  /// HarvestRoots.
  /// </summary>
  TSystemRootSource = class abstract(TObject)
  strict private
    FPkix: IPkixProvider;
  strict protected
    /// <summary>Gather the platform's trusted roots as DER. May return empty; Harvest
    /// turns an empty result into a fail-closed error.</summary>
    function HarvestRoots: TArray<TBytes>; virtual; abstract;
    /// <summary>Human-readable source label, used in the fail-closed message.</summary>
    function SourceName: string; virtual; abstract;
    /// <summary>The PKIX provider, for subclasses that must parse (e.g. PEM).</summary>
    property Pkix: IPkixProvider read FPkix;
  protected
    /// <summary>Adds ADer to AAccumulator only if the provider confirms it a
    /// well-formed X.509 certificate; the accumulator handles the exact-byte
    /// de-dup for hashed-symlink directories.</summary>
    procedure AddUnique(const AAccumulator: TSystemRootAccumulator;
      const ADer: TBytes);
  public
    constructor Create(const APkix: IPkixProvider);
    /// <summary>Reads the source now. Fail-closed: an empty or unreadable source
    /// raises ESystemTrustUnavailableTlsLibException; a non-empty result is returned
    /// as harvested.</summary>
    function Harvest: TArray<TBytes>;
    /// <summary>Harvests now and freezes the result into an immutable anchor store.</summary>
    function Snapshot: ITrustAnchorStore;
  end;

implementation

resourcestring
  SSystemTrustEmpty =
    'the %s trust store could not be read or contained no usable root certificates';
  SNoProvider = 'a PKIX provider is required to read the system trust store';

{ TDelegatePostChecks }

class function TDelegatePostChecks.RejectStapledRevoked(
  const APkix: IPkixProvider; const AClock: ITlsClock;
  const AOsPath: TArray<TBytes>; const AStaple: TBytes;
  out AAlert: TTlsAlertDescription): Boolean;
var
  LClock: ITlsClock;
begin
  // a nil clock would make every staple indeterminate; the delegates accept a nil clock and mean
  // "system time", so honor that here rather than silently skipping the revocation check
  LClock := AClock;
  if LClock = nil then
    LClock := TSystemClock.Create as ITlsClock;
  Result := TCertificateVerifier.StapleVerdict(APkix, LClock, AOsPath, AStaple) =
    TStapleVerdict.Revoked;
  if Result then
    AAlert := TTlsAlertDescription.CertificateRevoked;
end;

class function TDelegatePostChecks.RejectIpMismatch(const AName: TServerName;
  const APkix: IPkixProvider; const AOsPath: TArray<TBytes>;
  out AAlert: TTlsAlertDescription): Boolean;
begin
  // only an IP-literal identity is re-checked here; a DNS host (or an empty name) was matched by
  // the OS name logic
  if not AName.IsIp then
    Exit(False);
  // fail closed: without a provider to read the SANs, or with no validated leaf, an IP host cannot
  // be confirmed against an iPAddress SAN
  if (APkix = nil) or (System.Length(AOsPath) = 0) then
  begin
    AAlert := TTlsAlertDescription.InternalError;
    Exit(True);
  end;
  Result := not TEndpointIdentity.Matches(AName, nil,
    APkix.Certificates.IpAddresses(AOsPath[0]));
  if Result then
    AAlert := TTlsAlertDescription.BadCertificate;
end;

class function TDelegatePostChecks.HardNeedsLiveRevocation(
  APosture: TRevocationPosture; ADeferral: TVerdictDeferral): Boolean;
begin
  Result := TRevocationDecision.HardNeedsLiveRevocation(APosture,
    ADeferral = TVerdictDeferral.LiveRevocation);
end;

class function TDelegatePostChecks.LiveNeedsLiveRevocation(
  AFetch: TSystemTrustFetch; ADeferral: TVerdictDeferral): Boolean;
begin
  Result := (AFetch = TSystemTrustFetch.Live) and
    (ADeferral <> TVerdictDeferral.LiveRevocation);
end;

class function TDelegatePostChecks.OsHostName(const AHostName: string): string;
var
  LName: TServerName;
begin
  if TServerName.TryParse(AHostName, LName) and LName.IsIp then
    Result := ''
  else
    Result := AHostName;
end;

class function TDelegatePostChecks.RejectNameMismatch(const AName: TServerName;
  const APkix: IPkixProvider; const AOsPath: TArray<TBytes>;
  out AAlert: TTlsAlertDescription): Boolean;
begin
  // an engine that validates the chain but not the host: the full RFC 6125 identity is matched here.
  // an empty name never fires; without a provider to read the SANs, or with no validated leaf, the
  // name cannot be confirmed and fails closed
  if AName.IsEmpty then
    Exit(False);
  if (APkix = nil) or (System.Length(AOsPath) = 0) then
  begin
    AAlert := TTlsAlertDescription.BadCertificate;
    Exit(True);
  end;
  Result := not TEndpointIdentity.Matches(AName,
    APkix.Certificates.DnsNames(AOsPath[0]),
    APkix.Certificates.IpAddresses(AOsPath[0]));
  if Result then
    AAlert := TTlsAlertDescription.BadCertificate;
end;

{ TSystemRootAccumulator }

constructor TSystemRootAccumulator.Create;
begin
  inherited Create;
  FRoots := TList<TBytes>.Create;
  FSeen := TDictionary<TBytes, Boolean>.Create;
end;

destructor TSystemRootAccumulator.Destroy;
begin
  FSeen.Free;
  FRoots.Free;
  inherited Destroy;
end;

procedure TSystemRootAccumulator.Add(const ADer: TBytes);
var
  LCopy: TBytes;
begin
  if FSeen.ContainsKey(ADer) then
    Exit;
  LCopy := Copy(ADer, 0, Length(ADer));
  FSeen.Add(LCopy, True);
  FRoots.Add(LCopy);
end;

function TSystemRootAccumulator.ToArray: TArray<TBytes>;
begin
  Result := FRoots.ToArray;
end;

{ TSystemRootSource }

constructor TSystemRootSource.Create(const APkix: IPkixProvider);
begin
  inherited Create;
  if APkix = nil then
    raise ESystemTrustUnavailableTlsLibException.CreateRes(@SNoProvider);
  FPkix := APkix;
end;

procedure TSystemRootSource.AddUnique(const AAccumulator: TSystemRootAccumulator;
  const ADer: TBytes);
begin
  if not FPkix.Certificates.IsWellFormed(ADer) then
    Exit;
  AAccumulator.Add(ADer);
end;

function TSystemRootSource.Harvest: TArray<TBytes>;
begin
  Result := HarvestRoots;
  if Length(Result) = 0 then
    raise ESystemTrustUnavailableTlsLibException.CreateResFmt(
      @SSystemTrustEmpty, [SourceName]);
end;

function TSystemRootSource.Snapshot: ITrustAnchorStore;
begin
  // a failed harvest raises here, before any store is built
  Result := TTrustAnchorStore.Create(Harvest) as ITrustAnchorStore;
end;

end.
